package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// sessionMarker is what the PAM login stamper drops in the marker dir.
type sessionMarker struct {
	Serial    string `json:"serial"`
	Login     string `json:"login"`
	RHost     string `json:"rhost"`
	LeaderPID int    `json:"leader_pid"`
	Host      string `json:"host"`
	Started   string `json:"started"` // RFC3339 login time — stable session key across restarts
}

// sessionRecorder is the narrow store seam used by the marker scanner. Keeping
// it smaller than *store.Store makes the outage behavior directly testable and
// prevents the scanner from growing unrelated database responsibilities.
type sessionRecorder interface {
	RecordSession(context.Context, store.AuditSession) (int64, error)
	EndSession(context.Context, int64, string) error
}

func watchSessionsCmd() *cobra.Command {
	var (
		dir      string
		interval time.Duration
		once     bool
	)
	cmd := &cobra.Command{
		Use:   "watch-sessions [dir]",
		Short: "Register SSH sessions from login markers (host collector use)",
		Long: `watch-sessions turns the markers dropped by the PAM login stamper into
audit_session rows, attributing kernel events to a human via cert serial and
cgroup. Runs as a privileged host daemon (holds Vault creds); the PAM hook
itself stays credential-free.

  vctl watch-sessions /run/vctl/sessions          # daemon
  vctl watch-sessions /run/vctl/sessions --once    # one pass (testing)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withAuditIngestStore(cmd.Context(), func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				if len(args) == 1 {
					dir = args[0]
				}
				reconcileStaleSessions(ctx, st)

				seen := map[string]int64{} // marker path -> session id
				scan := func() error { return scanMarkers(ctx, st, dir, seen) }

				if once {
					return scan()
				}

				// A Vault/DB outage must not turn every pending marker into a retry
				// storm. Emit at most one warning per minute and exponentially back
				// off scans from the normal interval to five minutes. Any successful
				// pass resets the interval immediately.
				var lastWarn time.Time
				return runWatchLoop(ctx, interval, 5*time.Minute, scan, func(err error) {
					if time.Since(lastWarn) > time.Minute {
						ui.Warnf(os.Stderr, "%v (retrying)", err)
						lastWarn = time.Now()
					}
				}, func(ctx context.Context, delay time.Duration) bool {
					return waitForContext(ctx, jitterWatchDelay(delay))
				})
			})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/run/vctl/sessions", "marker directory")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Second, "scan interval")
	cmd.Flags().BoolVar(&once, "once", false, "process current markers once and exit")
	return cmd
}

// reconcileStaleSessions ends sessions this host left un-ended on a prior run
// whose leader process is gone — the in-memory seen map is lost on restart, so
// without this stale "live" sessions accumulate. Best-effort.
func reconcileStaleSessions(ctx context.Context, st *store.Store) {
	hn, err := os.Hostname()
	if err != nil {
		return
	}
	stale, err := st.UnendedSessions(ctx, hn)
	if err != nil {
		return
	}
	for _, sess := range stale {
		if processAlive(sess.LeaderPID) {
			continue
		}
		if err := st.EndSession(ctx, sess.ID, ""); err != nil {
			ui.Warnf(os.Stderr, "end stale session %d: %v", sess.ID, err)
		}
	}
}

// scanMarkers turns new login markers in dir into audit_session rows and closes
// sessions whose leader has exited. seen maps marker path -> session id across
// calls. A dir-read error is wrapped with the path for the caller.
func scanMarkers(ctx context.Context, st sessionRecorder, dir string, seen map[string]int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if _, ok := seen[path]; ok {
			closeIfEnded(ctx, st, path, seen)
			continue
		}
		m, err := readMarker(path)
		if err != nil {
			continue
		}
		started, _ := time.Parse(time.RFC3339, m.Started)
		id, err := st.RecordSession(ctx, store.AuditSession{
			CertSerial: m.Serial, Hostname: m.Host, LoginUser: m.Login,
			SourceIP: stripPort(m.RHost), LeaderPID: m.LeaderPID,
			CgroupID: cgroupID(m.LeaderPID), StartedAt: started,
		})
		if err != nil {
			// A backend outage affects every marker. Stop after the first failed
			// write so one scan produces one Vault/DB attempt and one aggregate
			// warning instead of N attempts and N log lines.
			return fmt.Errorf("record session %s: %w", e.Name(), err)
		}
		seen[path] = id
		ui.Infof(os.Stderr, "session %d started: %s on %s (serial %s)", id, m.Login, m.Host, m.Serial)
	}
	return nil
}

// closeIfEnded ends a session whose leader process has exited and removes its marker.
func closeIfEnded(ctx context.Context, st sessionRecorder, path string, seen map[string]int64) {
	m, err := readMarker(path)
	if err != nil || processAlive(m.LeaderPID) {
		return
	}
	_ = st.EndSession(ctx, seen[path], "")
	_ = os.Remove(path)
	delete(seen, path)
}

func readMarker(path string) (sessionMarker, error) {
	var m sessionMarker
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// cgroupID resolves a pid's cgroup v2 id (kernfs inode), matching the cgroup id
// Tetragon reports, so events link to the session. Best-effort: 0 on failure.
func cgroupID(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return 0
	}
	// cgroup v2: a single line "0::/path".
	line := strings.TrimSpace(string(b))
	idx := strings.LastIndex(line, "::")
	if idx < 0 {
		return 0
	}
	rel := strings.TrimPrefix(line[idx+2:], "/")
	fi, err := os.Stat(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		return 0
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(stat.Ino)
	}
	return 0
}

func stripPort(addr string) string {
	if addr == "" {
		return ""
	}
	// PAM_RHOST is usually just the IP, but tolerate "ip port".
	if i := strings.IndexByte(addr, ' '); i >= 0 {
		return addr[:i]
	}
	return addr
}
