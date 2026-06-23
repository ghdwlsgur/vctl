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
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error { // RW
				ctx := cmd.Context()
				if len(args) == 1 {
					dir = args[0]
				}

				// Restart reconcile: the in-memory seen map is lost on restart, so
				// end any session this host left un-ended whose leader process is
				// gone (otherwise stale "live" sessions accumulate).
				if hn, err := os.Hostname(); err == nil {
					if stale, err := st.UnendedSessions(ctx, hn); err == nil {
						for _, sess := range stale {
							if !processAlive(sess.LeaderPID) {
								if err := st.EndSession(ctx, sess.ID, ""); err != nil {
									ui.Warnf(os.Stderr, "end stale session %d: %v", sess.ID, err)
								}
							}
						}
					}
				}

				seen := map[string]int64{} // marker path -> session id
				scan := func() error {
					entries, err := os.ReadDir(dir)
					if err != nil {
						return err
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
							ui.Warnf(os.Stderr, "record session %s: %v", e.Name(), err)
							continue
						}
						seen[path] = id
						ui.Infof(os.Stderr, "session %d started: %s on %s (serial %s)", id, m.Login, m.Host, m.Serial)
					}
					return nil
				}

				if once {
					return scan()
				}
				if interval <= 0 {
					interval = 5 * time.Second // guard: NewTicker panics on <= 0
				}
				// Fail fast if the marker dir is unreadable at startup (misconfig):
				// a silently-idle daemon would record no sessions forever.
				if err := scan(); err != nil {
					return fmt.Errorf("watch %s: %w", dir, err)
				}
				t := time.NewTicker(interval)
				defer t.Stop()
				var lastWarn time.Time
				for {
					select {
					case <-ctx.Done():
						return nil
					case <-t.C:
						// In the loop the dir may transiently vanish; warn (rate-limited)
						// instead of crashing the daemon.
						if err := scan(); err != nil && time.Since(lastWarn) > time.Minute {
							ui.Warnf(os.Stderr, "watch %s: %v (retrying)", dir, err)
							lastWarn = time.Now()
						}
					}
				}
			})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/run/vctl/sessions", "marker directory")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Second, "scan interval")
	cmd.Flags().BoolVar(&once, "once", false, "process current markers once and exit")
	return cmd
}

// closeIfEnded ends a session whose leader process has exited and removes its marker.
func closeIfEnded(ctx context.Context, st *store.Store, path string, seen map[string]int64) {
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
