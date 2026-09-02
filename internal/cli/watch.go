package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
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
	EndSession(context.Context, int64, time.Time, string) error
}

func watchSessionsCmd(env cmdkit.Env) *cobra.Command {
	var (
		dir      string
		hostname string
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
  vctl watch-sessions /run/vctl/sessions --once    # one pass (testing)

Sessions are recorded under --hostname when given, which is how a host whose OS
name differs from its inventory name (aio01 vs incheon-aio01) gets its audit rows
to line up with the rest of the inventory. This mirrors node-agent --hostname.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, adb, err := env.Audit()
			if err != nil {
				return err
			}
			return adb.Ingesting(cmd.Context(), func(st audit.Ingestor) error {
				ctx := cmd.Context()
				if len(args) == 1 {
					dir = args[0]
				}
				reconcileStaleSessions(ctx, st, hostname)

				seen := map[string]int64{} // marker path -> session id
				scan := func() error { return scanMarkers(ctx, st, dir, hostname, seen) }

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
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname to record sessions under; defaults to the marker's os hostname")
	cmdkit.RegisterCompletion(cmd, "hostname", cmdkit.CompleteInventoryHost(env))
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Second, "scan interval")
	cmd.Flags().BoolVar(&once, "once", false, "process current markers once and exit")
	return cmd
}

// reconcileStaleSessions ends sessions this host left un-ended on a prior run
// whose leader process is gone — the in-memory seen map is lost on restart, so
// without this stale "live" sessions accumulate. Best-effort.
//
// hostname must be the same name the sessions were recorded under, or the lookup
// matches nothing and the stale rows stay "live" forever.
func reconcileStaleSessions(ctx context.Context, st audit.Ingestor, hostname string) {
	hn, err := reportedHostname(hostname)
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
		// Host clock, matching the marker's started_at. See store.EndSession.
		if err := st.EndSession(ctx, sess.ID, time.Now().UTC(), ""); err != nil {
			ui.Warnf(os.Stderr, "end stale session %d: %v", sess.ID, err)
		}
	}
}

// scanMarkers turns new login markers in dir into audit_session rows and closes
// sessions whose leader has exited. seen maps marker path -> session id across
// calls. A dir-read error is wrapped with the path for the caller.
func scanMarkers(ctx context.Context, st sessionRecorder, dir, hostname string, seen map[string]int64) error {
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
		host := m.Host
		if hostname != "" {
			host = hostname
		}
		id, err := st.RecordSession(ctx, store.AuditSession{
			CertSerial: m.Serial, Hostname: host, LoginUser: m.Login,
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
		ui.Infof(os.Stderr, "session %d started: %s on %s (serial %s)", id, m.Login, host, m.Serial)
	}
	return nil
}

// closeIfEnded ends a session whose leader process has exited and removes its marker.
func closeIfEnded(ctx context.Context, st sessionRecorder, path string, seen map[string]int64) {
	m, err := readMarker(path)
	if err != nil || processAlive(m.LeaderPID) {
		return
	}
	_ = st.EndSession(ctx, seen[path], time.Now().UTC(), "")
	_ = os.Remove(path)
	delete(seen, path)
}

// reportedHostname resolves the name sessions are recorded under: the override
// when given, otherwise the OS hostname. Kept next to the marker scanner so both
// the recorder and the stale-session reconciler agree — disagreeing would leave
// un-ended sessions the reconciler can never find.
func reportedHostname(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	return os.Hostname()
}

func readMarker(path string) (sessionMarker, error) {
	var m sessionMarker
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
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
