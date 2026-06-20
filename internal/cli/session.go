package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func sessionCmd() *cobra.Command {
	var (
		list   bool
		host   string
		asJSON bool
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "session [cert-serial]",
		Short: "Show what was done inside an SSH session (kernel audit timeline)",
		Long: `session joins access (who/where, from access_log) with the host-side kernel
events a session produced (process/file/network), captured by the Tetragon
collector and linked by the login-time session stamper.

Two uses:
  - audit: "who ran what on which host, when"
  - dataset: structured record of SRE work per host, exportable with --json for
    feeding an agent.

  vctl session --list                 recent sessions
  vctl session <cert-serial>          full timeline for one access
  vctl session <cert-serial> --json   machine-readable export`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				return err
			}
			defer st.Close()

			if list || len(args) == 0 {
				sessions, err := st.ListSessions(ctx, host, limit)
				if err != nil {
					return err
				}
				if asJSON {
					return writeJSON(sessions)
				}
				return printSessions(sessions)
			}

			serial := args[0]
			sessions, events, err := st.SessionTimeline(ctx, serial, limit)
			if err != nil {
				return err
			}
			if len(sessions) == 0 {
				ui.Warnf(os.Stderr, "no session recorded for serial %s (collector/stamper deployed on the host?)", serial)
				return nil
			}
			if asJSON {
				return writeJSON(timelineExport(sessions, events))
			}
			return printTimeline(sessions, events)
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list recent sessions instead of one timeline")
	cmd.Flags().StringVar(&host, "host", "", "filter by hostname substring (with --list)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "max sessions to show")
	return cmd
}

// sessionStartCmd registers an SSH session (cert serial -> human, on a host).
// Hidden: invoked by the host-side login stamper, not by humans.
func sessionStartCmd() *cobra.Command {
	var a store.AuditSession
	cmd := &cobra.Command{
		Use:    "session-start",
		Short:  "Register an SSH session for kernel audit (host stamper use)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			app, err := newApp()
			if err != nil {
				return err
			}
			st, err := app.OpenStore(ctx, true) // RW
			if err != nil {
				return err
			}
			defer st.Close()
			id, err := st.RecordSession(ctx, a)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, id)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&a.CertSerial, "serial", "", "SSH cert serial (from SSH_USER_AUTH)")
	f.StringVar(&a.VaultUser, "user", "", "resolved human identity (cert key id)")
	f.StringVar(&a.Hostname, "host", "", "this host's name")
	f.StringVar(&a.LoginUser, "login", "", "OS login user (ubuntu/rocky/root)")
	f.StringVar(&a.SourceIP, "source-ip", "", "client source IP")
	f.IntVar(&a.LeaderPID, "leader-pid", 0, "sshd session leader pid")
	f.Int64Var(&a.CgroupID, "cgroup", 0, "session cgroup id")
	cmd.MarkFlagRequired("host")
	return cmd
}

func printSessions(sessions []store.AuditSession) error {
	if len(sessions) == 0 {
		ui.Warnf(os.Stderr, "no sessions recorded yet")
		return nil
	}
	rows := make([][]string, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, []string{
			s.StartedAt.Local().Format("2006-01-02 15:04:05"),
			orDash(s.VaultUser), s.Hostname, orDash(s.LoginUser),
			s.CertSerial, dur(s.StartedAt, s.EndedAt),
		})
	}
	ui.Section(os.Stdout, "sessions")
	return ui.Table(os.Stdout, []string{"started", "vault user", "host", "login", "serial", "dur"}, rows)
}

func printTimeline(sessions []store.AuditSession, events map[int64][]store.KernelEvent) error {
	for _, s := range sessions {
		ui.Section(os.Stdout, fmt.Sprintf("%s on %s (%s)", orDash(s.VaultUser), s.Hostname, s.CertSerial))
		ui.Infof(os.Stdout, "login=%s source=%s started=%s dur=%s",
			orDash(s.LoginUser), orDash(s.SourceIP),
			s.StartedAt.Local().Format("2006-01-02 15:04:05"), dur(s.StartedAt, s.EndedAt))
		if s.Summary != "" {
			ui.Infof(os.Stdout, "summary: %s", s.Summary)
		}
		evs := events[s.ID]
		if len(evs) == 0 {
			ui.Warnf(os.Stdout, "  (no kernel events linked)")
			continue
		}
		rows := make([][]string, 0, len(evs))
		for _, e := range evs {
			rows = append(rows, []string{
				e.TS.Local().Format("15:04:05"), e.Kind, detail(e),
			})
		}
		if err := ui.Table(os.Stdout, []string{"time", "kind", "detail"}, rows); err != nil {
			return err
		}
	}
	return nil
}

func detail(e store.KernelEvent) string {
	switch e.Kind {
	case "exec":
		if e.Args != "" {
			return e.Binary + " " + e.Args
		}
		return e.Binary
	case "open":
		return e.Filename
	case "connect":
		return e.DestAddr
	case "exit":
		if e.ExitCode != nil {
			return fmt.Sprintf("%s (exit %d)", e.Binary, *e.ExitCode)
		}
		return e.Binary
	default:
		return e.Binary
	}
}

// timelineExport builds the JSON shape for dataset/agent consumption.
func timelineExport(sessions []store.AuditSession, events map[int64][]store.KernelEvent) any {
	type ev struct {
		TS       time.Time `json:"ts"`
		Kind     string    `json:"kind"`
		Binary   string    `json:"binary,omitempty"`
		Args     string    `json:"args,omitempty"`
		CWD      string    `json:"cwd,omitempty"`
		Filename string    `json:"filename,omitempty"`
		DestAddr string    `json:"dest_addr,omitempty"`
		ExitCode *int      `json:"exit_code,omitempty"`
	}
	type sess struct {
		CertSerial string     `json:"cert_serial"`
		VaultUser  string     `json:"vault_user"`
		Hostname   string     `json:"hostname"`
		LoginUser  string     `json:"login_user"`
		SourceIP   string     `json:"source_ip"`
		StartedAt  time.Time  `json:"started_at"`
		EndedAt    *time.Time `json:"ended_at,omitempty"`
		Summary    string     `json:"summary,omitempty"`
		Events     []ev       `json:"events"`
	}
	out := make([]sess, 0, len(sessions))
	for _, s := range sessions {
		so := sess{
			CertSerial: s.CertSerial, VaultUser: s.VaultUser, Hostname: s.Hostname,
			LoginUser: s.LoginUser, SourceIP: s.SourceIP, StartedAt: s.StartedAt,
			EndedAt: s.EndedAt, Summary: s.Summary,
		}
		for _, e := range events[s.ID] {
			so.Events = append(so.Events, ev{
				TS: e.TS, Kind: e.Kind, Binary: e.Binary, Args: e.Args, CWD: e.CWD,
				Filename: e.Filename, DestAddr: e.DestAddr, ExitCode: e.ExitCode,
			})
		}
		out = append(out, so)
	}
	return out
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dur(start time.Time, end *time.Time) string {
	if end == nil {
		return "live"
	}
	d := end.Sub(start).Round(time.Second)
	return d.String()
}
