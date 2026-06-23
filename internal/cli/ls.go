package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func lsCmd() *cobra.Command {
	var dc string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List accessible inventory hosts",
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

			servers, err := st.ListWithStatus(ctx, dc)
			if err != nil {
				return err
			}
			if len(servers) == 0 {
				ui.Warnf(os.Stderr, "inventory is empty. Run 'vctl sync' first.")
				return nil
			}
			rows := make([][]string, 0, len(servers))
			for _, s := range servers {
				jump := s.JumpVia
				if jump == "" {
					jump = ui.Muted("direct")
				}
				rows = append(rows, []string{ui.Truncate(s.Hostname, 40), s.IP, s.User, s.DC, jump, liveStatus(s), agentStatus(s.Status), serviceSummary(s.Status)})
			}
			ui.Section(os.Stdout, "inventory")
			return ui.Table(os.Stdout, []string{"host", "ip", "user", "dc", "jump", "status", "agent", "services"}, rows)
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	return cmd
}

// liveStatus prefers the node-agent's live report over the sync-time probe.
// An agent that reported within the freshness window means the host is up right
// now (dynamic); a stale agent reads as down; with no agent we fall back to the
// last sync probe, marked "up~" to show it's point-in-time, not live.
func liveStatus(s store.ServerWithStatus) string {
	if s.Status != nil {
		if time.Since(s.Status.LastSeenAt) <= 10*time.Minute {
			return ui.OK("up")
		}
		return ui.Warn("stale") // agent stopped reporting → likely down
	}
	if s.LastSeenUp != nil {
		return ui.Muted("up~") // last sync probe only (no agent)
	}
	return ui.Muted("down")
}

func agentStatus(st *store.ServerStatus) string {
	if st == nil {
		return ui.Muted("-")
	}
	age := time.Since(st.LastSeenAt)
	text := fmt.Sprintf("seen %s", compactDuration(age))
	if age <= 10*time.Minute {
		return ui.OK(text)
	}
	if age <= time.Hour {
		return ui.Warn(text)
	}
	return ui.Muted(text)
}

func serviceSummary(st *store.ServerStatus) string {
	if st == nil {
		return ui.Muted("-")
	}
	parts := []string{
		serviceBit("ssh", st.SSHDOK),
		serviceBit("kubelet", st.KubeletOK),
		serviceBit("crio", st.CRIOOK),
		serviceBit("docker", st.DockerOK),
		serviceBit("audit", st.AuditCollectorOK),
	}
	return stringsJoinNonEmpty(parts, " ")
}

func serviceBit(label string, ok *bool) string {
	if ok == nil {
		return ""
	}
	if *ok {
		return ui.OK(label)
	}
	return ui.Warn(label + "!")
}

func stringsJoinNonEmpty(vals []string, sep string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return ui.Muted("-")
	}
	return strings.Join(out, sep)
}

func compactDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
