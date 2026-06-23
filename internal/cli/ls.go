package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
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
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				servers, err := st.ListWithStatus(cmd.Context(), dc)
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
					rows = append(rows, []string{ui.Truncate(s.Hostname, 40), s.IP, s.User, s.DC, jump, liveStatus(s), agentStatus(s.Status)})
				}
				ui.Section(os.Stdout, "inventory")
				if err := ui.Table(os.Stdout, []string{"host", "ip", "user", "dc", "jump", "status", "agent"}, rows); err != nil {
					return err
				}
				printDCTotals(servers)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	return cmd
}

// printDCTotals prints a per-DC count summary (hosts + reachable) under the
// inventory table so the fleet size per datacenter is visible at a glance.
func printDCTotals(servers []store.ServerWithStatus) {
	ui.Section(os.Stdout, "by dc")
	_ = ui.Table(os.Stdout, []string{"dc", "hosts", "up"}, dcTotalsRows(servers))
}

// dcTotalsRows aggregates servers into sorted [dc, hosts, up] rows with a
// trailing [total, …] row. Pure (no I/O) so it can be unit-tested; "up" counts
// agent-fresh and probe ("up~") hosts via the shared liveStatusText.
func dcTotalsRows(servers []store.ServerWithStatus) [][]string {
	type agg struct{ total, up int }
	byDC := map[string]*agg{}
	order := make([]string, 0)
	var total, totalUp int
	for _, s := range servers {
		a := byDC[s.DC]
		if a == nil {
			a = &agg{}
			byDC[s.DC] = a
			order = append(order, s.DC)
		}
		a.total++
		total++
		if t := liveStatusText(s); t == "up" || t == "up~" {
			a.up++
			totalUp++
		}
	}
	sort.Strings(order)
	rows := make([][]string, 0, len(order)+1)
	for _, dc := range order {
		a := byDC[dc]
		rows = append(rows, []string{dc, strconv.Itoa(a.total), strconv.Itoa(a.up)})
	}
	rows = append(rows, []string{"total", strconv.Itoa(total), strconv.Itoa(totalUp)})
	return rows
}

// statusFreshnessWindow is how recently a node-agent must have reported for a
// host to count as live "up" (in both `vctl list` and the `vctl ssh` picker).
// Past it, the agent reads as "stale". One place to tune the operational SLA.
const statusFreshnessWindow = 10 * time.Minute

// liveStatus prefers the node-agent's live report over the sync-time probe.
// An agent that reported within the freshness window means the host is up right
// now (dynamic); a stale agent reads as down; with no agent we fall back to the
// last sync probe, marked "up~" to show it's point-in-time, not live.
func liveStatus(s store.ServerWithStatus) string {
	switch liveStatusText(s) {
	case "up":
		return ui.OK("up")
	case "stale":
		return ui.Warn("stale") // agent stopped reporting → likely down
	case "up~":
		return ui.Muted("up~") // last sync probe only (no agent)
	default:
		return ui.Fail("down") // red — not reachable / no signal
	}
}

// liveStatusText is the shared, uncolored liveness decision used by both
// `vctl list` and the `vctl ssh` picker so the two never disagree. Agent
// freshness wins; otherwise the sync-time probe; otherwise down.
func liveStatusText(s store.ServerWithStatus) string {
	if s.Status != nil {
		if time.Since(s.Status.LastSeenAt) <= statusFreshnessWindow {
			return "up"
		}
		return "stale"
	}
	if s.LastSeenUp != nil {
		return "up~"
	}
	return "down"
}

func agentStatus(st *store.ServerStatus) string {
	if st == nil {
		return ui.Muted("-")
	}
	age := time.Since(st.LastSeenAt)
	text := fmt.Sprintf("seen %s", compactDuration(age))
	if age <= statusFreshnessWindow {
		return ui.OK(text)
	}
	if age <= time.Hour {
		return ui.Warn(text)
	}
	return ui.Muted(text)
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
