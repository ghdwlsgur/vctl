package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
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
				renderInventory(os.Stdout, servers)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	return cmd
}

// renderInventory prints the inventory grouped by DC. Each DC gets a header with
// its reachable/total count, and every host row leads with a colored status dot
// (the same up/stale/down decision as the `vctl ssh` picker), so the fleet reads
// as sections rather than one flat table with a repeating dc column. Column
// widths are computed across all rows so groups stay aligned.
//
// Servers arrive already sorted by (dc, hostname) from ListWithStatus, so a
// single pass can detect group boundaries.
func renderInventory(w io.Writer, servers []store.ServerWithStatus) {
	host := make([]string, len(servers))
	cells := make([][]string, len(servers)) // ip, user, jump, status, agent
	widths := make([]int, 6)                // host + the five cells above
	for i, s := range servers {
		jump := s.JumpVia
		if jump == "" {
			jump = ui.Muted("direct")
		}
		host[i] = ui.Truncate(s.Hostname, 40)
		cells[i] = []string{s.IP, s.User, jump, liveStatus(s), agentStatus(s.Status)}
		if n := lipgloss.Width(host[i]); n > widths[0] {
			widths[0] = n
		}
		for j, c := range cells[i] {
			if n := lipgloss.Width(c); n > widths[j+1] {
				widths[j+1] = n
			}
		}
	}

	dcStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tallies := tallyByDC(servers)
	byDC := make(map[string]dcTally, len(tallies))
	grandTotal, grandUp := 0, 0
	for _, t := range tallies {
		byDC[t.DC] = t
		grandTotal += t.Total
		grandUp += t.Up
	}
	for i := 0; i < len(servers); {
		dc := servers[i].DC
		name := dc
		if name == "" {
			name = "(no dc)"
		}
		t := byDC[dc]
		fmt.Fprintf(w, "%s %s\n", dcStyle.Render("▌ "+name), ui.Muted(fmt.Sprintf("· %d/%d up", t.Up, t.Total)))

		for ; i < len(servers) && servers[i].DC == dc; i++ {
			var line strings.Builder
			line.WriteString("  ")
			line.WriteString(statusDot(servers[i]))
			line.WriteString(" ")
			line.WriteString(ui.PadRight(host[i], widths[0]))
			for j, c := range cells[i] {
				line.WriteString("  ")
				line.WriteString(ui.PadRight(c, widths[j+1]))
			}
			fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("%d hosts · %d up", grandTotal, grandUp)))
}

// statusDot is the leading liveness glyph for each inventory row: a filled dot
// for reachable hosts (green up / yellow stale / muted probe-only) and a hollow
// red dot for unreachable. Mirrors liveStatusText so list and picker never disagree.
func statusDot(s store.ServerWithStatus) string {
	switch liveStatusText(s) {
	case "up":
		return ui.OK("●")
	case "stale":
		return ui.Warn("●")
	case "up~":
		return ui.Muted("●")
	default:
		return ui.Fail("○")
	}
}

// dcTally is the per-DC host/reachable count used for the inventory headers.
type dcTally struct {
	DC    string
	Up    int
	Total int
}

// tallyByDC counts hosts and reachable ("up"/"up~") per DC, in first-seen order.
// renderInventory uses it for the per-DC headers and grand total, so the count
// logic that ships is the same logic the tests assert on. Pure (no I/O); "up"
// counts agent-fresh and probe-only hosts via the shared liveStatusText.
func tallyByDC(servers []store.ServerWithStatus) []dcTally {
	idx := map[string]int{}
	out := make([]dcTally, 0)
	for _, s := range servers {
		i, ok := idx[s.DC]
		if !ok {
			i = len(out)
			idx[s.DC] = i
			out = append(out, dcTally{DC: s.DC})
		}
		out[i].Total++
		if t := liveStatusText(s); t == "up" || t == "up~" {
			out[i].Up++
		}
	}
	return out
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
	text := fmt.Sprintf("seen %s", ui.CompactDuration(age))
	if age <= statusFreshnessWindow {
		return ui.OK(text)
	}
	if age <= time.Hour {
		return ui.Warn(text)
	}
	return ui.Muted(text)
}
