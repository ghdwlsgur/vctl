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
	var (
		dc     string
		allIPs bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List accessible inventory hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withInventory(cmd.Context(), func(_ *app.App, inv *app.Inventory) error {
				servers, err := inv.ListInventory(cmd.Context(), dc)
				if err != nil {
					return err
				}
				if len(servers) == 0 {
					ui.Warnf(os.Stderr, "inventory is empty. Run 'vctl sync' first.")
					return nil
				}
				renderInventory(os.Stdout, servers, inv.Cached(), allIPs)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	cmd.Flags().BoolVar(&allIPs, "all-ips", false, "list every address a host answers on instead of a count")
	return cmd
}

// ipCell renders the address a host is reached at, and how many others it also
// answers on.
//
// Listing every address inline was the obvious thing and it made the table
// unreadable. Column widths are computed across all rows, so one seven-homed
// host stretched the address column for the whole fleet: hosts with a single
// address carried ~150 characters of padding before their next column. The
// extras were rarely the reason anyone ran this — most are container bridges
// (docker 172.17/, podman 10.88/, 10.89/) that nothing connects to.
//
// So the count is shown instead of the addresses. It keeps the fact that a host
// is multi-homed visible, which is what a reader scanning the list needs, and
// leaves the addresses themselves to `--all-ips`. Nothing is dropped from the
// data — `vctl ssh --server <ip>` still matches every address the store holds.
//
// Filtering by CIDR was the other option and is worse: here 172.16/ and 172.18/
// are real farm networks, so a heuristic that hides "container-looking" ranges
// would hide real ones too, and which ranges are noise differs per site.
func ipCell(r store.InventoryRow, allIPs bool) string {
	if len(r.Addresses) <= 1 {
		return r.IP
	}
	if allIPs {
		return r.Addresses[0] + " " + ui.Muted("+"+strings.Join(r.Addresses[1:], " +"))
	}
	return r.Addresses[0] + " " + ui.Muted(fmt.Sprintf("(+%d)", len(r.Addresses)-1))
}

// agentCell reports node-agent liveness for the inventory listing: a fresh
// heartbeat (within statusFreshnessWindow) is "up", an older one is "stale",
// and a host that has never reported is a muted "no-agent". Full metrics stay
// in `vctl status`; this is just the at-a-glance agent flag `vctl list` needs.
//
// cached suppresses the verdict entirely. Liveness is a question only live data
// can answer, and a snapshot's heartbeats are old by construction — rendering
// them through the usual rules would report the whole fleet as "stale", blaming
// the agents for what is really an unreachable database.
func agentCell(r store.InventoryRow, cached bool) string {
	if cached {
		return ui.Muted("?")
	}
	if r.AgentSeen == nil {
		return ui.Muted("no-agent")
	}
	if time.Since(*r.AgentSeen) <= statusFreshnessWindow {
		return ui.OK("up")
	}
	return ui.Warn("stale " + ui.CompactDuration(time.Since(*r.AgentSeen)))
}

// renderInventory prints the inventory grouped by DC, with a node-agent liveness
// column (up/stale/no-agent) so agent-reporting hosts stand out. Full runtime
// metrics stay in `vctl status`. Column widths are computed across all rows so
// groups stay aligned.
//
// Servers arrive already sorted by (dc, hostname) from the store, so a single
// pass can detect group boundaries.
func renderInventory(w io.Writer, servers []store.InventoryRow, cached, allIPs bool) {
	// The hostname is column 0 rather than a value carried alongside the row.
	// Keeping it separate meant every later index was off by one — widths[0] for
	// the host, widths[j+1] for everything else — which is a standing invitation
	// to misalign a column while adding one.
	cells := make([][]string, len(servers)) // host, agent, ip, user, jump
	for i, s := range servers {
		jump := s.JumpVia
		if jump == "" {
			jump = ui.Muted("direct")
		}
		cells[i] = []string{
			ui.Truncate(s.Hostname, 40),
			agentCell(s, cached),
			ipCell(s, allIPs),
			s.User,
			jump,
		}
	}
	widths := ui.ColumnWidths(cells)

	dcStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	for i := 0; i < len(servers); {
		dc := servers[i].DC
		name := dc
		if name == "" {
			name = "(no dc)"
		}
		end := i + 1
		for end < len(servers) && servers[end].DC == dc {
			end++
		}
		fmt.Fprintf(w, "%s %s\n", dcStyle.Render("▌ "+name), ui.Muted(fmt.Sprintf("· %d hosts", end-i)))

		for ; i < end; i++ {
			var line strings.Builder
			line.WriteString("  ")
			for j, c := range cells[i] {
				if j > 0 {
					line.WriteString("  ")
				}
				line.WriteString(ui.PadRight(c, widths[j]))
			}
			fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
		}
		fmt.Fprintln(w)
	}
	footer := fmt.Sprintf("%d hosts", len(servers))
	if cached {
		// Repeated on stdout because the stderr warning is lost the moment
		// someone pipes the listing into a file or another tool.
		footer += " · local snapshot; agent liveness unavailable"
	}
	fmt.Fprintln(w, ui.Muted(footer))
}

// statusFreshnessWindow is how recently a node-agent must have reported for a
// host to count as live "up" in status-aware views such as the SSH picker.
// Past it, the agent reads as "stale". One place to tune the operational SLA.
const statusFreshnessWindow = 10 * time.Minute

// liveStatus prefers the node-agent's live report over the sync-time probe.
// An agent that reported within the freshness window means the host is up right
// now (dynamic); a stale agent reads as down; with no agent we fall back to the
// last sync probe, marked "up~" to show it's point-in-time, not live.
//
// cached means the row came from the local snapshot, where no verdict is
// honest — see agentCell.
func liveStatus(s store.ServerWithStatus, cached bool) string {
	if cached {
		return ui.Muted("?")
	}
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

// liveStatusText is the shared, uncolored liveness decision for status-aware
// views. Agent freshness wins; otherwise the sync-time probe; otherwise down.
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
