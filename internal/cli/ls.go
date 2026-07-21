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

// ipCell renders the primary address plus any additional ones (operator-set
// extra_ips and node-agent observed_ips), deduped, so a multi-homed host shows
// every address that `vctl ssh --server <ip>` will match. Extras are muted.
func ipCell(s store.ServerWithStatus) string {
	seen := map[string]bool{s.IP: true}
	var extra []string
	add := func(ips []string) {
		for _, ip := range ips {
			if ip != "" && !seen[ip] {
				seen[ip] = true
				extra = append(extra, ip)
			}
		}
	}
	add(s.ExtraIPs)
	if s.Status != nil {
		add(s.Status.ObservedIPs)
	}
	if len(extra) == 0 {
		return s.IP
	}
	return s.IP + " " + ui.Muted("+"+strings.Join(extra, " +"))
}

// renderInventory prints the inventory grouped by DC. Runtime liveness is
// intentionally omitted: list is an inventory view, while `vctl status` owns
// operational state. Column widths are computed across all rows so groups stay
// aligned.
//
// Servers arrive already sorted by (dc, hostname) from ListWithStatus, so a
// single pass can detect group boundaries.
func renderInventory(w io.Writer, servers []store.ServerWithStatus) {
	host := make([]string, len(servers))
	cells := make([][]string, len(servers)) // ip, user, jump
	widths := make([]int, 4)                // host + the three cells above
	for i, s := range servers {
		jump := s.JumpVia
		if jump == "" {
			jump = ui.Muted("direct")
		}
		host[i] = ui.Truncate(s.Hostname, 40)
		cells[i] = []string{ipCell(s), s.User, jump}
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
			line.WriteString(ui.PadRight(host[i], widths[0]))
			for j, c := range cells[i] {
				line.WriteString("  ")
				line.WriteString(ui.PadRight(c, widths[j+1]))
			}
			fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("%d hosts", len(servers))))
}

// statusFreshnessWindow is how recently a node-agent must have reported for a
// host to count as live "up" in status-aware views such as the SSH picker.
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
