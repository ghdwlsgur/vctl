package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func lsCmd(env CommandEnv) *cobra.Command {
	var (
		dc     string
		allIPs bool
		wide   bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List accessible inventory hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withInventory(cmd.Context(), func(_ *app.App, inv *app.Inventory) error {
				servers, err := inv.ListInventory(cmd.Context(), dc)
				if err != nil {
					return err
				}
				if len(servers) == 0 {
					ui.Warnf(os.Stderr, "inventory is empty. Run 'vctl sync' first.")
					return nil
				}
				return renderInventoryMode(os.Stdout, servers, inv.Cached(), allIPs, wide)
			})
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	cmd.Flags().BoolVar(&allIPs, "all-ips", false, "list every address a host answers on instead of a count")
	cmd.Flags().BoolVar(&wide, "wide", false, "show separate agent, state and SSH user columns")
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
		return addrCell(r.IP, r.Port)
	}
	// Only the primary carries the port: it is the one `vctl ssh` dials. The
	// extras are addresses the same daemon answers on, so repeating the port on
	// each would state the same fact several times.
	first := addrCell(r.Addresses[0], r.Port)
	if allIPs {
		return first + " " + ui.Muted("+"+strings.Join(r.Addresses[1:], " +"))
	}
	return first + " " + ui.Muted(fmt.Sprintf("(+%d)", len(r.Addresses)-1))
}

// stateCell renders what an operator declared about a host, and renders nothing
// when that is "active".
//
// Same trade as the port: active is the overwhelming majority, and labelling
// every row with it would bury the handful that are not. What is left is a
// column that is blank unless somebody has something to say.
//
// The colours encode whether a down reading on that row is news. broken is red
// because it is a fault; maintenance is amber because it is planned and
// temporary; retired is muted because nothing is expected of it any more.
func stateCell(state string) string {
	switch store.StateOrActive(state) {
	case store.StateBroken:
		return ui.Fail(store.StateBroken)
	case store.StateMaintenance:
		return ui.Warn("maint")
	case store.StateRetired:
		return ui.Muted(store.StateRetired)
	default:
		return ""
	}
}

// defaultSSHPort is the port a bare address implies, and the one worth omitting.
const defaultSSHPort = 22

// addrCell renders the address a connection would actually use, showing the
// port only when it is not 22.
//
// Non-default ports are common enough to matter and rare enough that printing
// all of them would be the wrong trade: in the inventory this was written
// against, 18 of 123 hosts differ, across four values. Rendering ":22" on the
// other 105 to surface those 18 puts the noise on the majority of rows and
// makes the exceptions no easier to find — the eye is scanning for a
// difference, and a column where every cell has a suffix has none.
//
// Omitting it is only safe because the omission is unambiguous: nothing else
// puts a colon in this column, so a bare address means 22 rather than "unknown".
func addrCell(ip string, port int) string {
	if port == 0 || port == defaultSSHPort {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
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
	return ui.Warn("stale " + strutil.CompactDuration(time.Since(*r.AgentSeen)))
}

// renderInventory prints the inventory grouped by DC, with a node-agent liveness
// column (up/stale/no-agent) so agent-reporting hosts stand out. Full runtime
// metrics stay in `vctl status`. Column widths are computed across all rows so
// groups stay aligned.
//
// Servers arrive already sorted by (dc, hostname) from the store, so a single
// pass can detect group boundaries.
func renderInventory(w io.Writer, servers []store.InventoryRow, cached, allIPs bool) error {
	return renderInventoryMode(w, servers, cached, allIPs, false)
}

func renderInventoryMode(w io.Writer, servers []store.InventoryRow, cached, allIPs, wide bool) error {
	groups := make([]ui.TableGroup, 0)
	var current *ui.TableGroup
	for i, s := range servers {
		if i == 0 || s.DC != servers[i-1].DC {
			name := s.DC
			if name == "" {
				name = "(no dc)"
			}
			groups = append(groups, ui.TableGroup{Title: name})
			current = &groups[len(groups)-1]
		}
		jump := s.JumpVia
		if jump == "" {
			jump = ui.Muted("direct")
		}
		row := []string{
			s.Hostname,
			strings.TrimSpace(agentCell(s, cached) + " " + stateCell(s.State)),
			ipCell(s, allIPs), jump,
		}
		if wide {
			row = []string{s.Hostname, agentCell(s, cached), stateCell(s.State), ipCell(s, allIPs), s.User, jump}
		}
		current.Rows = append(current.Rows, row)
	}
	for i := range groups {
		unit := "hosts"
		if len(groups[i].Rows) == 1 {
			unit = "host"
		}
		groups[i].Meta = fmt.Sprintf("%d %s", len(groups[i].Rows), unit)
	}
	columns := []ui.Column{
		{Header: "host", MinWidth: 14, MaxWidth: 34},
		{Header: "status", MinWidth: 8, MaxWidth: 18},
		{Header: "address", MinWidth: 12, MaxWidth: 26},
		{Header: "via", MinWidth: 8, MaxWidth: 24},
	}
	if wide {
		columns = []ui.Column{
			{Header: "host", MinWidth: 14, MaxWidth: 34},
			{Header: "agent", MinWidth: 7, MaxWidth: 12},
			{Header: "state", MinWidth: 5, MaxWidth: 8, Optional: true, Priority: 2},
			{Header: "address", MinWidth: 12, MaxWidth: 26},
			{Header: "user", MinWidth: 4, MaxWidth: 12, Optional: true, Priority: 3},
			{Header: "via", MinWidth: 8, MaxWidth: 24},
		}
	}
	if err := ui.GroupedTable(w, columns, groups, ui.TableOptions{Indent: "  "}); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	footer := fmt.Sprintf("%d hosts", len(servers))
	if cached {
		// Repeated on stdout because the stderr warning is lost the moment
		// someone pipes the listing into a file or another tool.
		footer += " · local snapshot; agent liveness unavailable"
	}
	_, err := fmt.Fprintln(w, ui.Muted(footer))
	return err
}

// statusFreshnessWindow is how recently a node-agent must have reported for a
// host to count as live "up" in status-aware views such as the SSH picker.
// Past it, the agent reads as "stale". One place to tune the operational SLA.
const statusFreshnessWindow = 10 * time.Minute

// liveStatus renders the node-agent's live report. A fresh heartbeat is "up",
// a lapsed one "stale"; a host with no agent gets a muted "-" and no verdict.
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
	default:
		return ui.Muted("-") // unmanaged — liveness is not a claim we can make
	}
}

// liveStatusText is the shared, uncolored liveness decision for status-aware
// views. It is a statement about the node-agent, so a host that has never
// reported gets "" — no verdict — rather than a fallback.
//
// It used to fall back to the sync-time probe ("up~") and then to "down".
// That painted every unmanaged machine in the inventory — appliances,
// gateways, hosts nobody onboarded — with a red "down" they could never
// clear, blaming them for a daemon they don't run. `vctl status` already
// counts these as "unmanaged" rather than failed; this is the same judgement.
func liveStatusText(s store.ServerWithStatus) string {
	if s.Status == nil {
		return ""
	}
	if time.Since(s.Status.LastSeenAt) <= statusFreshnessWindow {
		return "up"
	}
	return "stale"
}
