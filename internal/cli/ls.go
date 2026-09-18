package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func lsCmd(env cmdkit.Env) *cobra.Command {
	var (
		dc     string
		allIPs bool
		wide   bool
		drift  bool
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List accessible inventory hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if drift {
				return runListDrift(cmd, env, dc)
			}
			return env.WithInventory(cmd.Context(), func(_ *app.App, inv *app.Inventory) error {
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
	cmd.Flags().BoolVar(&drift, "drift", false, "only hosts whose primary address is not one the node-agent sees")
	return cmd
}

// runListDrift reports hosts whose primary address — the one `vctl ssh` dials —
// is neither an address their node-agent sees nor one that answers.
//
// The ordinary listing cannot show this. It renders the *merged* address set,
// in which the stale primary sits first and the live addresses follow as
// extras, so a drifted host looks exactly like a multi-homed healthy one. The
// two facts are in the same row and nothing compares them, which is how a host
// stays undialable while reporting in every 30 seconds.
//
// The agent's view alone is not enough to judge. A floating IP is an address a
// NAT'd instance is *reached* at and never *sees* on its own NICs, so every
// cloud VM behind one looks drifted by that test — measured: it flagged a
// gateway whose primary answers fine. Only an address that is both unobserved
// and unanswering is drift, and the second half of that can only be found by
// trying, so this probes the candidates. It is a diagnostic, not a listing, and
// costs one short TCP dial per candidate.
func runListDrift(cmd *cobra.Command, env cmdkit.Env, dc string) error {
	return env.WithInventory(cmd.Context(), func(_ *app.App, inv *app.Inventory) error {
		rows, err := inv.ListWithStatus(cmd.Context(), dc)
		if err != nil {
			return err
		}
		var candidates []store.ServerWithStatus
		agents := 0
		for _, r := range rows {
			if r.Status != nil && len(r.Status.ObservedIPs) > 0 {
				agents++
			}
			if r.PrimaryDrifted() {
				candidates = append(candidates, r)
			}
		}
		drifted, reachable := splitByPrimaryReachable(cmd.Context(), candidates)
		return printDriftedHosts(drifted, reachable, len(rows), agents, inv.Cached())
	})
}

// splitByPrimaryReachable separates candidates whose primary still answers —
// the floating-IP shape, which is not drift — from those where nothing answers.
func splitByPrimaryReachable(ctx context.Context, candidates []store.ServerWithStatus) (drifted, reachable []store.ServerWithStatus) {
	answers := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			answers[i] = primaryAnswers(ctx, candidates[i])
		}(i)
	}
	wg.Wait()
	for i, c := range candidates {
		if answers[i] {
			reachable = append(reachable, c)
			continue
		}
		drifted = append(drifted, c)
	}
	return drifted, reachable
}

// primaryAnswers reports whether anything accepts a connection on the host's
// primary address and SSH port. A refused connection counts as answering: some
// machine is there, which is not the drift this looks for.
func primaryAnswers(ctx context.Context, w store.ServerWithStatus) bool {
	ctx, cancel := context.WithTimeout(ctx, driftProbeTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(w.IP, strconv.Itoa(w.Port)))
	if err == nil {
		_ = conn.Close()
		return true
	}
	var se *os.SyscallError
	return errors.As(err, &se) && errors.Is(se.Err, syscall.ECONNREFUSED)
}

// driftProbeTimeout is short on purpose: the answer wanted here is "did
// something respond promptly", and a host that needs longer than this is not
// one an operator is about to ssh into either.
const driftProbeTimeout = 3 * time.Second

// lastProbeCell renders when sync last reached the primary address.
func lastProbeCell(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return ui.Ago(*t)
}

// printDriftedHosts puts the two addresses side by side, which is the whole
// point: the reader has to see that the one vctl dials is not one the host has.
func printDriftedHosts(drifted, reachable []store.ServerWithStatus, total, agents int, cached bool) error {
	if cached {
		ui.Warnf(os.Stderr, "reading the local snapshot — drift is judged on heartbeats that are old by construction")
	}
	if len(drifted) == 0 {
		ui.Successf(os.Stdout, "no drift: every primary address either answers or is one its node-agent reports (%d of %d hosts have an agent)", agents, total)
		noteReachableUnobserved(reachable)
		return nil
	}
	rows := make([][]string, 0, len(drifted))
	for _, d := range drifted {
		rows = append(rows, []string{
			d.Hostname, d.IP, strings.Join(d.Status.ObservedIPs, ", "),
			ui.Ago(d.Status.LastSeenAt), lastProbeCell(d.LastSeenUp),
		})
	}
	ui.Section(os.Stdout, "inventory drift")
	if err := ui.Table(os.Stdout, []string{"host", "dials", "agent sees", "heartbeat", "primary answered"}, rows); err != nil {
		return err
	}
	ui.Warnf(os.Stderr, "%d of %d agent-reporting hosts dial an address their agent does not have", len(drifted), agents)
	ui.Infof(os.Stderr, "fix one with: vctl edit <host> --ip <address> — and correct ~/.ssh/config too, or the next sync puts the old value back")
	noteReachableUnobserved(reachable)
	return nil
}

// noteReachableUnobserved accounts for the candidates that turned out fine, so
// the number is not silently dropped: these are the NAT'd hosts reached at an
// address they cannot see, and an operator who knows how many there are will
// not go looking for them again.
func noteReachableUnobserved(reachable []store.ServerWithStatus) {
	if len(reachable) == 0 {
		return
	}
	names := make([]string, 0, len(reachable))
	for _, r := range reachable {
		names = append(names, r.Hostname)
	}
	ui.Infof(os.Stderr, "%d host(s) are reached at an address their agent does not see, and it answers — a floating IP, not drift: %s",
		len(reachable), strings.Join(names, ", "))
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
		return cmdkit.AddrCell(r.IP, r.Port)
	}
	// Only the primary carries the port: it is the one `vctl ssh` dials. The
	// extras are addresses the same daemon answers on, so repeating the port on
	// each would state the same fact several times.
	first := cmdkit.AddrCell(r.Addresses[0], r.Port)
	if allIPs {
		return first + " " + ui.Muted("+"+strings.Join(r.Addresses[1:], " +"))
	}
	return first + " " + ui.Muted(fmt.Sprintf("(+%d)", len(r.Addresses)-1))
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
			strings.TrimSpace(agentCell(s, cached) + " " + cmdkit.StateCell(s.State)),
			ipCell(s, allIPs), jump,
		}
		if wide {
			row = []string{s.Hostname, agentCell(s, cached), cmdkit.StateCell(s.State), ipCell(s, allIPs), s.User, jump}
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
