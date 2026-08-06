package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// capabilityFreshWindow is how old a probe result may be before the listing
// stops presenting it as current.
//
// The node agent probes hourly — much less often than the five-minute
// heartbeat, because what a host runs changes on the timescale of deployments
// rather than of processes. Three missed passes is the point where the silence
// is more likely to be the agent than the schedule.
const capabilityFreshWindow = 3 * time.Hour

func openstackCmd() *cobra.Command {
	var (
		farm   string
		role   string
		wide   bool
		asJSON bool
		all    bool
		parked bool
	)
	cmd := &cobra.Command{
		Use:     "openstack",
		Aliases: []string{"os"},
		Short:   "Show which hosts run OpenStack, in what role, and for which farm",
		Long: "Read what the node agents' capability probes found: the deployment a host belongs to,\n" +
			"the roles it holds, and the versions it runs.\n\n" +
			"A host appears here only once a probe has filed a result for it. Membership in a farm\n" +
			"is shown when something declared or confirmed it — never inferred from what a host runs,\n" +
			"because two unrelated deployments behind one endpoint look identical from a host.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				hosts, err := st.OpenStackHosts(ctx)
				if err != nil {
					return err
				}
				// Parked hosts go first, before coverage, so the denominator and
				// the table are counting the same fleet.
				if !parked {
					deps, err := st.Deployments(ctx)
					if err != nil {
						return err
					}
					hosts = store.InService(hosts, deps)
				}
				// Coverage is over the whole fleet, so it is taken before the
				// filters — otherwise `--role compute` would report the fleet as
				// having only compute nodes in it.
				cov, err := st.OpenStackCoverageOf(ctx, hosts)
				if err != nil {
					return err
				}
				hosts = filterOpenStack(hosts, farm, role, all)
				if asJSON {
					return writeJSON(openStackExport{Hosts: hosts, Coverage: cov})
				}
				renderOpenStack(os.Stdout, hosts, cov, wide, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&farm, "farm", "", "only hosts in this deployment; use 'unassigned' for the ones nothing has claimed")
	cmd.Flags().StringVar(&role, "role", "", "only hosts holding this role, for example compute or controller")
	cmd.Flags().BoolVar(&wide, "wide", false, "show every component and version instead of the summary column")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	cmd.Flags().BoolVar(&all, "all", false, "include hosts a probe examined and found no OpenStack on")
	cmd.Flags().BoolVar(&parked, "parked", false, "include hosts the inventory has in maintenance or retired, and the farms made only of them")
	cmd.AddCommand(openstackHostCmd())
	// Deliberately not app-gated, for the same reason `vctl migrate` is not.
	//
	// Vault is the boundary here: reconciling needs kv/teams/sre/vctl-* and
	// database/creds/vctl-rw, which only vctl-admin and this CronJob's policy
	// can read. Nobody reaches a farm's credentials without them.
	//
	// The app layer cannot answer for this caller anyway. A CronJob
	// authenticating with kubernetes auth has no per-person identity to look
	// up — the grant table is a table of people, and putting a workload in it
	// to satisfy a check is the wrong shape. The gate also opened the store
	// with vctl-ro, a role this Job has no reason to hold, so the check failed
	// before the command it guards could run at all.
	cmd.AddCommand(openstackReconcileCmd())
	cmd.AddCommand(openstackVMCmd())
	cmd.AddCommand(gate(openstackFarmCmd(), "openstack-farm", classMutate))
	return cmd
}

type openStackExport struct {
	Hosts    []store.OpenStackHost   `json:"hosts"`
	Coverage store.OpenStackCoverage `json:"coverage"`
}

// unassignedFarm is what the listing calls hosts nothing has claimed. It is a
// rendering, not a deployment: no row anywhere carries this id.
const unassignedFarm = "unassigned"

// filterOpenStack narrows the listing.
//
// Hosts a probe found nothing on are hidden by default. They are real answers
// and they are kept in the database on purpose, but a fleet where most machines
// are not part of any OpenStack deployment would otherwise bury the ones that
// are. --all brings them back.
func filterOpenStack(hosts []store.OpenStackHost, farm, role string, all bool) []store.OpenStackHost {
	out := make([]store.OpenStackHost, 0, len(hosts))
	for _, h := range hosts {
		if !h.Detected && !all {
			continue
		}
		if farm != "" && !farmMatches(h, farm) {
			continue
		}
		// Only current roles match. A host that stopped being a compute node
		// still carries the old row, and answering `--role compute` with it
		// would send someone to a machine that has not run nova in weeks.
		if role != "" && !containsFold(h.Roles, role) {
			continue
		}
		out = append(out, h)
	}
	return out
}

func farmMatches(h store.OpenStackHost, farm string) bool {
	if strings.EqualFold(farm, unassignedFarm) {
		return h.Farm == ""
	}
	if strings.EqualFold(h.Farm, farm) {
		return true
	}
	// A host claimed by two deployments is in both, so both have to match it —
	// otherwise `--farm a` and `--farm b` would each disown the conflict and it
	// would be visible only in the unfiltered listing.
	for _, m := range h.Memberships {
		if strings.EqualFold(m.DeploymentID, farm) {
			return true
		}
	}
	return false
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// renderOpenStack prints hosts grouped by deployment, with widths computed
// across every group so the columns line up between them.
func renderOpenStack(w io.Writer, hosts []store.OpenStackHost, cov store.OpenStackCoverage, wide bool, now time.Time) {
	if len(hosts) == 0 {
		// An empty table is ambiguous on its own: nothing found and nothing
		// looked produce the same blank listing, and they call for opposite
		// responses. The coverage line says which one this is.
		ui.Infof(w, "no OpenStack hosts to show.")
		fmt.Fprintln(w, ui.Muted(coverageLine(cov)))
		return
	}
	hosts = groupByFarm(hosts)
	cells := make([][]string, len(hosts))
	for i, h := range hosts {
		cells[i] = []string{
			ui.Truncate(h.Hostname, 40),
			rolesCell(h),
			versionCell(h, wide),
			ageCell(h, now),
			openStackNoteCell(h, now),
		}
	}
	widths := ui.ColumnWidths(cells)

	farmStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	for i := 0; i < len(hosts); {
		farm := hosts[i].Farm
		end := i + 1
		for end < len(hosts) && hosts[end].Farm == farm {
			end++
		}
		fmt.Fprintf(w, "%s %s\n", farmStyle.Render("▌ "+farmLabel(hosts[i])),
			ui.Muted(farmSuffix(hosts[i], end-i)))
		if shape := farmShape(hosts[i:end]); shape != "" {
			fmt.Fprintf(w, "  %s\n", ui.Muted(shape))
		}
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
	fmt.Fprintln(w, ui.Muted(coverageLine(cov)))
}

// groupByFarm orders hosts so every deployment's rows are adjacent, which the
// single-pass renderer below requires.
//
// The store returns hosts sorted by name, because that is the order the rest of
// vctl lists a fleet in. Rendering that directly printed a group header every
// time the farm changed between two adjacent names — one deployment appearing
// as four separate blocks, each with its own count, in a fleet whose naming does
// not follow its topology. Sorting here rather than in the store keeps the
// grouping a property of this view: the JSON export stays in hostname order,
// where a farm is a field and not a heading.
//
// Unassigned goes last. It is the leftover bucket, and the deployments are what
// someone opened this to read.
func groupByFarm(hosts []store.OpenStackHost) []store.OpenStackHost {
	out := make([]store.OpenStackHost, len(hosts))
	copy(out, hosts)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Farm == "") != (b.Farm == "") {
			return b.Farm == ""
		}
		// By what is printed, not by the id behind it. Sorting on the endpoint
		// while showing the name put "incheon, seoul-b, 172.16.0.21, seoul-a"
		// on screen — an order that is correct and looks like no order at all.
		if la, lb := farmLabel(a), farmLabel(b); la != lb {
			return la < lb
		}
		return a.Hostname < b.Hostname
	})
	return out
}

// farmShape summarises how a deployment is built: how many hosts hold each
// role.
//
// The per-host rows say what each machine does; this says what the deployment
// is. "3 controllers, 5 compute, 3 network" is the question someone opens this
// to answer, and counting it off a list of nine hosts each carrying up to nine
// comma-separated roles is not something a reader should have to do.
//
// Roles are ordered by how many hosts hold them, so the shape leads with what
// the deployment is mostly made of.
func farmShape(hosts []store.OpenStackHost) string {
	count := map[string]int{}
	for _, h := range hosts {
		for _, r := range h.Roles {
			count[r]++
		}
	}
	if len(count) == 0 {
		return ""
	}
	roles := make([]string, 0, len(count))
	for r := range count {
		roles = append(roles, r)
	}
	sort.Slice(roles, func(i, j int) bool {
		if count[roles[i]] != count[roles[j]] {
			return count[roles[i]] > count[roles[j]]
		}
		// By name within a tie, so the shape does not reshuffle between runs.
		return roles[i] < roles[j]
	})
	parts := make([]string, 0, len(roles))
	for _, r := range roles {
		parts = append(parts, fmt.Sprintf("%s %d", r, count[r]))
	}
	return strings.Join(parts, " · ")
}

func farmLabel(h store.OpenStackHost) string {
	switch {
	case h.Farm == "":
		return "(" + unassignedFarm + ")"
	case h.FarmName != "":
		return h.FarmName
	default:
		return h.Farm
	}
}

// farmSuffix carries the count and, for anything weaker than a statement, what
// the grouping rests on. A confirmed farm needs no annotation; a guess does.
func farmSuffix(h store.OpenStackHost, n int) string {
	s := fmt.Sprintf("· %d hosts", n)
	if h.Farm == "" {
		return s + " · nothing has claimed these"
	}
	if h.FarmRegion != "" {
		s += " · " + h.FarmRegion
	}
	switch h.Confidence {
	case store.ConfidenceConfirmed:
		return s
	case store.ConfidenceDeclared:
		return s + " · declared on the host"
	case "":
		return s
	default:
		return s + " · " + h.Confidence
	}
}

// rolesCell lists what the host does now, and what it has stopped doing.
func rolesCell(h store.OpenStackHost) string {
	if len(h.Roles) == 0 && len(h.Dropped) == 0 {
		return ui.Muted("none")
	}
	s := strings.Join(h.Roles, ",")
	if len(h.Dropped) > 0 {
		gone := make([]string, 0, len(h.Dropped))
		for _, d := range h.Dropped {
			gone = append(gone, d.Role)
		}
		// Struck through by prefix rather than colour alone: this is the one
		// column where a reader has to see the difference at a glance, and
		// colour does not survive a pipe.
		part := ui.Muted("-" + strings.Join(gone, ",-"))
		if s == "" {
			return part
		}
		s += " " + part
	}
	return s
}

// versionCell answers the question the summary column is for — "what release is
// this host on" — with nova, because that is the component a farm is usually
// described by. --wide replaces it with everything found, which is what a
// rolling upgrade needs: the components genuinely disagree for weeks and one
// number cannot say which one lags.
func versionCell(h store.OpenStackHost, wide bool) string {
	if !wide {
		if c, ok := h.Components["nova-compute"]; ok && c.Version != "" {
			return c.Version
		}
		if v := firstVersion(h.Components); v != "" {
			return ui.Muted(v)
		}
		return ui.Muted("-")
	}
	names := make([]string, 0, len(h.Components))
	for name := range h.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		c := h.Components[name]
		part := name
		if c.Version != "" {
			part += "=" + c.Version
		}
		// Only a service can be down. qemu has a version and no daemon, and
		// flagging it made every healthy compute node carry a fault.
		if c.Service && !c.Active {
			// A stopped service is not an absent one, and the distinction is the
			// difference between a broken compute node and a host that never had
			// OpenStack on it.
			part = ui.Warn(part + "(down)")
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return ui.Muted("-")
	}
	return strings.Join(parts, " ")
}

// firstVersion picks a stand-in release for a host with no nova on it — a
// storage or network node still has a version worth showing.
//
// A running service is preferred over a stopped one. Taking the first name
// alphabetically put `glance-api=30.0.0(down)` in the summary column of a
// healthy controller, so the one number on the row described the only component
// that was not working.
func firstVersion(comps map[string]store.CapabilityComponent) string {
	names := make([]string, 0, len(comps))
	for name := range comps {
		names = append(names, name)
	}
	sort.Strings(names)
	fallback := ""
	for _, name := range names {
		c := comps[name]
		if c.Version == "" {
			continue
		}
		if c.Active || !c.Service {
			return name + "=" + c.Version
		}
		if fallback == "" {
			fallback = name + "=" + c.Version
		}
	}
	return fallback
}

// ageCell says how long ago the probe ran, and stops calling the result current
// once it is old enough that the agent is the likelier explanation.
func ageCell(h store.OpenStackHost, now time.Time) string {
	if h.ObservedAt.IsZero() {
		return ui.Muted("-")
	}
	age := ui.CompactDuration(now.Sub(h.ObservedAt))
	if now.Sub(h.ObservedAt) > capabilityFreshWindow {
		return ui.Warn(age)
	}
	return ui.Muted(age)
}

// openStackNoteCell carries what makes this row worth a second look: a probe
// that failed, a host somebody has declared broken, roles that have gone away.
func openStackNoteCell(h store.OpenStackHost, now time.Time) string {
	var notes []string
	if h.LastError != "" {
		notes = append(notes, ui.Fail("probe: "+ui.Truncate(h.LastError, 40)))
	}
	if s := stateCell(h.HostState); s != "" {
		notes = append(notes, s)
	}
	// Only worth saying once the reading is stale anyway. A fresh probe that
	// dropped a role is a change that happened; an old one is a question about
	// whether anything is reporting at all.
	if len(h.Dropped) > 0 && now.Sub(h.ObservedAt) > capabilityFreshWindow {
		notes = append(notes, ui.Muted("roles last seen "+ui.CompactDuration(now.Sub(h.Dropped[0].LastSeen))+" ago"))
	}
	return strings.Join(notes, ui.Muted(" · "))
}

// coverageLine puts the listing in proportion. Without it "3 compute nodes" is
// unreadable: three out of a fleet that has been fully probed is a small
// deployment, three out of five probed hosts is a sample.
func coverageLine(c store.OpenStackCoverage) string {
	s := fmt.Sprintf("%d/%d hosts probed · %d run OpenStack", c.Probed, c.Hosts, c.Running)
	if c.Absent > 0 {
		s += fmt.Sprintf(" · %d do not", c.Absent)
	}
	// Kept apart from "do not": a probe that could not answer is not evidence
	// that the host runs nothing.
	if c.Failed > 0 {
		s += fmt.Sprintf(" · %d could not be probed", c.Failed)
	}
	if c.Unprobed > 0 {
		s += fmt.Sprintf(" · %d never probed", c.Unprobed)
	}
	return s
}

func openstackHostCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "host [hostname]",
		Short: "Show one host's OpenStack roles, components and farm",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				row, err := resolveHost(ctx, st, args, "OpenStack detail")
				if err != nil {
					return err
				}
				hosts, err := st.OpenStackHosts(ctx)
				if err != nil {
					return err
				}
				for _, h := range hosts {
					if h.Hostname != row.Hostname {
						continue
					}
					if asJSON {
						return writeJSON(h)
					}
					renderOpenStackHost(os.Stdout, h, time.Now())
					return nil
				}
				if asJSON {
					return writeJSON(map[string]any{"hostname": row.Hostname, "probed": false})
				}
				// Not an error: the host exists, nothing has looked at it. Saying
				// "not found" would send someone looking for a missing inventory
				// entry instead of a missing agent.
				ui.Warnf(os.Stderr, "%s: no capability probe has reported. Is the node agent running there?", row.Hostname)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	return cmd
}

func renderOpenStackHost(w io.Writer, h store.OpenStackHost, now time.Time) {
	ui.Section(w, h.Hostname)
	rows := []ui.KV{
		{Key: "DC", Value: ui.OrDash(h.DC)},
		{Key: "Host state", Value: h.HostState, State: hostStateUI(h.HostState)},
		{Key: "OpenStack", Value: detectedText(h), State: detectedState(h)},
		{Key: "Roles", Value: ui.OrDash(strings.Join(h.Roles, ", "))},
	}
	if len(h.Dropped) > 0 {
		parts := make([]string, 0, len(h.Dropped))
		for _, d := range h.Dropped {
			parts = append(parts, fmt.Sprintf("%s (last seen %s ago)", d.Role, ui.CompactDuration(now.Sub(d.LastSeen))))
		}
		rows = append(rows, ui.KV{Key: "No longer", Value: strings.Join(parts, ", "), State: ui.StateWarn})
	}
	rows = append(rows, ui.KV{Key: "Farm", Value: farmDetail(h), State: farmState(h)})
	if h.ObservedAt.IsZero() {
		rows = append(rows, ui.KV{Key: "Probed", Value: "never"})
	} else {
		st := ui.StateOK
		if now.Sub(h.ObservedAt) > capabilityFreshWindow {
			st = ui.StateWarn
		}
		rows = append(rows, ui.KV{Key: "Probed", Value: ui.CompactDuration(now.Sub(h.ObservedAt)) + " ago", State: st})
	}
	if h.LastError != "" {
		rows = append(rows, ui.KV{Key: "Last error", Value: h.LastError, State: ui.StateFail})
	}
	for _, k := range sortedDetailKeys(h.Details) {
		rows = append(rows, ui.KV{Key: detailLabel(k), Value: h.Details[k]})
	}
	ui.KVs(w, rows)

	if len(h.Components) == 0 {
		return
	}
	fmt.Fprintln(w)
	names := make([]string, 0, len(h.Components))
	for name := range h.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	table := make([][]string, 0, len(names))
	for _, name := range names {
		c := h.Components[name]
		// A component that is not a service has no run state to report, and
		// inventing one for it turned an installed qemu into a fault.
		state := ui.Muted("installed")
		switch {
		case c.Service && c.Active:
			state = ui.OK("running")
		case c.Service:
			state = ui.Warn("stopped")
		}
		table = append(table, []string{name, ui.OrDash(c.Version), state})
	}
	_ = ui.Table(w, []string{"component", "version", "state"}, table)
}

// detectedText must not turn a failed probe into an answer. detected=false with
// an error beside it means "we could not tell", and rendering that as "none
// found" states as fact the one thing the probe failed to establish.
func detectedText(h store.OpenStackHost) string {
	switch {
	case h.Detected:
		return "present"
	case h.LastError != "":
		return "unknown — the probe could not complete"
	default:
		return "probed, none found"
	}
}

func detectedState(h store.OpenStackHost) ui.State {
	switch {
	case h.Detected:
		return ui.StateOK
	case h.LastError != "":
		return ui.StateWarn
	default:
		return ui.StatePlain
	}
}

func hostStateUI(state string) ui.State {
	switch state {
	case store.StateBroken:
		return ui.StateFail
	case store.StateMaintenance:
		return ui.StateWarn
	case store.StateRetired:
		return ui.StatePlain
	default:
		return ui.StateOK
	}
}

// farmDetail spells out the evidence rather than just the name, because acting
// on a farm assignment is only safe for the two levels that are statements.
func farmDetail(h store.OpenStackHost) string {
	if h.Farm == "" {
		return "unassigned — nothing has claimed this host"
	}
	name := h.Farm
	if h.FarmName != "" {
		name = fmt.Sprintf("%s (%s)", h.FarmName, h.Farm)
	}
	if len(h.Memberships) > 1 {
		ids := make([]string, 0, len(h.Memberships))
		for _, m := range h.Memberships {
			ids = append(ids, m.DeploymentID)
		}
		return "claimed by " + strings.Join(ids, " and ")
	}
	return name + " · " + h.Confidence
}

func farmState(h store.OpenStackHost) ui.State {
	switch {
	case len(h.Memberships) > 1:
		return ui.StateFail
	case h.Farm == "":
		return ui.StateWarn
	case h.Confidence == store.ConfidenceConfirmed || h.Confidence == store.ConfidenceDeclared:
		return ui.StateOK
	default:
		return ui.StateWarn
	}
}

// sortedDetailKeys drops the deployment fields: they are already rendered as the
// farm row, with the evidence spelled out, and repeating the raw value below it
// invites reading the probe's guess as a second opinion.
func sortedDetailKeys(details map[string]string) []string {
	out := make([]string, 0, len(details))
	for k := range details {
		if k == "deployment" || k == "deployment_source" {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func detailLabel(k string) string {
	return strings.ToUpper(k[:1]) + strings.ReplaceAll(k[1:], "_", " ")
}
