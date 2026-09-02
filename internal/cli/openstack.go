package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// staleProbeWindow is how old a collector's answer may be before the listing
// stops presenting it as current.
//
// Both collectors run hourly — the node agent's capability probe and the
// reconciler that records VMs — much less often than the five-minute
// heartbeat, because what a host runs changes on the timescale of deployments
// rather than of processes. Three missed passes is the point where the
// silence is more likely to be the collector than the schedule. One constant
// on purpose: the host and VM windows carried the same number for the same
// reasoning as prose cross-references, which is how one gets changed without
// the other.
const staleProbeWindow = 3 * time.Hour

func openstackCmd(env cmdkit.Env) *cobra.Command {
	var legacy openStackListOptions
	cmd := &cobra.Command{
		Use:     "openstack [deployment]",
		Aliases: []string{"os"},
		Args:    cobra.MaximumNArgs(1),
		Short:   "Browse OpenStack farms, hosts and VMs",
		Long: "Open the interactive OpenStack fleet browser. Pass a deployment name to start there.\n\n" +
			"Use 'vctl openstack list' for tabular or structured host output.\n" +
			"The former listing flags remain accepted here for compatibility. If a deployment\n" +
			"name matches a subcommand, use 'vctl openstack explore <deployment>'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if legacy.requested(cmd) || cmd.Flags().Changed("output") {
				if len(args) > 0 {
					return fmt.Errorf("a deployment argument opens the browser; use 'vctl openstack list --farm %s' for the table", args[0])
				}
				return runOpenStackList(cmd, env, legacy)
			}
			return runOpenStackExplore(cmd, env, args)
		},
	}
	registerOpenStackListFlags(cmd, &legacy, true)
	// Persistent, so it means the same thing on every listing under here. The
	// listings answer from the last reading when it is fresh, which is most of
	// what makes them quick — this is how somebody says they would rather wait.
	cmd.PersistentFlags().Bool("fresh", false, "read the database instead of the last stored reading")
	cmdkit.RegisterCompletion(cmd, "farm", completeFarm(env, unassignedFarm))
	cmdkit.RegisterCompletion(cmd, "role", completeRole(env))
	cmd.ValidArgsFunction = cmdkit.ByPosition(completeFarm(env))
	cmd.AddCommand(openstackListCmd(env))
	cmd.AddCommand(openstackHostCmd(env))
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
	cmd.AddCommand(openstackReconcileCmd(env))
	cmd.AddCommand(openstackVMCmd(env))
	// Read-only and interactive, so it is gated by neither RBAC nor a flag: it
	// shows what the ungated listings already show, through a picker.
	cmd.AddCommand(openstackExploreCmd(env))
	// The farm subtree gates its own leaves — see openstackFarmCmd. Annotating
	// the parent did nothing but require mutate permission to read its help.
	cmd.AddCommand(openstackFarmCmd(env))
	return cmdkit.SupportsStructuredOutput(cmd)
}

type openStackListOptions struct {
	farm, role  string
	wide, json  bool
	all, parked bool
}

func (o openStackListOptions) requested(cmd *cobra.Command) bool {
	for _, name := range []string{"farm", "role", "wide", "json", "all", "parked"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func registerOpenStackListFlags(cmd *cobra.Command, o *openStackListOptions, hidden bool) {
	cmd.Flags().StringVar(&o.farm, "farm", "", "only hosts in this deployment; use 'unassigned' for unclaimed hosts")
	cmd.Flags().StringVar(&o.role, "role", "", "only hosts holding this role, for example compute or controller")
	cmd.Flags().BoolVar(&o.wide, "wide", false, "show every component and version")
	cmd.Flags().BoolVar(&o.json, "json", false, "machine-readable output")
	cmd.Flags().BoolVar(&o.all, "all", false, "include hosts where no OpenStack was detected")
	cmd.Flags().BoolVar(&o.parked, "parked", false, "include maintenance and retired hosts")
	if hidden {
		for _, name := range []string{"farm", "role", "wide", "json", "all", "parked"} {
			_ = cmd.Flags().MarkHidden(name)
		}
	}
}

func openstackListCmd(env cmdkit.Env) *cobra.Command {
	var opts openStackListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List OpenStack hosts in a table",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOpenStackList(cmd, env, opts)
		},
	}
	registerOpenStackListFlags(cmd, &opts, false)
	cmdkit.RegisterCompletion(cmd, "farm", completeFarm(env, unassignedFarm))
	cmdkit.RegisterCompletion(cmd, "role", completeRole(env))
	return cmdkit.SupportsStructuredOutput(cmd)
}

func runOpenStackList(cmd *cobra.Command, env cmdkit.Env, opts openStackListOptions) error {
	format, err := cmdkit.CommandOutput(cmd, opts.json)
	if err != nil {
		return err
	}
	return env.WithApp(func(a *app.App) error {
		ctx := cmd.Context()
		st := &openLater{app: a}
		defer st.Close()
		rd, err := listingReading(ctx, a, st, fleet.ShapeFarms, mustBeLive(cmd, format != cmdkit.OutputTable), fleetSnapshot)
		if err != nil {
			return err
		}
		cat := rd.Catalog
		hosts := cat.Hosts()
		if !opts.parked {
			hosts = store.InService(hosts, cat.Deployments())
		}
		cov := coverageOf(cat, hosts)
		selector := opts.farm
		if selector != "" && !strings.EqualFold(selector, unassignedFarm) {
			f, err := cat.Resolve(selector)
			if err != nil {
				return err
			}
			selector = f.ID
		}
		hosts = filterOpenStack(hosts, selector, opts.role, opts.all)
		if format != cmdkit.OutputTable {
			return cmdkit.WriteStructured(format, openStackExport{Hosts: hosts, Coverage: cov})
		}
		renderOpenStack(os.Stdout, hosts, cov, opts.wide, time.Now())
		return nil
	})
}

// coverageOf puts the listing in proportion, from the same reading the table
// came from.
//
// It was a query — and one that quietly disagreed with the table: the query
// judged every capability row on its own while the fold judges the newest pass,
// so a controller whose earlier probes failed showed nine roles in the table
// and "1 could not be probed" in the summary underneath it. Counting the rows
// that are on screen cannot drift from them.
func coverageOf(cat fleet.Catalog, hosts []store.OpenStackHost) store.OpenStackCoverage {
	c := store.OpenStackCoverage{Hosts: cat.InventoryHosts(), Probed: len(hosts)}
	for _, h := range hosts {
		switch {
		case h.Detected:
			c.Running++
		case h.LastError != "":
			c.Failed++
		default:
			c.Absent++
		}
	}
	// Clamped because the two numbers come from different places: a capability
	// row for a host since retired would otherwise make this negative.
	if c.Unprobed = c.Hosts - c.Probed; c.Unprobed < 0 {
		c.Unprobed = 0
	}
	return c
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
		if role != "" && !strutil.ContainsFold(h.Roles, role) {
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

// Column positions in a listing row. Named because the renderer now leaves some
// of them out per farm, and index arithmetic on a bare 2 is how the wrong column
// goes missing.
const (
	colHost = iota
	colRoles
	colRelease
	colAge
	colNote
)

// sharedCols carries the values every host in one farm reports, which the
// heading states once instead of the rows repeating N times.
//
// A column reading the same on every row says nothing about any row — it
// describes the farm. Seven hosts on 2025.1 print the release seven times and
// push everything after it to the right; the farm is on 2025.1, said once. The
// moment two hosts disagree the column comes back, because then the
// disagreement is the thing worth seeing.
type sharedCols struct {
	release string
	age     string
}

func (s sharedCols) hides(col int) bool {
	return (col == colRelease && s.release != "") || (col == colAge && s.age != "")
}

// sharedColumns decides what a farm's heading can absorb from its rows.
//
// --wide absorbs nothing. It exists for the reader who wants every value on
// every row, and folding rows away is the opposite of that.
func sharedColumns(hosts []store.OpenStackHost, cells [][]string, now time.Time, wide bool) sharedCols {
	var out sharedCols
	if wide || len(hosts) == 0 {
		return out
	}
	// Not the muted dash: "no version known" is nothing to hoist, and a heading
	// ending in "· -" reads as a rendering fault.
	if v := cells[0][colRelease]; v != ui.Muted("-") {
		same := true
		for _, c := range cells {
			if c[colRelease] != v {
				same = false
				break
			}
		}
		if same {
			out.release = v
		}
	}
	// Age folds only when there is no outlier to lose. This column earns its
	// place by showing the one host that stopped reporting, so a farm holding a
	// stale host keeps it on every row. The value hoisted is the oldest, so
	// folding can never make a farm look fresher than its worst host.
	var oldest time.Time
	for _, h := range hosts {
		if h.ObservedAt.IsZero() || now.Sub(h.ObservedAt) > staleProbeWindow {
			return out
		}
		if oldest.IsZero() || h.ObservedAt.Before(oldest) {
			oldest = h.ObservedAt
		}
	}
	if !oldest.IsZero() {
		out.age = ui.Muted(strutil.CompactDuration(now.Sub(oldest)))
	}
	return out
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
	standIn := false
	for i, h := range hosts {
		cells[i] = []string{
			ui.Truncate(h.Hostname, 40),
			rolesCell(h, wide),
			versionCell(h, wide),
			ageCell(h, now),
			openStackNoteCell(h, now),
		}
		standIn = standIn || strings.Contains(cells[i][colRelease], standInMark)
	}
	widths := ui.ColumnWidths(cells)

	for i := 0; i < len(hosts); {
		farm := hosts[i].Farm
		end := i + 1
		for end < len(hosts) && hosts[end].Farm == farm {
			end++
		}
		shared := sharedColumns(hosts[i:end], cells[i:end], now, wide)
		fmt.Fprintln(w, ui.GroupHeading(farmLabel(hosts[i]), farmSuffix(hosts[i], end-i, shared)))
		if shape := farmShape(hosts[i:end], wide); shape != "" {
			fmt.Fprintf(w, "  %s\n", ui.Muted(shape))
		}
		fmt.Fprintln(w)
		for ; i < end; i++ {
			visible := make([]string, 0, len(cells[i]))
			vw := make([]int, 0, len(cells[i]))
			for j, c := range cells[i] {
				if shared.hides(j) {
					continue
				}
				visible = append(visible, c)
				vw = append(vw, widths[j])
			}
			fmt.Fprintln(w, "  "+ui.GridRow(visible, vw))
		}
		fmt.Fprintln(w)
	}
	if standIn {
		fmt.Fprintln(w, ui.Muted(standInMark+" release read from a component other than nova; --wide names it"))
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
// the deployment is mostly made of, and cut off once it stops summarising: nine
// roles listed with their counts is the wall of text this line exists to spare
// the reader. --wide prints them all.
func farmShape(hosts []store.OpenStackHost, wide bool) string {
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
	if !wide && len(parts) > shapeRoles {
		// Three-index slice: appending onto parts[:shapeRoles] would otherwise
		// write over the fourth entry it is still reading from.
		parts = append(parts[:shapeRoles:shapeRoles], fmt.Sprintf("+%d more", len(parts)-shapeRoles))
	}
	return strings.Join(parts, " · ")
}

// shapeRoles is how many roles the shape line names before it stops. Past a
// handful the line is no longer a summary — it is the same list the rows carry,
// transposed.
const shapeRoles = 3

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

// farmSuffix carries the count, whatever every host in the farm agrees on, and
// — for anything weaker than a statement — what the grouping rests on. A
// confirmed farm needs no annotation; a guess does. Returned bare: it is the
// meta half of a ui.GroupHeading, which supplies the mute and the leading "·".
func farmSuffix(h store.OpenStackHost, n int, shared sharedCols) string {
	parts := make([]string, 0, 4)
	if h.FarmRegion != "" {
		parts = append(parts, h.FarmRegion)
	}
	parts = append(parts, pluralHosts(n))
	// Only what the rows have given up. These read as facts about the farm
	// because that is what they became the moment every host agreed.
	if shared.release != "" {
		parts = append(parts, shared.release)
	}
	if shared.age != "" {
		parts = append(parts, shared.age)
	}
	s := strings.Join(parts, " · ")
	if h.Farm == "" {
		return s + " · nothing has claimed these"
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

// pluralHosts counts hosts without the "1 hosts" that a bare %d gives.
func pluralHosts(n int) string {
	if n == 1 {
		return "1 host"
	}
	return fmt.Sprintf("%d hosts", n)
}

// rolesInlineMax and rolesInlineWidth bound what the roles column prints in
// full.
//
// Past that it becomes the widest thing on the screen: a controller carries
// nine roles — about ninety characters — repeated near-identically on every
// controller in the farm. Because the widths are shared across groups, that one
// string also pushed release and age to the right on every row of every other
// farm.
const (
	rolesInlineMax   = 2
	rolesInlineWidth = 24
)

// rolePrecedence orders roles by how much each one says about why the host
// exists. A machine holding controller is a controller whatever else it runs.
var rolePrecedence = []string{
	"controller", "compute", "network", "block-storage",
	"image", "identity", "orchestration", "dashboard", "load-balancer",
}

func primaryRole(roles []string) string {
	for _, want := range rolePrecedence {
		if slices.Contains(roles, want) {
			return want
		}
	}
	return roles[0]
}

// rolesSummary names what the host is for, and says how much it is leaving out.
//
// One or two roles are described by listing them. Past that the list stops being
// a description: what a reader takes from nine comma-separated roles is "this is
// a controller", which is one word. The count stays so the short form is not
// mistaken for the whole answer, and --wide prints the list.
func rolesSummary(roles []string, wide bool) string {
	if len(roles) == 0 {
		return ""
	}
	joined := strings.Join(roles, ",")
	if wide || (len(roles) <= rolesInlineMax && len(joined) <= rolesInlineWidth) {
		return joined
	}
	return fmt.Sprintf("%s (%d roles)", primaryRole(roles), len(roles))
}

// rolesCell lists what the host does now, and what it has stopped doing.
func rolesCell(h store.OpenStackHost, wide bool) string {
	if len(h.Roles) == 0 && len(h.Dropped) == 0 {
		return ui.Muted("none")
	}
	s := rolesSummary(h.Roles, wide)
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
// standInMark flags a release that did not come from nova.
//
// The name of the component it did come from used to be printed inline, which
// made the column ragged — "cinder-api=2025.1" beside "2025.1" — for a detail
// almost nobody is reading the column for. The mark keeps the caveat, the
// legend under the listing says what it means, and --wide names the component.
const standInMark = "*"

func versionCell(h store.OpenStackHost, wide bool) string {
	if !wide {
		if c, ok := h.Components["nova-compute"]; ok && c.Version != "" {
			return c.Version
		}
		if v := firstVersion(h.Components); v != "" {
			return ui.Muted(v + standInMark)
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
// alphabetically put glance-api's 30.0.0 in the summary column of a healthy
// controller, so the one number on the row described the only component that was
// not working.
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
			return c.Version
		}
		if fallback == "" {
			fallback = c.Version
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
	age := strutil.CompactDuration(now.Sub(h.ObservedAt))
	if now.Sub(h.ObservedAt) > staleProbeWindow {
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
	if s := cmdkit.StateCell(h.HostState); s != "" {
		notes = append(notes, s)
	}
	// Only worth saying once the reading is stale anyway. A fresh probe that
	// dropped a role is a change that happened; an old one is a question about
	// whether anything is reporting at all.
	if len(h.Dropped) > 0 && now.Sub(h.ObservedAt) > staleProbeWindow {
		notes = append(notes, ui.Muted("roles last seen "+strutil.CompactDuration(now.Sub(h.Dropped[0].LastSeen))+" ago"))
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

func openstackHostCmd(env cmdkit.Env) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "host [hostname]",
		Short: "Show one host's OpenStack roles, components and farm",
		Args:  cobra.MaximumNArgs(1),
		// Every probed host, not only the ones running OpenStack: "probed,
		// found nothing" is an answer this command exists to show.
		ValidArgsFunction: completeOpenStackHost(env, false),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := cmdkit.CommandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.WithStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				row, err := cmdkit.ResolveHost(ctx, st, args, "OpenStack detail")
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
					if format != cmdkit.OutputTable {
						return cmdkit.WriteStructured(format, h)
					}
					renderOpenStackHost(os.Stdout, h, time.Now())
					return nil
				}
				if format != cmdkit.OutputTable {
					return cmdkit.WriteStructured(format, map[string]any{"hostname": row.Hostname, "probed": false})
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
	return cmdkit.SupportsStructuredOutput(cmd)
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
			parts = append(parts, fmt.Sprintf("%s (last seen %s ago)", d.Role, strutil.CompactDuration(now.Sub(d.LastSeen))))
		}
		rows = append(rows, ui.KV{Key: "No longer", Value: strings.Join(parts, ", "), State: ui.StateWarn})
	}
	rows = append(rows, ui.KV{Key: "Farm", Value: farmDetail(h), State: farmState(h)})
	if h.ObservedAt.IsZero() {
		rows = append(rows, ui.KV{Key: "Probed", Value: "never"})
	} else {
		st := ui.StateOK
		if now.Sub(h.ObservedAt) > staleProbeWindow {
			st = ui.StateWarn
		}
		rows = append(rows, ui.KV{Key: "Probed", Value: strutil.CompactDuration(now.Sub(h.ObservedAt)) + " ago", State: st})
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
	// Details come from a node-agent capability report, which is inventory-
	// controlled and does not validate its keys; an empty key would panic on
	// k[:1]. A compromised or buggy host must not be able to crash the CLI.
	if k == "" {
		return ""
	}
	return strings.ToUpper(k[:1]) + strings.ReplaceAll(k[1:], "_", " ")
}
