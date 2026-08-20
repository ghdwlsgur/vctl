package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// providerIDPrefix is how Kubernetes names an OpenStack VM in
// Node.spec.providerID. It is the join between a cluster and the farm under it.
const providerIDPrefix = "openstack:///"

func openstackVMCmd(env CommandEnv) *cobra.Command {
	var (
		farm     string
		host     string
		project  string
		address  string
		id       string
		showGone bool
		asJSON   bool
		wide     bool
	)
	cmd := &cobra.Command{
		Use:     "vm [query]",
		Aliases: []string{"vms", "instances"},
		Short:   "VMs per deployment, and which physical host each one sits on",
		Long: "The chain this walks:\n\n" +
			"  OpenStack farm → physical compute host → VM → Kubernetes node → cluster\n\n" +
			"--host takes an inventory hostname and resolves it to nova's name for the same\n" +
			"machine, so a physical host answers for the VMs on it. --id takes a Nova UUID or a\n" +
			"Kubernetes providerID (openstack:///<uuid>) and goes the other way.\n\n" +
			"An argument that is not a UUID is searched for in VM names and addresses:\n\n" +
			"  vctl openstack vm bastion        every VM whose name contains it\n" +
			"  vctl openstack vm 10.3.1         every VM answering on an address that starts there",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.withApp(func(a *app.App) error {
				ctx := cmd.Context()
				lazy := &openLater{app: a}
				defer lazy.Close()
				// One argument, read by its shape. A UUID is an identity and a
				// word is a search, and asking somebody to say which is which
				// with a flag would be asking them to describe what they can
				// already see.
				search := ""
				if len(args) > 0 {
					if v := normalizeInstanceID(args[0]); isInstanceID(v) {
						if id == "" {
							id = v
						}
					} else {
						search = args[0]
					}
				}
				f := store.InstanceFilter{
					Address: address, Search: search,
					InstanceID:     normalizeInstanceID(id),
					IncludeMissing: showGone,
				}
				// A request nothing narrows is the whole reading, and the whole
				// reading is the thing that gets stored. So it is answered from
				// one catalog — off disk when there is a fresh one, out of the
				// database otherwise — and projected by the same function
				// either way, which is what stops the two from drifting.
				//
				// Everything narrowing is a SQL predicate: ILIKE over names, an
				// address join, a project resolved through its own table.
				// Re-implementing those over stored rows is how a cache starts
				// giving different answers than the command it stands in for, so
				// those go to the database and stay there. --farm and --missing
				// are the exceptions, because they are the two predicates the
				// reading was stored under.
				narrowed := search != "" || address != "" || id != "" || project != "" || host != ""
				if !narrowed {
					rd, err := vmCatalog(ctx, a, lazy, mustBeLive(cmd, format != outputTable))
					if err != nil {
						return err
					}
					cat := rd.Catalog
					vms, err := vmsFrom(cat, farm, showGone)
					if err != nil {
						return err
					}
					if format != outputTable {
						return writeStructured(format, vms)
					}
					renderVMs(os.Stdout, vms, cat.Names(), operatorNetworks(), time.Now(), wide)
					return nil
				}
				return lazy.use(ctx, func(st *store.Store) error {
					// One reading of the deployments for both things this
					// command asks about them: which one --farm means, and what
					// to call each in the grouping header. Those were two reads,
					// and the second was issued after the VMs had already been
					// fetched.
					var cat fleet.Catalog
					if farm != "" || format == outputTable {
						c, err := loadFarmCatalog(ctx, a, st)
						if err != nil {
							return err
						}
						cat = c
					}
					if farm != "" {
						resolved, err := cat.Resolve(farm)
						if err != nil {
							return err
						}
						f.DeploymentID = resolved.ID
					}
					// After the farm, so --farm narrows what a name has to be
					// unique within.
					if project != "" {
						ids, note, err := resolveProjects(ctx, st, f.DeploymentID, project)
						if err != nil {
							return err
						}
						f.ProjectIDs = ids
						if note != "" {
							ui.Infof(os.Stderr, "%s", note)
						}
					}
					if host != "" {
						nova, err := novaNameFor(ctx, st, host, f.DeploymentID)
						if err != nil {
							return err
						}
						f.Hypervisor = nova
					}
					vms, err := st.Instances(ctx, f)
					if err != nil {
						return err
					}
					if format != outputTable {
						return writeStructured(format, vms)
					}
					renderVMs(os.Stdout, vms, cat.Names(), operatorNetworks(), time.Now(), wide)
					return nil
				})
			})
		},
	}
	cmd.Flags().StringVar(&farm, "farm", "", "only this deployment, by name or Keystone endpoint")
	cmd.Flags().StringVar(&host, "host", "", "only VMs on this physical host (inventory hostname)")
	cmd.Flags().StringVar(&project, "project", "", "only this project, by id or by the name the table shows")
	cmd.Flags().StringVar(&address, "address", "", "the VM answering on this IP")
	cmd.Flags().StringVar(&id, "id", "", "a Nova UUID, or a Kubernetes providerID (openstack:///<uuid>)")
	cmd.Flags().BoolVar(&showGone, "missing", false, "include VMs the control plane no longer lists")
	cmd.AddCommand(openstackVMShowCmd(env))
	cmd.Flags().BoolVar(&wide, "wide", false, "full UUIDs and the rest of what was collected")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	registerCompletion(cmd, "farm", completeFarm(env))
	registerCompletion(cmd, "host", completeOpenStackHost(env, true))
	registerCompletion(cmd, "project", completeProject(env))
	registerCompletion(cmd, "id", completeVM(env))
	// The positional is a search, so it completes to names rather than to the
	// uuids --id takes. Somebody who has the uuid is not searching for it.
	cmd.ValidArgsFunction = completeVMName(env)
	return supportsStructuredOutput(cmd)
}

// vmCatalog is the whole reading for an unnarrowed listing, and where it came
// from.
//
// The live read is the full snapshot rather than the light one plus a query: it
// costs about 150ms more against a connection that costs ten seconds, and it is
// the reading that gets stored — so the run after it, and the browser after
// that, pay neither.
//
// This used to be its own sequence, and it was the same sequence as the other
// two listings minus the last branch: when the database refused, `openstack` and
// `farm list` served the stored reading and `vm` returned the error. Not a
// decision — a copy that stopped early. Going through listingReading is what
// makes the three agree by construction.
func vmCatalog(ctx context.Context, a *app.App, lazy *openLater, live bool) (fleet.Reading, error) {
	return listingReading(ctx, a, lazy, fleet.ShapeVMs, live, fleetSnapshotWithVMs)
}

// vmsFrom is the listing projected out of a reading.
//
// It reproduces exactly two of instancesOn's predicates — the deployment and
// the missing rows — and nothing else, because those are the two it can
// reproduce without guessing. The order is left alone: the rows arrived from
// that statement with its ORDER BY, and both predicates are filters over it, so
// what comes out here is what the database would have returned at the instant
// it was read.
//
// The same function for the stored reading and the live one. Two projections
// would be two chances to disagree about what `vm --farm x` means, and the
// disagreement would only show up as a cached listing that looked slightly
// wrong.
//
// Over AllVMs rather than the catalog's per-farm lists, which have already
// dropped the missing rows — going through those would make --missing return
// nothing and read as a fleet where nothing has ever been deleted.
func vmsFrom(cat fleet.Catalog, selector string, includeMissing bool) ([]store.Instance, error) {
	want := ""
	if selector != "" {
		f, err := cat.Resolve(selector)
		if err != nil {
			return nil, err
		}
		want = f.ID
	}
	rows := cat.AllVMs()
	out := make([]store.Instance, 0, len(rows))
	for _, v := range rows {
		if want != "" && v.DeploymentID != want {
			continue
		}
		if !includeMissing && v.MissingSince != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// normalizeInstanceID accepts what Kubernetes writes as well as a bare UUID.
//
// A node's spec.providerID is openstack:///<uuid>, and making somebody strip
// that by hand before pasting it is the kind of friction that ends in the wrong
// substring being pasted.
func normalizeInstanceID(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), providerIDPrefix)
}

// isInstanceID reports whether a string is a Nova UUID rather than a search.
//
// Shape, not a lookup: deciding by querying would make an argument that finds
// nothing change meaning, so "the VM I called abc-123 that was deleted" would
// silently become a substring search across the fleet.
func isInstanceID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// resolveFarmID turns a name people use into the deployment id rows carry, for
// the callers that need nothing else from the reading.
func resolveFarmID(ctx context.Context, a *app.App, st *store.Store, v string) (string, error) {
	cat, err := loadFarmCatalog(ctx, a, st)
	if err != nil {
		return "", err
	}
	f, err := cat.Resolve(v)
	if err != nil {
		return "", err
	}
	return f.ID, nil
}

// resolveProjects turns what somebody typed into the project ids to filter on,
// and a note when that took more than one.
//
// The table prints the project's name and --project took only its id, so the
// value on screen was not a value this flag accepted. Copying what you can see
// returned an empty listing, which reads as "this project has no VMs" — the one
// answer that was certainly wrong.
//
// A name is not unique the way a farm id is. Each deployment runs its own
// Keystone, so a name means one project per farm and eight farms hold eight
// different projects called "admin". This does not refuse that: the listing
// groups by farm and prints the name in every row, so showing all of them
// answers the question that was asked and shows its own scope. It says how wide
// it went, because a person who meant one farm should not have to count the
// headers to notice.
//
// resolveFarm refuses its ambiguity for the opposite reason — the commands
// behind it rename and change state, where guessing wrong is silent and
// permanent.
//
// Matching nothing is an error rather than an empty table, for the same reason
// it is one there: nothing found and nothing asked for look identical once
// rendered.
func resolveProjects(ctx context.Context, st *store.Store, deployment, selector string) (ids []string, note string, err error) {
	projects, err := st.Projects(ctx, deployment)
	if err != nil {
		return nil, "", err
	}
	return pickProjects(projects, deployment, selector)
}

// pickProjects is the rule above, over a list rather than a database, so the
// rule can be tested as a rule.
func pickProjects(projects []store.Project, deployment, selector string) (ids []string, note string, err error) {
	// An id wins outright. It is the identifier, and a project elsewhere that
	// happens to be named like this one does not override it.
	for _, p := range projects {
		if strings.EqualFold(p.ID, selector) {
			return []string{p.ID}, "", nil
		}
	}
	var (
		byName []store.Project
		farms  = map[string]bool{}
	)
	for _, p := range projects {
		if p.Name != "" && strings.EqualFold(p.Name, selector) {
			byName = append(byName, p)
			farms[p.DeploymentID] = true
		}
	}
	switch {
	case len(byName) == 0:
		where := "the fleet"
		if deployment != "" {
			where = deployment
		}
		return nil, "", fmt.Errorf("no project in %s has the id or name %q; 'vctl openstack vm' shows the names in use", where, selector)
	case len(farms) > 1:
		ids = make([]string, 0, len(byName))
		for _, p := range byName {
			ids = append(ids, p.ID)
		}
		return ids, fmt.Sprintf("%q names a different project in each of %d farms — showing all of them; --farm picks one",
			selector, len(farms)), nil
	default:
		// One farm. Two projects with one name inside a single Keystone is not
		// possible, so this is a single project.
		return []string{byName[0].ID}, "", nil
	}
}

// novaNameFor maps an inventory hostname onto the name nova files VMs under.
//
// The instance rows carry nova's name as reported, not a resolved one — so this
// re-derives the join with the same matcher the reconciler uses. Storing the
// resolved name instead would bake today's matching rules into data that
// outlives them, and the rules have already changed twice.
//
// The matcher is a naming rule, not a storage detail. It lived in the store,
// which meant this had to reach into the persistence layer to answer a question
// about what two machines are called.
func novaNameFor(ctx context.Context, st *store.Store, inventoryHost, deployment string) (string, error) {
	names, err := st.HypervisorNames(ctx, deployment)
	if err != nil {
		return "", err
	}
	pairs, ambiguous := membership.MatchHosts([]string{inventoryHost}, names)
	if nova, ok := pairs[inventoryHost]; ok {
		return nova, nil
	}
	if len(ambiguous) > 0 {
		return "", fmt.Errorf("%s matches more than one hypervisor name (%s); name the deployment with --farm",
			inventoryHost, strings.Join(ambiguous, ", "))
	}
	return "", fmt.Errorf("no VMs are recorded on %s; it may not be a compute node, or nothing has collected yet", inventoryHost)
}

// farmNames maps deployment id to what people call it, for the grouping header.
//
// Still its own read, for the callers that want nothing but the labels — shell
// completion describing a VM, for one. Commands that also resolve a --farm take
// both off one catalog instead.
func farmNames(ctx context.Context, st *store.Store) (map[string]string, error) {
	deps, err := st.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(deps))
	for _, d := range deps {
		if d.DisplayName != "" {
			out[d.ID] = d.DisplayName
		}
	}
	return out, nil
}

// renderVMs groups by farm and names the owning project.
//
// The farm is a header rather than a column: without --farm this listing mixes
// every deployment together, and a VM's name says nothing about which one it is
// in. Repeating the farm on every row would cost more width than it buys, and
// the same listing already groups this way for hosts.
//
// The project is a column because it varies within a farm — it is the question
// "whose VM is this", asked one row at a time.
// vmHeaders names the columns. Without them the table is eight unlabelled
// strings and the reader has to infer which is the project and which the
// hypervisor from what happens to be in them.
var vmHeaders = []string{"ID", "NAME", "STATE", "PROJECT", "HYPERVISOR", "ADDRESS", "AZ", "SEEN", ""}

func renderVMs(w io.Writer, vms []store.Instance, farms map[string]string, operatorNets []string, now time.Time, wide bool) {
	if len(vms) == 0 {
		ui.Infof(w, "no VMs to show.")
		return
	}
	byFarm := map[string][]store.Instance{}
	for _, v := range vms {
		byFarm[v.DeploymentID] = append(byFarm[v.DeploymentID], v)
	}
	ids := make([]string, 0, len(byFarm))
	for id := range byFarm {
		ids = append(ids, id)
	}
	// By what is printed, not by the id behind it — sorting on the endpoint
	// while showing the name produces an order that looks like no order at all.
	sort.Slice(ids, func(i, j int) bool {
		return vmFarmLabel(ids[i], farms) < vmFarmLabel(ids[j], farms)
	})

	// The same header the host listing uses, so one farm reads the same in both.
	for _, id := range ids {
		group := byFarm[id]
		fmt.Fprintf(w, "\n%s %s\n", farmHeading(vmFarmLabel(id, farms)),
			ui.Muted(fmt.Sprintf("· %d VMs", len(group))))
		cells := make([][]string, 0, len(group)+1)
		cells = append(cells, headerRow(wide))
		for _, v := range group {
			cells = append(cells, []string{
				ui.Muted(vmIDCell(v, wide)),
				ui.Truncate(nameOrID(v), 32),
				vmStateCell(v),
				ui.Muted(ui.Truncate(vmProjectLabel(v), 22)),
				ui.Truncate(v.HypervisorHostname, 20),
				ui.Truncate(primaryAddress(v, operatorNets), 24),
				ui.Muted(ui.Truncate(v.AvailabilityZone, 12)),
				vmSeenCell(v, now),
				vmMissingCell(v, now),
			})
		}
		widths := ui.ColumnWidths(cells)
		for i := range cells {
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
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("\n%d VMs · %d farms", len(vms), len(byFarm))))
}

// vmFarmLabel is the name if the farm has one, the endpoint otherwise. Nothing
// claims the farm is unnamed — an endpoint is a real answer to "which one".
func vmFarmLabel(id string, farms map[string]string) string {
	if n := farms[id]; n != "" {
		return n
	}
	return id
}

// vmProjectLabel prefers the name and falls back to the id.
//
// The id is kept in the data because it is the identifier; the name is what the
// last collection saw it called. An empty name means nothing has resolved it
// yet — usually a farm collected before this column existed — and showing the
// id then is better than showing a blank.
func vmProjectLabel(v store.Instance) string {
	if v.ProjectName != "" {
		return v.ProjectName
	}
	return v.ProjectID
}

func nameOrID(v store.Instance) string {
	if v.Name != "" {
		return v.Name
	}
	// A VM with no name still has to be identifiable, and the UUID is the only
	// thing it definitely has.
	return v.InstanceID
}

// vmStateCell folds nova's three state fields into the one thing a reader wants
// to know, and keeps them apart when they disagree.
//
// task_state leads when set: a VM stuck mid-migration is neither running nor
// stopped, and reporting it as ACTIVE hides the only interesting thing about it.
func vmStateCell(v store.Instance) string {
	if v.TaskState != "" {
		return ui.Warn(v.TaskState)
	}
	switch strings.ToUpper(v.Status) {
	case "ACTIVE":
		if v.PowerState != "" && v.PowerState != "running" {
			// The API and the hypervisor disagree, which is worth seeing.
			return ui.Warn("ACTIVE/" + v.PowerState)
		}
		return ui.OK("ACTIVE")
	case "ERROR":
		return ui.Fail("ERROR")
	case "SHUTOFF", "STOPPED", "PAUSED", "SUSPENDED":
		return ui.Muted(strings.ToUpper(v.Status))
	default:
		return v.Status
	}
}

// primaryAddress leads with the address somebody can actually reach the VM on
// and mutes the rest.
//
// A VM answers on several — a tenant network that does not route past its own
// farm, sometimes a storage one, and one an operator can open. Nothing in the
// data marks them apart, so leading with whichever nova listed first was right
// by accident: half the rows showed a 10.x that nobody outside the farm can
// open, and the address column is the column people copy out of.
//
// Order: a floating address, then one on an operator network, then anything —
// and that ranking is openstack.ReachableAddress, the same function the SSH
// path resolves a VM with, so the address on screen is the address a connection
// will use. It was inline here, decoration and all, which is why the two could
// not share it.
func primaryAddress(v store.Instance, operatorNets []string) string {
	best := openstack.PreferredAddress(v.Addresses, operatorNets)
	if extra := len(v.Addresses) - 1; extra > 0 && best != "" {
		return best + ui.Muted(fmt.Sprintf(" (+%d)", extra))
	}
	return best
}

func vmMissingCell(v store.Instance, now time.Time) string {
	if v.MissingSince == nil {
		return ""
	}
	return ui.Fail("gone " + ui.CompactDuration(now.Sub(*v.MissingSince)))
}

// headerRow labels the columns, muted so the data stays the thing being read.
func headerRow(wide bool) []string {
	out := make([]string, len(vmHeaders))
	for i, h := range vmHeaders {
		if h == "" {
			continue
		}
		out[i] = ui.Muted(h)
	}
	if wide {
		out[0] = ui.Muted("UUID")
	}
	return out
}

// vmIDCell is how somebody gets from a listing to `vctl ssh --vm`.
//
// The id was in the data and on no screen: a VM with a name showed the name,
// and finding the uuid meant piping --json through something. It is the only
// selector SSH accepts, deliberately — a name fits several VMs across farms —
// so hiding it left the two commands unable to be used together.
//
// Short by default because eight hex characters identify a VM in any fleet this
// will see, and a full uuid on every row costs the columns after it. --wide
// prints the whole thing, which is what a copy-paste wants.
func vmIDCell(v store.Instance, wide bool) string {
	if wide || len(v.InstanceID) < 8 {
		return v.InstanceID
	}
	return v.InstanceID[:8]
}

// vmSeenCell is how long ago a collection last saw this VM.
//
// An address is only as current as the pass that recorded it. A reconcile that
// has been failing for days leaves rows that look exactly like fresh ones, and
// the address in them is where some VM used to be.
func vmSeenCell(v store.Instance, now time.Time) string {
	if v.ObservedAt.IsZero() {
		return ui.Muted("-")
	}
	age := now.Sub(v.ObservedAt)
	s := ui.CompactDuration(age)
	if age > vmStaleWindow {
		return ui.Warn(s)
	}
	return ui.Muted(s)
}

// vmStaleWindow is when a VM's recorded address stops being something to act
// on.
//
// The reconciler runs hourly. Three missed passes is the point where the
// silence is more likely to be the collector than the schedule — the same
// reasoning, and the same number, as the capability probe's freshness window.
const vmStaleWindow = 3 * time.Hour

// openstackVMShowCmd is one VM, in full, with the command to reach it.
//
// The listing is a table and a table has to leave things out. What somebody
// needs when they have found the VM is the other half — the whole uuid, the
// addresses rather than the best one, when it was last seen, and whether SSH
// will work — and, having found it, the line to run next. Printing that line
// rather than describing it is the difference between one step and three.
func openstackVMShowCmd(env CommandEnv) *cobra.Command {
	var farm string
	cmd := &cobra.Command{
		Use:               "show <nova-uuid>",
		Short:             "One VM in full, and how to reach it",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeVM(env),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, ok := access.NovaID(args[0])
			if !ok {
				return fmt.Errorf("show takes a Nova instance id or openstack:///<id>, not %q; "+
					"run 'vctl openstack vm' to find it", args[0])
			}
			return env.withStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				f := store.InstanceFilter{InstanceID: id, IncludeMissing: true}
				// One reading answers both questions this command asks about
				// deployments: which one --farm means, and what to call the one
				// the VM turns out to be in.
				cat, err := loadFarmCatalog(ctx, a, st)
				if err != nil {
					return err
				}
				if farm != "" {
					resolved, err := cat.Resolve(farm)
					if err != nil {
						return err
					}
					f.DeploymentID = resolved.ID
				}
				vms, err := st.Instances(ctx, f)
				if err != nil {
					return err
				}
				if len(vms) == 0 {
					return fmt.Errorf("no VM %s; run 'vctl openstack reconcile' if it is new", id)
				}
				if len(vms) > 1 {
					farms := make([]string, 0, len(vms))
					for _, c := range vms {
						farms = append(farms, c.DeploymentID)
					}
					return fmt.Errorf("%s is in %d deployments (%s); add --farm to say which",
						id, len(vms), strings.Join(farms, ", "))
				}
				nets := operatorNetworks()
				renderVMShow(os.Stdout, vms[0], cat.Names(), nets, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&farm, "farm", "", "deployment holding the VM, when its id is in more than one")
	registerCompletion(cmd, "farm", completeFarm(env))
	return cmd
}

func renderVMShow(w io.Writer, v store.Instance, farms map[string]string, nets []string, now time.Time) {
	ui.Section(w, nameOrID(v))
	rows := []ui.KV{
		{Key: "UUID", Value: v.InstanceID},
		{Key: "Farm", Value: vmFarmLabel(v.DeploymentID, farms)},
		{Key: "Project", Value: vmProjectLabel(v)},
		{Key: "State", Value: vmStateCell(v)},
		{Key: "Hypervisor", Value: v.HypervisorHostname},
	}
	if v.AvailabilityZone != "" {
		rows = append(rows, ui.KV{Key: "AZ", Value: v.AvailabilityZone})
	}
	// Every address, not the ranked one. The listing picks; this is where a
	// person decides, and the tenant addresses are part of what they are
	// deciding between.
	for i, a := range v.Addresses {
		key := "Addresses"
		if i > 0 {
			key = ""
		}
		label := a.Address
		if a.NetworkName != "" {
			label += ui.Muted("  " + a.NetworkName)
		}
		if a.Type == "floating" {
			label += ui.Muted("  floating")
		}
		rows = append(rows, ui.KV{Key: key, Value: label})
	}
	if v.FlavorID != "" {
		rows = append(rows, ui.KV{Key: "Flavor", Value: v.FlavorID})
	}
	if v.ImageID != "" {
		rows = append(rows, ui.KV{Key: "Image", Value: v.ImageID})
	}
	if v.CreatedAt != nil {
		rows = append(rows, ui.KV{Key: "Created", Value: v.CreatedAt.Format(time.RFC3339)})
	}
	rows = append(rows, ui.KV{Key: "Seen", Value: vmSeenLine(v, now)})
	if v.MissingSince != nil {
		rows = append(rows, ui.KV{
			Key:   "Missing",
			Value: "since " + ui.CompactDuration(now.Sub(*v.MissingSince)) + " ago — the control plane stopped listing it",
			State: ui.StateFail,
		})
	}
	ui.KVs(w, rows)

	// The next command, ready to run. Naming the flags and leaving somebody to
	// assemble them is where the flow broke in the first place.
	fmt.Fprintln(w)
	if addr := openstack.ConnectableAddress(v.Addresses, nets); addr != "" {
		fmt.Fprintf(w, "  %s\n", ui.Muted("vctl ssh --vm "+v.InstanceID+" --user <login>"))
		return
	}
	fmt.Fprintf(w, "  %s\n", ui.Muted(
		"no floating or operator-network address, so 'vctl ssh --vm' will refuse; "+
			"use 'vctl ssh <user>@<addr>' if you know one of the above is this VM"))
}

func vmSeenLine(v store.Instance, now time.Time) string {
	if v.ObservedAt.IsZero() {
		return "never"
	}
	age := now.Sub(v.ObservedAt)
	s := ui.CompactDuration(age) + " ago"
	if age > vmStaleWindow {
		return s + " — older than the collector's schedule, so the address may not be current"
	}
	return s
}

// operatorNetworks is the address prefixes this fleet routes.
//
// A config that will not load costs the address preference and nothing else —
// the listing still prints, it just cannot rank the addresses. Refusing to show
// VMs because a config file is malformed would be the worse trade.
func operatorNetworks() []string {
	cfg, err := config.Load()
	if err != nil {
		return nil
	}
	return cfg.OperatorNetworks
}
