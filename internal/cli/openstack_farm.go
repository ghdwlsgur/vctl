package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/timing"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func openstackFarmCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "farm",
		Short: "Name the deployments so the listing reads as something other than endpoints",
	}
	// Gated per leaf, because a gate on the parent is not a gate.
	//
	// Cobra runs the leaf, and enforceRBAC reads the annotation off whatever it
	// is about to run. `farm` carried the annotation and `farm state` carried
	// none, so the pre-run found an empty name and returned straight away:
	// `vctl openstack farm state` changed a deployment's declared state with no
	// authorization check at all. Measured — cobra resolves that argv to
	// "state", whose rbac.command was "".
	//
	// show stays ungated, alongside `openstack` and `list`: reading what is
	// deployed is allowed to any authenticated user, and only the two that write
	// are mutations. Same grant name as before, so grants already issued still
	// apply.
	cmd.AddCommand(gate(openstackFarmNameCmd(env), "openstack-farm"))
	cmd.AddCommand(openstackFarmDoctorCmd(env))
	cmd.AddCommand(openstackFarmListCmd(env))
	cmd.AddCommand(openstackFarmShowCmd(env))
	cmd.AddCommand(gate(openstackFarmStateCmd(env), "openstack-farm"))
	return cmd
}

func openstackFarmNameCmd(env CommandEnv) *cobra.Command {
	var region string
	var clearRegion bool
	cmd := &cobra.Command{
		Use:   "name [deployment] [name]",
		Short: "Give a deployment a name people can read",
		Long: "A farm's id is its Keystone endpoint — 172.16.0.245:5000 — which is stable and says\n" +
			"nothing. This attaches a name to it.\n\n" +
			"The name is stored rather than derived. Deriving it from the hosts, by a common prefix\n" +
			"or their datacenter, would rename the farm whenever its membership changed.\n\n" +
			"With no arguments the deployment is picked from a list and the name asked for in a form.",
		Args: cobra.MaximumNArgs(2),
		// Only the first argument. The second is the new name — nothing knows
		// it yet, which is the whole point of the command.
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withStore(cmd.Context(), true, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, a, st)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
					return nil
				}
				id, name := "", ""
				if len(args) > 0 {
					id = args[0]
				}
				if len(args) > 1 {
					name = args[1]
				}
				id, name, region, err = resolveFarmName(farms, id, name, region)
				if err != nil {
					return err
				}
				// nil is "leave whatever is recorded". An omitted --region on a
				// command that reads as a rename used to write an empty one and
				// drop the region silently; removing one is its own flag.
				//
				// The interactive form asks for a region, so what it collected
				// is an answer either way.
				//
				// Anything non-empty is an answer, whether it came from the flag
				// or from the prompt the interactive form shows.
				var write *string
				if clearRegion {
					empty := ""
					write = &empty
				} else if region != "" {
					write = &region
				}
				if err := st.SetDeploymentName(ctx, id, name, write); err != nil {
					return err
				}
				// The name is what every listing leads with and what shell
				// completion offers, so a stored reading kept past this one
				// would go on offering the old name — to the person who just
				// changed it.
				forgetReadings(a)
				ui.Successf(os.Stdout, "%s is now %q", id, name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "the deployment's region, if it has one worth recording")
	cmd.Flags().BoolVar(&clearRegion, "clear-region", false, "remove the recorded region instead of keeping it")
	cmd.MarkFlagsMutuallyExclusive("region", "clear-region")
	return cmd
}

// farmChoice is what the picker shows, which is now the domain's own farm.
//
// It used to be a CLI struct assembled here from two queries, alongside three
// other assemblies of the same thing elsewhere. The rules for "which hosts
// count towards a farm" agreed between them by inspection rather than by
// construction — see internal/openstack/fleet.
type farmChoice = fleet.Farm

// farmStateMeanings says what each word claims about a deployment.
//
// Not the host wording: a farm is not a machine. "broken" here is a control
// plane that will not answer, which is a different thing from a host that will
// not boot, and the anomalies each state marks as expected differ with it.
func farmStateMeanings() string {
	return "active: expected to answer, a failing reconcile is news\n" +
		"maintenance: somebody is working on it, failures are expected\n" +
		"broken: a fault somebody diagnosed and has not fixed\n" +
		"retired: not operated any more, and hidden from the listing"
}

// fleetSnapshot reads the fleet once: what every farm-taking command resolves
// and renders against.
//
// One transaction, one instant. Before this each command opened its own reads
// and two of them read the same tables twice in a single run — so a screen
// could pair a host count from before a reconcile with a VM count from after.
//
// It returns the snapshot rather than the catalog and does not store it. Both
// are fleet.Reader's business: it knows which shape was asked for, so it stores
// under the right one, and folding into a catalog is what a caller wanted rather
// than part of reading.
func fleetSnapshot(ctx context.Context, st *store.Store) (store.Fleet, error) {
	defer timing.Start("fleet-query")()
	return st.FleetSnapshot(ctx)
}

// fleetSnapshotWithVMs is the reading that carries the instance rows, for the
// screen that lists them.
func fleetSnapshotWithVMs(ctx context.Context, st *store.Store) (store.Fleet, error) {
	defer timing.Start("fleet-query+vms")()
	return st.FleetSnapshotWithVMs(ctx)
}

// loadVMCatalog is the full reading for a caller that is not going through a
// Reader — the browser, which manages its own freshness against its own window.
//
// Stored once, as ShapeVMs. A full reading answers everything a light one would
// have, and LoadAtLeast already reaches up: a caller asking for farms considers
// both files and takes whichever is newer. Writing it twice bought nothing and
// cost a second copy of the same 200KB on every browse.
func loadVMCatalog(ctx context.Context, a *app.App, st *store.Store) (fleet.Catalog, error) {
	snap, err := fleetSnapshotWithVMs(ctx, st)
	if err != nil {
		return fleet.Catalog{}, err
	}
	keepReading(a, fleet.ShapeVMs, snap)
	return fleet.From(snap), nil
}

// loadFarmCatalog is the reading without the VM rows: everything about the
// fleet except which instances there are.
//
// Most screens print how many VMs a deployment has and never which ones, and
// carrying the rows to print a number is most of what those commands cost —
// measured at 60–135ms per listing.
func loadFarmCatalog(ctx context.Context, a *app.App, st *store.Store) (fleet.Catalog, error) {
	defer timing.Start("fleet-query-light")()
	snap, err := st.FleetFarms(ctx)
	if err != nil {
		return fleet.Catalog{}, err
	}
	// Deliberately not stored. This reading has no VM counts and no reconcile
	// times — it does not need them — and writing it under the same shape would
	// replace a full reading with a lesser one, so a later `farm list` would
	// print every deployment as having zero VMs and never having reconciled.
	//
	// Only supersets are written; anything may be read. See loadCatalog.
	return fleet.From(snap), nil
}

// farmChoices is the light reading: which deployments there are and what is in
// them, without the fleet's VMs.
//
// Resolving a typed word and labelling a picker do not need instances, and
// shell completion pays for what it reads on every Tab — so this is two
// statements where loadCatalog is eight.
func farmChoices(ctx context.Context, a *app.App, st *store.Store) ([]farmChoice, error) {
	cat, err := loadFarmCatalog(ctx, a, st)
	if err != nil {
		return nil, err
	}
	return cat.Farms(), nil
}

// resolveFarmName fills in whatever was not given on the command line.
func resolveFarmName(farms []farmChoice, id, name, region string) (string, string, string, error) {
	if id != "" {
		// resolveFarm rather than a position lookup: this path renames a
		// deployment, and its error says which ids share a name instead of
		// picking one of them.
		f, err := resolveFarm(farms, id)
		if err != nil {
			return "", "", "", err
		}
		if name != "" {
			return f.ID, strings.TrimSpace(name), region, nil
		}
		return farmNameForm(f, region)
	}
	if !isTerminal() {
		return "", "", "", fmt.Errorf("a deployment is required when there is no terminal to pick at")
	}
	i, err := pickIndex(farmPickLabels(farms), nil, "Name a deployment")
	if err != nil {
		return "", "", "", err
	}
	return farmNameForm(farms[i], region)
}

// resolveFarm turns what somebody typed into exactly one deployment.
//
// The rules live in internal/openstack/fleet, because they only mean anything
// if they are the same everywhere and they were not: one copy matched ids and
// membership ids and never the name on screen, so `--farm seoul-b` — the name
// that listing itself prints — selected nothing and rendered as an empty fleet.
func resolveFarm(farms []farmChoice, selector string) (farmChoice, error) {
	return fleet.Resolve(farms, selector)
}

// indexOfFarm is resolveFarm for the callers that need a position in the list
// they were given, such as the interactive picker's starting cursor.
func indexOfFarm(farms []farmChoice, selector string) int {
	return fleet.IndexOf(farms, selector)
}

// farmPickLabels shows what each deployment contains, because the endpoint on
// its own is not something a person recognises.
//
// The name leads. It used to be the second column behind a 24-wide endpoint, so
// a chooser meant to be read by name presented a column of IP addresses with
// the names trailing off to the right — the exact thing `farm name` exists to
// stop the listing from doing. An unnamed deployment puts its endpoint in that
// slot, which is the whole of what is known about it.
func farmPickLabels(farms []farmChoice) []string {
	out := make([]string, 0, len(farms))
	for _, f := range farms {
		lead, rest := f.ID, ""
		if f.Name != "" {
			lead, rest = f.Name, f.ID
		}
		label := ui.Value(ui.PadRight(ui.Truncate(lead, 22), 22))
		label += "  " + ui.Muted(ui.PadRight(rest, 22))
		if f.State != "" && f.State != store.StateActive {
			label += "  " + stateCell(f.State)
		}
		if n := len(f.Hosts); n > 0 {
			label += "  " + ui.Muted(pluralHosts(n)+" · "+ui.Truncate(farmShape(f.Hosts, false), 44))
		}
		out = append(out, label)
	}
	return out
}

func farmNameForm(f farmChoice, region string) (string, string, string, error) {
	if !isTerminal() {
		return "", "", "", fmt.Errorf("a name is required when there is no terminal to ask at")
	}
	name := f.Name
	if region == "" {
		region = f.Region
	}
	desc := f.ID
	if n := len(f.Hosts); n > 0 {
		desc = fmt.Sprintf("%s · %d hosts · %s", f.ID, n, farmShape(f.Hosts, false))
	}
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Name").
			Description(desc).
			Value(&name).
			Validate(nonEmpty("name")),
		// Optional, and last. Most deployments here have no region worth
		// recording, and a required field for something usually empty turns
		// naming a farm into filling in a form.
		huh.NewInput().Title("Region").
			Description("optional; blank is fine").
			Value(&region),
	))
	if err := form.WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
		return "", "", "", err
	}
	return f.ID, strings.TrimSpace(name), strings.TrimSpace(region), nil
}

func openstackFarmStateCmd(env CommandEnv) *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:   "state [deployment] [state]",
		Short: "Declare what an operator knows about a deployment: active, maintenance, broken, retired",
		Long: "Observation cannot tell a farm that is broken from one being rebuilt. A reconcile\n" +
			"failing every six hours against a farm somebody is mid-upgrade on is expected; the\n" +
			"same failure against a farm nobody touched is news, and nothing collected separates\n" +
			"them.\n\n" +
			"Anomalies are still reported once a state is declared — a declared fault does not\n" +
			"stop being a fault, and somebody has to see what it is — but they are marked as\n" +
			"expected rather than as news.\n\n" +
			"With no arguments the deployment is picked from a list and the state asked for in a form.",
		Args:              cobra.MaximumNArgs(2),
		ValidArgsFunction: byPosition(completeFarm(env), staticCompletions(store.HostStates...)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withStore(cmd.Context(), true, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, a, st)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
					return nil
				}
				id, state := "", ""
				if len(args) > 0 {
					id = args[0]
				}
				if len(args) > 1 {
					state = args[1]
				}
				id, state, note, err = resolveFarmState(farms, id, state, note)
				if err != nil {
					return err
				}
				if err := st.SetDeploymentState(ctx, id, state, note); err != nil {
					return err
				}
				// A declared state changes what the listings mark as expected
				// and hides a retired deployment altogether. Keeping the old
				// reading would mean the farm somebody just retired stays in the
				// list they retired it out of.
				forgetReadings(a)
				ui.Successf(os.Stdout, "%s is now %s", id, state)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "why — the state says what to expect, this says what happened")
	return cmd
}

// resolveFarmState fills in whatever was not given on the command line.
func resolveFarmState(farms []farmChoice, id, state, note string) (string, string, string, error) {
	if id != "" {
		i := indexOfFarm(farms, id)
		if i < 0 {
			return "", "", "", fmt.Errorf("no deployment %q; run 'vctl openstack' to see them", id)
		}
		if state != "" {
			if !store.ValidState(state) {
				return "", "", "", fmt.Errorf("%q is not a state; use one of %s",
					state, strings.Join(store.HostStates, ", "))
			}
			return farms[i].ID, state, strings.TrimSpace(note), nil
		}
		return farmStateForm(farms[i], note)
	}
	if !isTerminal() {
		return "", "", "", fmt.Errorf("a deployment is required when there is no terminal to pick at")
	}
	i, err := pickIndex(farmPickLabels(farms), nil, "Declare a deployment's state")
	if err != nil {
		return "", "", "", err
	}
	return farmStateForm(farms[i], note)
}

func farmStateForm(f farmChoice, note string) (string, string, string, error) {
	if !isTerminal() {
		return "", "", "", fmt.Errorf("a state is required when there is no terminal to ask at")
	}
	state := f.State
	if state == "" {
		state = store.StateActive
	}
	desc := f.ID
	if n := len(f.Hosts); n > 0 {
		desc = fmt.Sprintf("%s · %d hosts · %s", f.ID, n, farmShape(f.Hosts, false))
	}
	form := huh.NewForm(huh.NewGroup(
		// A Select, not free text: the database constrains the column, and
		// typing "down" into a field that takes only these four should fail at
		// the form rather than after the note has been written.
		//
		// Inline, so ↑/↓ still move between fields here as they do everywhere
		// else. See ui.FormKeyMap.
		huh.NewSelect[string]().Title("State").
			Description(desc+"\n"+farmStateMeanings()).
			Options(stateOptions()...).
			Value(&state).
			Inline(true),
		huh.NewInput().Title("Note").
			Description("optional; what happened, for whoever reads this a week later").
			Value(&note),
	))
	if err := form.WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
		return "", "", "", err
	}
	return f.ID, state, strings.TrimSpace(note), nil
}
