package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func openstackFarmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "farm",
		Short: "Name the deployments so the listing reads as something other than endpoints",
	}
	cmd.AddCommand(openstackFarmNameCmd())
	cmd.AddCommand(openstackFarmShowCmd())
	cmd.AddCommand(openstackFarmStateCmd())
	return cmd
}

func openstackFarmNameCmd() *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "name [deployment] [name]",
		Short: "Give a deployment a name people can read",
		Long: "A farm's id is its Keystone endpoint — 172.16.0.245:5000 — which is stable and says\n" +
			"nothing. This attaches a name to it.\n\n" +
			"The name is stored rather than derived. Deriving it from the hosts, by a common prefix\n" +
			"or their datacenter, would rename the farm whenever its membership changed.\n\n" +
			"With no arguments the deployment is picked from a list and the name asked for in a form.",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, st)
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
				if err := st.SetDeploymentName(ctx, id, name, region); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "%s is now %q", id, name)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "the deployment's region, if it has one worth recording")
	return cmd
}

// farmChoice is one deployment as the picker shows it.
type farmChoice struct {
	ID      string
	Name    string
	Region  string
	State   string
	Hosts   int
	Roles   string
	Unnamed bool
}

// farmChoices assembles what a person needs to tell one endpoint from another.
//
// The id alone is not enough to choose by. Somebody naming farms is looking at
// a list of addresses they may never have seen, and the thing that identifies a
// deployment to them is what is in it — seven hosts, three controllers.
func farmChoices(ctx context.Context, st *store.Store) ([]farmChoice, error) {
	hosts, err := st.OpenStackHosts(ctx)
	if err != nil {
		return nil, err
	}
	named := map[string]store.Deployment{}
	ds, err := st.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		named[d.ID] = d
	}

	byFarm := map[string][]store.OpenStackHost{}
	for _, h := range hosts {
		if h.Farm != "" && h.Detected {
			byFarm[h.Farm] = append(byFarm[h.Farm], h)
		}
	}
	// A deployment somebody named before it was ever reconciled still belongs in
	// the list, or renaming it would mean typing an id that is not offered.
	for id := range named {
		if _, ok := byFarm[id]; !ok {
			byFarm[id] = nil
		}
	}

	out := make([]farmChoice, 0, len(byFarm))
	for id, hs := range byFarm {
		c := farmChoice{ID: id, Hosts: len(hs), Roles: farmShape(hs)}
		if d, ok := named[id]; ok {
			c.Name, c.Region, c.State = d.DisplayName, d.Region, d.State
		}
		c.Unnamed = c.Name == ""
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// resolveFarmName fills in whatever was not given on the command line.
func resolveFarmName(farms []farmChoice, id, name, region string) (string, string, string, error) {
	if id != "" {
		i := indexOfFarm(farms, id)
		if i < 0 {
			return "", "", "", fmt.Errorf("no deployment %q; run 'vctl openstack' to see them", id)
		}
		if name != "" {
			return farms[i].ID, strings.TrimSpace(name), region, nil
		}
		return farmNameForm(farms[i], region)
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

func indexOfFarm(farms []farmChoice, id string) int {
	for i, f := range farms {
		if strings.EqualFold(f.ID, id) || (f.Name != "" && strings.EqualFold(f.Name, id)) {
			return i
		}
	}
	return -1
}

// farmPickLabels shows what each deployment contains, because the endpoint on
// its own is not something a person recognises.
func farmPickLabels(farms []farmChoice) []string {
	out := make([]string, 0, len(farms))
	for _, f := range farms {
		label := ui.PadRight(f.ID, 24)
		if f.Name != "" {
			label += "  " + ui.Value(f.Name)
		}
		if f.State != "" && f.State != store.StateActive {
			label += "  " + stateCell(f.State)
		}
		if f.Hosts > 0 {
			label += "  " + ui.Muted(fmt.Sprintf("%d hosts · %s", f.Hosts, ui.Truncate(f.Roles, 48)))
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
	if f.Hosts > 0 {
		desc = fmt.Sprintf("%s · %d hosts · %s", f.ID, f.Hosts, f.Roles)
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

func openstackFarmStateCmd() *cobra.Command {
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
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, st)
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
	if f.Hosts > 0 {
		desc = fmt.Sprintf("%s · %d hosts · %s", f.ID, f.Hosts, f.Roles)
	}
	form := huh.NewForm(huh.NewGroup(
		// A Select, not free text: the database constrains the column, and
		// typing "down" into a field that takes only these four should fail at
		// the form rather than after the note has been written.
		huh.NewSelect[string]().Title("State").
			Description(desc).
			Options(stateOptions()...).
			Value(&state),
		huh.NewInput().Title("Note").
			Description("optional; what happened, for whoever reads this a week later").
			Value(&note),
	))
	if err := form.WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
		return "", "", "", err
	}
	return f.ID, state, strings.TrimSpace(note), nil
}
