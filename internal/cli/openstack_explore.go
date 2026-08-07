package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// openstackExploreCmd walks the fleet by choosing rather than by typing.
//
// Everything here already existed as its own command, and that is the problem
// it solves. Someone asking "what is in this farm" has to know that hosts are
// `openstack --farm`, VMs are `openstack vm --farm`, the architecture is
// `farm show`, and a VM's detail is `vm show <uuid>` — four commands, three of
// which need an identifier they do not have yet. The chain is only obvious once
// you already know the answer.
//
// So this is the same data with the identifiers removed from the user's side of
// it: pick a farm, pick a host or a VM, and the thing you picked is the argument
// the detail view wanted. Nothing new is computed and nothing is written — every
// screen below is a call into the command that owns it, so the two can never
// disagree about what a farm looks like.
//
// It is deliberately not what `vctl openstack` does. That listing is piped, has
// --json, and is read by other programs; a picker attached to it would be a
// prompt in the middle of a script.
func openstackExploreCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "explore [deployment]",
		Aliases: []string{"browse"},
		Short:   "Walk a farm and what is in it, by choosing instead of typing",
		Long: "One way in to everything the other commands show:\n\n" +
			"  deployment → its hosts → one host's roles and versions\n" +
			"             → its VMs   → one VM's addresses and how to reach it\n\n" +
			"Read-only. It changes nothing, and every screen is the same renderer the\n" +
			"individual command uses — `farm show`, `openstack host`, `vm show`.\n\n" +
			"An argument starts inside that deployment instead of at the picker.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Nothing here works without somebody to ask, and failing with the
			// commands that do work is more useful than failing with "no
			// terminal".
			if !isTerminal() {
				return fmt.Errorf("explore is interactive and there is no terminal to pick at; " +
					"use 'vctl openstack farm list', 'vctl openstack --farm <f>' and " +
					"'vctl openstack vm --farm <f>' instead")
			}
			return env.withStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				return exploreFarms(cmd.Context(), a, st, args)
			})
		},
	}
	return cmd
}

// exploreFarms is the outer loop: choose a deployment, walk it, come back.
func exploreFarms(ctx context.Context, a *app.App, st *store.Store, args []string) error {
	farms, err := farmChoices(ctx, st)
	if err != nil {
		return err
	}
	if len(farms) == 0 {
		ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
		return nil
	}
	// An argument is a starting point, not a restriction: leaving that farm
	// returns to the full list rather than ending the session.
	if len(args) > 0 {
		f, err := resolveFarm(farms, args[0])
		if err != nil {
			return err
		}
		if err := exploreFarm(ctx, a, st, f); err != nil {
			return err
		}
	}
	for {
		i, back, err := pickOrBack(farmPickLabels(farms), "Deployments", "quit")
		if err != nil {
			return err
		}
		if back {
			return nil
		}
		if err := exploreFarm(ctx, a, st, farms[i]); err != nil {
			return err
		}
	}
}

// The farm menu's entries, by what they answer.
const (
	menuHosts        = "Hosts"
	menuVMs          = "VMs"
	menuArchitecture = "Architecture"
	menuDiagnose     = "Diagnose"
)

// exploreFarm is one deployment, until the reader leaves it.
//
// The snapshot is taken once per visit rather than per screen, so the host count
// on the menu and the hosts in the list are the same reading. Coming back out
// and in again is how you refresh — which is also the only way to be sure you
// did.
func exploreFarm(ctx context.Context, a *app.App, st *store.Store, f farmChoice) error {
	snap, err := st.FarmSnapshot(ctx, f.ID)
	if err != nil {
		return err
	}
	live := liveInstances(snap.Instances)
	names, err := farmNames(ctx, st)
	if err != nil {
		return err
	}
	for {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, farmHeadline(f, snap, live, time.Now()))

		items := []string{
			fmt.Sprintf("%s (%d)", menuHosts, len(snap.Hosts)),
			fmt.Sprintf("%s (%d)", menuVMs, len(live)),
			menuArchitecture + "  — roles, releases, unsettled membership",
			menuDiagnose + "     — what a reconcile would need, without changing anything",
		}
		i, back, err := pickOrBack(items, farmMenuTitle(f), "deployments")
		if err != nil {
			return err
		}
		if back {
			return nil
		}
		switch strings.Fields(items[i])[0] {
		case menuHosts:
			err = exploreHosts(snap.Hosts)
		case menuVMs:
			err = exploreVMs(live, names)
		case menuArchitecture:
			err = showArchitecture(ctx, st, f.ID)
		case menuDiagnose:
			// Read-only, like everything else here — see openstack_farm_doctor.
			// Verification is not passed on: a farm with a self-signed endpoint
			// is a finding to report, not something to work around silently.
			renderFarmDoctor(os.Stdout, f, diagnoseFarm(ctx, a, st, f.ID, false))
		}
		if err != nil {
			return err
		}
	}
}

// exploreHosts lists the machines and shows whichever one is chosen.
func exploreHosts(hosts []store.OpenStackHost) error {
	if len(hosts) == 0 {
		ui.Infof(os.Stdout, "no host has filed a capability probe for this deployment yet.")
		return nil
	}
	now := time.Now()
	labels := make([]string, 0, len(hosts))
	for _, h := range hosts {
		labels = append(labels, hostPickLabel(h, now))
	}
	for {
		i, back, err := pickOrBack(labels, "Hosts", "back")
		if err != nil || back {
			return err
		}
		fmt.Fprintln(os.Stdout)
		renderOpenStackHost(os.Stdout, hosts[i], time.Now())
	}
}

// exploreVMs lists the instances and shows whichever one is chosen.
//
// The detail view is the one that closes the loop the review opened: it carries
// the whole uuid and the `vctl ssh` line that reaches it, so the identifier
// nobody can memorise never has to be typed.
func exploreVMs(vms []store.Instance, farms map[string]string) error {
	if len(vms) == 0 {
		ui.Infof(os.Stdout, "no VMs recorded here. 'vctl openstack reconcile --farm <f>' collects them.")
		return nil
	}
	nets := operatorNetworks()
	labels := make([]string, 0, len(vms))
	for _, v := range vms {
		labels = append(labels, vmPickLabel(v, nets))
	}
	for {
		i, back, err := pickOrBack(labels, "VMs", "back")
		if err != nil || back {
			return err
		}
		fmt.Fprintln(os.Stdout)
		renderVMShow(os.Stdout, vms[i], farms, nets, time.Now())
	}
}

func showArchitecture(ctx context.Context, st *store.Store, id string) error {
	now := time.Now()
	assessment, err := collectAssessment(ctx, st, id, now)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout)
	renderFarmShow(os.Stdout, assessment, now)
	return nil
}

// liveInstances drops the VMs nova no longer lists.
//
// FarmSnapshot keeps them because the assessment counts them, and a menu is not
// a count: "VMs (34)" leading to a list where nine are gone reads as a fleet
// that has more machines than it does.
func liveInstances(in []store.Instance) []store.Instance {
	out := make([]store.Instance, 0, len(in))
	for _, v := range in {
		if v.MissingSince == nil {
			out = append(out, v)
		}
	}
	return out
}

// farmHeadline is the one line above the menu: which deployment this is, and
// whether anything has confirmed it lately.
func farmHeadline(f farmChoice, snap store.FarmSnapshot, live []store.Instance, now time.Time) string {
	name := f.Name
	if name == "" {
		name = f.ID
	}
	parts := []string{}
	if f.Name != "" {
		parts = append(parts, f.ID)
	}
	if f.Region != "" {
		parts = append(parts, f.Region)
	}
	parts = append(parts, pluralHosts(len(snap.Hosts)), fmt.Sprintf("%d VMs", len(live)))
	if f.State != "" && f.State != store.StateActive {
		parts = append(parts, f.State)
	}
	// The last successful reconcile is what makes every other number here worth
	// trusting, so it is on the same line as them rather than a screen away.
	switch {
	case snap.Run == nil || snap.Run.SucceededAt == nil:
		parts = append(parts, "never reconciled")
	default:
		parts = append(parts, "reconciled "+ui.CompactDuration(now.Sub(*snap.Run.SucceededAt))+" ago")
	}
	return farmHeading(name) + " " + ui.Muted("· "+strings.Join(parts, " · "))
}

func farmMenuTitle(f farmChoice) string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}

// hostPickLabel says what the machine is for, in the order somebody scans:
// which host, what it does, what it runs, how fresh that is.
func hostPickLabel(h store.OpenStackHost, now time.Time) string {
	label := ui.PadRight(h.Hostname, 24) + "  " + ui.PadRight(rolesSummary(h.Roles, false), 26)
	label += "  " + ui.PadRight(versionCell(h, false), 10)
	label += "  " + ageCell(h, now)
	if h.LastError != "" {
		label += "  " + ui.Fail("probe failed")
	}
	if s := stateCell(h.HostState); s != "" {
		label += "  " + s
	}
	return label
}

// vmPickLabel leads with the name because that is what a person recognises, and
// carries the address because it is the other thing they came for. The uuid is
// not here: it is 36 characters that identify nothing to a reader, and the
// detail view has it.
func vmPickLabel(v store.Instance, nets []string) string {
	label := ui.PadRight(ui.Truncate(nameOrID(v), 32), 32) + "  " + ui.PadRight(vmStateCell(v), 18)
	label += "  " + ui.PadRight(ui.Truncate(primaryAddress(v, nets), 20), 20)
	label += "  " + ui.Muted(ui.Truncate(v.HypervisorHostname, 18))
	return label
}

// pickOrBack is pickIndex with cancelling treated as an answer.
//
// Esc means "up one level" in a walk, not failure. pickIndex reports a
// cancellation as an error because its callers are one-shot commands where
// there is nothing to go back to.
//
// The hint says which of the two it is here, because at the top of the walk
// there is no level above and the same key ends the session — and a prompt that
// offers "back" and then exits has told the reader the wrong thing.
func pickOrBack(items []string, title, hint string) (int, bool, error) {
	idxs, cancelled, err := runListPicker(items, nil, title+"   (esc: "+hint+")", false)
	if err != nil {
		return 0, false, err
	}
	if cancelled || len(idxs) == 0 {
		return 0, true, nil
	}
	return idxs[0], false, nil
}
