package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// A two-pane browser over what the fleet has already reported: deployments on
// the left, the chosen one's hosts or VMs on the right, a detail view over the
// top of both.
//
// It exists because the data was only reachable by naming it. Hosts are
// `openstack list --farm`, VMs are `openstack vm --farm`, a VM's detail is
// `vm show <uuid>` — three commands and an identifier nobody has memorised, in
// an order that is only obvious once you already know the answer. Moving a
// cursor asks the same questions without knowing any of it.
//
// Everything here reads the database and nothing else. No screen contacts a
// farm's control plane: that is `farm doctor`, it authenticates, and it can
// hang on a farm that is down — which is not a thing a browser may do. Two
// tests hold this, one for writes and one for the control plane.
//
// The detail screens are the individual commands' own renderers, so this and
// `openstack host` / `vm show` cannot drift into showing different facts about
// the same machine.
func openstackExploreCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "explore [deployment]",
		Aliases: []string{"browse", "ui"},
		Short:   "Browse deployments, hosts and VMs in one screen",
		Long: "Two panes: deployments on the left, the selected one's VMs or hosts on the right.\n\n" +
			"  tab      move between the panes        v / h   VMs or hosts on the right\n" +
			"  enter    open the row's detail         /       filter the focused pane\n" +
			"  r        re-read from the database     q       quit\n\n" +
			"Opens from the last reading when there is one and refreshes behind the screen,\n" +
			"so the first thing on screen is not an empty pane. The title bar says which it\n" +
			"is showing and how old it is.\n\n" +
			"Read-only, and it reads the database alone — nothing here contacts a farm's\n" +
			"control plane. Each detail screen is the same renderer the individual command\n" +
			"uses: `openstack host` and `vm show`.\n\n" +
			"A farm that is misbehaving is a different question, asked with\n" +
			"`vctl openstack farm doctor <deployment>`.\n\n" +
			"An argument selects that deployment at startup.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpenStackExplore(cmd, env, args)
		},
	}
	return cmd
}

func runOpenStackExplore(cmd *cobra.Command, env CommandEnv, args []string) error {
	// A full-screen program needs a screen. Naming the commands that answer the
	// same questions without one is more useful than reporting its absence.
	if !isTerminal() {
		return fmt.Errorf("openstack is a full-screen browser and there is no terminal; " +
			"use 'vctl openstack list', 'vctl openstack list --farm <f>' and " +
			"'vctl openstack vm --farm <f>' instead")
	}
	// withApp, not withStore: opening the store is the expensive part and the
	// screen may not need it at all. See openLater.
	return env.withApp(func(a *app.App) error {
		return runExplore(cmd.Context(), a, args, wantsFresh(cmd))
	})
}

// runExplore puts a screen up and lets it re-read behind itself.
//
// The database call is a tea.Cmd rather than a step in Update: a read on the
// key path stops the whole screen for as long as it takes, with no way to say
// so while it is stopped. As a Cmd it runs in its own goroutine and arrives as
// a message, so the browser stays usable — filtering, scrolling, opening a
// detail — while the numbers behind it are being fetched.
//
// That also removes the reload loop this used to have. Refreshing in place
// keeps the panes, the filters and the size because they were never taken
// away, and the cursor stays on the row it was on by name rather than by
// position.
func runExplore(ctx context.Context, a *app.App, args []string, live bool) error {
	st := &openLater{app: a}
	defer st.Close()

	data, err := firstExploreScreen(ctx, a, st, live)
	if err != nil {
		return err
	}
	if len(data.Farms) == 0 {
		ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
		return nil
	}
	m := newExploreModel(data)
	m.refresh = func() (exploreData, error) { return loadExploreData(ctx, a, st) }
	// A stored reading is a starting point, not an answer: the screen is up
	// immediately and the refresh that corrects it is already running.
	// Not when a login is due: the prompt would open behind the alternate
	// screen, where nobody can see or answer it.
	m.refreshing = data.Cached && !data.NeedsLogin
	if len(args) > 0 {
		// Resolved against the first reading, so a typo fails before the screen
		// opens rather than after.
		f, err := resolveFarm(data.Farms, args[0])
		if err != nil {
			return err
		}
		m.selectFarmID(f.ID)
	}
	// The alternate screen, so the terminal somebody was working in comes back
	// exactly as they left it.
	res, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	final, ok := res.(exploreModel)
	if !ok {
		return nil
	}
	// What was on screen at the end survives the screen. A VM's detail carries
	// the ssh line that reaches it, and an alternate screen that restores on
	// exit would take it back the moment somebody went to run it.
	if len(final.carry) > 0 {
		fmt.Fprintln(os.Stdout, strings.Join(final.carry, "\n"))
	}
	return final.err
}

// firstExploreScreen is what goes up before anything has been read.
//
// A stored reading opens the browser at once. Going to the database first buys
// a Vault credential, a TLS handshake and four queries — measured at ten
// seconds on a bad path here — against an alternate screen that shows nothing
// for the whole of it, which is indistinguishable from a program that has hung.
//
// Only when authenticating is silent. With a lapsed token the read would put an
// SSO prompt behind a full-screen program, where it cannot be seen or answered;
// that login happens here, in front of the screen, as it did before.
func firstExploreScreen(ctx context.Context, a *app.App, st *openLater, live bool) (exploreData, error) {
	if !live {
		if rd, ok := storedReader(a).Stored(fleet.ShapeVMs, fleet.ForBrowsing); ok {
			out := exploreDataFrom(rd.Catalog)
			// A stored reading with nothing in it is not worth a screen. The
			// caller answers an empty fleet with "no deployments yet, run the
			// node agents" and returns, which would be advice about a fleet
			// nobody has looked at since.
			if len(out.Farms) > 0 {
				out.Cached = true
				// A lapsed token no longer costs the screen.
				//
				// This used to go to the database first whenever a login was
				// due, because the login prompt would otherwise open behind a
				// full-screen program where it cannot be seen or answered. That
				// was right about the prompt and wrong about the screen: the
				// reader was made to wait for an authentication they had not
				// asked for yet, to see rows that were already on disk.
				//
				// So the rows go up, and the one thing that would need the
				// prompt — refreshing — is what does not happen. The title bar
				// says why, and `vctl login` in another terminal is the fix.
				out.NeedsLogin = a.WouldPromptForLogin()
				return out, nil
			}
		}
	}
	// On stderr, so the alternate screen wipes it the moment there is something
	// to show.
	ui.Infof(os.Stderr, "reading the fleet…")
	return loadExploreData(ctx, a, st)
}

// exploreData is the whole picture, read once.
//
// One read for the fleet rather than one per farm: moving a cursor must not
// open a database connection, and a browser whose panes disagree because they
// were read seconds apart is worse than one that is a minute old and says so.
// `r` re-reads, which is the only way to be sure the screen is current.
type exploreData struct {
	Farms  []farmChoice
	Hosts  map[string][]store.OpenStackHost
	VMs    map[string][]store.Instance
	Names  map[string]string
	Runs   map[string]store.ReconcileRun
	Nets   []string
	ReadAt time.Time

	// NeedsLogin says a refresh cannot run without an interactive login, so the
	// screen is showing what it has and will not correct itself.
	NeedsLogin bool

	// Cached says this came off disk rather than out of the database. The title
	// bar says so too: a browser showing a stored reading as though it had just
	// read is a browser that will eventually show somebody a machine that is
	// gone.
	Cached bool
}

// No span of its own. What this costs is the store opening and the query, and
// both are already measured — db-credential, db-connect, fleet-query+vms. An
// outer span around them counted the same milliseconds twice and pushed the
// report past 100%, which is the one thing a breakdown must not do.
func loadExploreData(ctx context.Context, a *app.App, st *openLater) (exploreData, error) {
	var out exploreData
	err := st.use(ctx, func(st *store.Store) error {
		// One transaction for the whole screen. This used to be four reads, two
		// of which the picker's own assembly then repeated — so the left pane's
		// host count and the right pane's VM list came from different instants.
		cat, err := loadVMCatalog(ctx, a, st)
		if err != nil {
			return err
		}
		out = exploreDataFrom(cat)
		return nil
	})
	return out, err
}

// exploreDataFrom lays a reading out the way the panes index it. The same
// arrangement whether it came from the database or off disk — one shape means
// the screen cannot behave differently depending on where its rows came from.
func exploreDataFrom(cat fleet.Catalog) exploreData {
	out := exploreData{
		Farms:  cat.Farms(),
		Hosts:  map[string][]store.OpenStackHost{},
		VMs:    map[string][]store.Instance{},
		Names:  cat.Names(),
		Runs:   map[string]store.ReconcileRun{},
		Nets:   operatorNetworks(),
		ReadAt: cat.ReadAt(),
	}
	for _, f := range out.Farms {
		out.Hosts[f.ID] = f.Hosts
		out.VMs[f.ID] = cat.VMs(f.ID)
		if run := cat.Run(f.ID); run != nil {
			out.Runs[f.ID] = *run
		}
	}
	return out
}
