// Package cli defines the vctl Cobra command tree.
package cli

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/timing"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Version is injected by main for --version output.
var Version = "dev"

// debugTiming is set by the persistent --debug-timing flag.
var debugTiming bool

// Dependencies are the externally-injectable collaborators of the command tree.
// The zero value uses production defaults (app.New); tests supply a fake NewApp
// to exercise commands without a real Vault or config.
type Dependencies struct {
	// NewApp builds the App that commands use. Defaults to app.New.
	NewApp func() (*app.App, error)
}

func (d Dependencies) withDefaults() Dependencies {
	if d.NewApp == nil {
		d.NewApp = app.New
	}
	return d
}

// Execute builds the production command tree and runs it.
//
// The timing report is printed here rather than in a post-run hook because a
// command that failed is exactly the one worth measuring, and PersistentPostRun
// does not run for those.
func Execute() error {
	err := NewRoot(Dependencies{}).Execute()
	timing.Report(os.Stderr)
	return err
}

// NewRoot builds the vctl command tree with the given dependencies. Split out
// from Execute so tests can construct the tree — check wiring, flags, arg rules,
// help/version output — and run commands with a fake app, instead of only being
// reachable through main with a real Vault.
func NewRoot(deps Dependencies) *cobra.Command {
	env := CommandEnv{NewApp: deps.withDefaults().NewApp}

	root := &cobra.Command{
		Version: Version,
		Use:     "vctl",
		Short:   "SRE infrastructure control plane",
		Long: `vctl is the SRE infrastructure control plane for secure access, inventory,
OpenStack farms and the WireGuard network.

Start here:
  vctl status           check your login and control-plane connections
  vctl list             browse the host inventory
  vctl ssh <host>       connect with a short-lived SSH certificate
  vctl openstack        explore farms, physical hosts and VMs`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// App-layer RBAC (layer 2) gate. Runs before every command; ungated
		// commands (no rbac annotation) pass through. vctl-admin bypasses.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if debugTiming {
				timing.Enable()
			}
			if err := validateOutputSelection(cmd); err != nil {
				return err
			}
			return enforceRBAC(env, cmd)
		},
	}
	// Where a command's wall clock goes. Not hidden: the answer is surprising
	// often enough — the query is rarely the slow part — that somebody
	// wondering why a listing takes half a second should be able to find out
	// without a debugger.
	root.PersistentFlags().BoolVar(&debugTiming, "debug-timing", false,
		"print where the command's time went (auth, credential, connect, query, render)")
	root.PersistentFlags().StringP("output", "o", string(outputTable),
		"output format for supported commands: table|json|yaml")

	// Only mutate/connect commands are gated (default-deny without a grant).
	// Read commands (list/status/audit/session) are ungated = allowed to any
	// authenticated user. The `vctl rbac` mutations gate themselves (classAdmin).
	root.AddGroup(
		&cobra.Group{ID: "access", Title: "Access Commands:"},
		&cobra.Group{ID: "infrastructure", Title: "Infrastructure Commands:"},
		&cobra.Group{ID: "operations", Title: "Operations Commands:"},
		&cobra.Group{ID: "administration", Title: "Administration Commands:"},
		&cobra.Group{ID: "automation", Title: "Automation Commands:"},
	)
	addCommandGroup(root, "access",
		loginCmd(env), logoutCmd(env), tokenCmd(env),
		gate(execCmd(env), "exec", classMutate),
		gate(sshCmd(env), "ssh", classMutate),
		gate(trustCACmd(env), "trust-ca", classMutate), caCmd(env), sessionCmd(env),
	)
	addCommandGroup(root, "infrastructure",
		lsCmd(env), ipCmd(env), wgCmd(env), openstackCmd(env), statusCmd(env),
	)
	addCommandGroup(root, "operations",
		gate(syncCmd(env), "sync", classMutate),
		addCmd(env), editCmd(env), deleteCmd(env), auditCmd(env), cacheCmd(env),
		gate(retentionCmd(env), "retention", classRead),
	)
	addCommandGroup(root, "administration", migrateCmd(env), rbacCmd(env))
	addCommandGroup(root, "automation",
		agentCmd(env), sessionStartCmd(env), collectCmd(env), pruneCmd(env),
		openStackPruneCmd(env), watchSessionsCmd(env), nodeAgentCmd(env), mcpCmd(env),
	)
	root.SetHelpCommandGroupID("automation")
	root.SetCompletionCommandGroupID("automation")
	return root
}

// addCommandGroup keeps the root's information architecture at the root. A
// command owns its behaviour; the control plane owns where an operator finds
// it. Callers do not need to repeat GroupID across every command constructor.
func addCommandGroup(root *cobra.Command, group string, commands ...*cobra.Command) {
	for _, command := range commands {
		command.GroupID = group
	}
	root.AddCommand(commands...)
}

func withAppFrom(newApp func() (*app.App, error), fn func(*app.App) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	return fn(a)
}

// withInventory is withStore's read-only sibling for the two commands that have
// to keep working during a database outage: it opens the inventory through the
// local snapshot fallback instead of requiring Postgres.
//
// Commands that write, or that read data with no offline meaning (audit history,
// RBAC administration), keep using withStore and keep failing loudly when the
// database is gone — which is the correct outcome for them.
func withInventoryFrom(ctx context.Context, newApp func() (*app.App, error), fn func(*app.App, *app.Inventory) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	a.OnSpoolFlush = reportSpoolFlush
	inv, err := a.OpenInventory(ctx)
	if err != nil {
		return err
	}
	defer inv.Close()
	warnIfCached(inv)
	return fn(a, inv)
}

// warnIfCached tells the operator, once per command, that what follows is a
// snapshot rather than the current inventory. Silence here would be the
// dangerous option: a decommissioned host still present in an hours-old snapshot
// looks exactly like a live one.
func warnIfCached(inv *app.Inventory) {
	if !inv.Cached() {
		return
	}
	ui.Warnf(os.Stderr, "inventory database unreachable — using the local snapshot from %s ago (run 'vctl cache status' for detail)",
		ui.CompactDuration(inv.Age(time.Now())))
}

// reportSpoolFlush surfaces the replay of access records that were queued while
// Postgres was unreachable.
func reportSpoolFlush(sent int, err error) {
	if err != nil {
		ui.Warnf(os.Stderr, "queued access records: %v", err)
		return
	}
	if sent > 0 {
		ui.Infof(os.Stderr, "flushed %d queued access record(s) to the audit log", sent)
	}
}

// withStore builds the app, opens the inventory store (rw=true for write roles),
// and runs fn with both — closing the store afterward. It collapses the
// new-app + open-store + defer-close preamble repeated by every store-backed
// command into one call.
// withStoreFrom is withPurposeStore with the app constructor left open.
//
// The MCP server needs the same open/run/close discipline but a different app:
// it must authenticate non-interactively, because a login prompt would write to
// the stdio channel that carries JSON-RPC and corrupt the protocol. That is one
// line of difference, and duplicating the preamble to express it meant the
// close-on-every-path guarantee lived in two places — the kind of thing that
// stays correct until someone fixes a leak in one copy.
func withStoreFrom(ctx context.Context, newApp func() (*app.App, error), p app.Purpose, fn func(*app.App, *store.Store) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	st, err := a.OpenStore(ctx, p)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}

// audit is the audit database, scoped to what a caller may do with it.
//
// The commands that touch audit data used to receive the whole store and pick
// their own methods out of it, which said nothing about the three separate
// credentials behind them — see internal/audit.
func (e CommandEnv) audit() (*app.App, *audit.Store, error) {
	a, err := e.newApp()
	if err != nil {
		return nil, nil, err
	}
	return a, audit.New(func(ctx context.Context, p audit.Purpose) (audit.Conn, error) {
		purpose := app.PurposeAuditRead
		if p == audit.Ingest {
			purpose = app.PurposeAuditIngest
		} else if p == audit.Prune {
			purpose = app.PurposeAuditPrune
		}
		return a.OpenStore(ctx, purpose)
	}), nil
}

// CommandEnv is what a command needs from the place it was built.
//
// It replaced a package variable that NewRoot pointed at the resolved
// Dependencies. That worked because callers build one tree at a time, which was
// true and was a convention rather than a guarantee: a second NewRoot
// overwrote the first tree's factory, and from then on whichever tree ran used
// the other's app. Nothing failed — the wrong dependency simply answered — and
// with no parallel tests in the package there was nothing to notice it.
//
// The zero value builds a real app, which is what a test constructing a tree
// only to read its shape gets. Anything that runs a command supplies one.
type CommandEnv struct {
	// NewApp builds the App this tree's commands use.
	NewApp func() (*app.App, error)
}

func (e CommandEnv) newApp() (*app.App, error) {
	if e.NewApp != nil {
		return e.NewApp()
	}
	// The zero value is what tests build a command tree with when they only
	// want its shape. Production always comes through NewRoot.
	return app.New()
}

// withApp is CommandEnv's version of the package function, for commands that
// need the app but not the store.
func (e CommandEnv) withApp(fn func(*app.App) error) error {
	return withAppFrom(e.newApp, fn)
}

// withInventory is CommandEnv's version of the package function: the store when
// it answers, the local snapshot when it does not.
func (e CommandEnv) withInventory(ctx context.Context, fn func(*app.App, *app.Inventory) error) error {
	return withInventoryFrom(ctx, e.newApp, fn)
}

// withPurposeStore opens the store for one purpose.
func (e CommandEnv) withPurposeStore(ctx context.Context, p app.Purpose, fn func(*app.App, *store.Store) error) error {
	return withStoreFrom(ctx, e.newApp, p, fn)
}

// withStore opens the inventory store for this subtree's app (rw=true for write
// roles), runs fn, and closes it.
func (e CommandEnv) withStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	p := app.PurposeInventoryRead
	if rw {
		p = app.PurposeInventoryWrite
	}
	return withStoreFrom(ctx, e.newApp, p, fn)
}
