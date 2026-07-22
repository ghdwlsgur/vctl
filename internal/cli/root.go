// Package cli defines the vctl Cobra command tree.
package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// Version is injected by main for --version output.
var Version = "dev"

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

// appFactory is the injection point behind the package-level newApp() that every
// command calls. NewRoot points it at the resolved Dependencies. It is package
// state (not threaded through each command) to keep the seam bounded; callers
// build one tree at a time, so it is not safe for concurrent NewRoot calls.
var appFactory = app.New

func newApp() (*app.App, error) { return appFactory() }

// Execute builds the production command tree and runs it.
func Execute() error {
	return NewRoot(Dependencies{}).Execute()
}

// NewRoot builds the vctl command tree with the given dependencies. Split out
// from Execute so tests can construct the tree — check wiring, flags, arg rules,
// help/version output — and run commands with a fake app, instead of only being
// reachable through main with a real Vault.
func NewRoot(deps Dependencies) *cobra.Command {
	appFactory = deps.withDefaults().NewApp

	root := &cobra.Command{
		Version: Version,
		Use:     "vctl",
		Short:   "CLI for direct Vault token management and SSH CA access",
		Long: `vctl manages Vault tokens without a local daemon.

Token lifecycle:
  vctl login            log in with userpass, oidc, or approle
  vctl token            print a valid token after renewal or re-auth
  vctl exec -- <cmd>    inject VAULT_TOKEN into a child process
  vctl agent            keep a token alive and write sink files

SSH CA access:
  vctl ssh <name>       resolve inventory and connect with a short-lived cert
  vctl list             list accessible inventory hosts
  vctl node-agent       report host runtime status for registered inventory
  vctl sync             sync inventory from ~/.ssh/config and probes
  vctl audit            show the central SSH access log

Secrets are not stored in inventory. Tokens are renewed before expiry, and Vault issues a short-lived SSH certificate for each connection.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// App-layer RBAC (layer 2) gate. Runs before every command; ungated
		// commands (no rbac annotation) pass through. vctl-admin bypasses.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return enforceRBAC(cmd)
		},
	}
	// Only mutate/connect commands are gated (default-deny without a grant).
	// Read commands (list/status/audit/session) are ungated = allowed to any
	// authenticated user. The `vctl rbac` mutations gate themselves (classAdmin).
	root.AddCommand(
		loginCmd(), logoutCmd(), tokenCmd(),
		gate(execCmd(), "exec", classMutate), agentCmd(),
		gate(sshCmd(), "ssh", classMutate),
		lsCmd(),
		gate(syncCmd(), "sync", classMutate),
		statusCmd(), auditCmd(),
		gate(trustCACmd(), "trust-ca", classMutate), caCmd(),
		sessionCmd(), sessionStartCmd(), collectCmd(),
		gate(pruneCmd(), "prune", classMutate),
		watchSessionsCmd(), nodeAgentCmd(),
		rbacCmd(), mcpCmd(),
	)
	return root
}

// withApp builds the app and runs fn with it — for commands that need the app
// (Vault/config) but not the inventory store, or that open the store themselves
// with bespoke error handling (e.g. status).
func withApp(fn func(*app.App) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	return fn(a)
}

// withStore builds the app, opens the inventory store (rw=true for write roles),
// and runs fn with both — closing the store afterward. It collapses the
// new-app + open-store + defer-close preamble repeated by every store-backed
// command into one call.
func withStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	p := app.PurposeInventoryRead
	if rw {
		p = app.PurposeInventoryWrite
	}
	return withPurposeStore(ctx, p, fn)
}

// withPurposeStore builds the app, opens the store for one purpose, runs fn, and
// closes it afterward — the shared preamble for every store-backed command.
func withPurposeStore(ctx context.Context, p app.Purpose, fn func(*app.App, *store.Store) error) error {
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

func withAuditStore(ctx context.Context, fn func(*app.App, *store.Store) error) error {
	return withPurposeStore(ctx, app.PurposeAuditRead, fn)
}

func withAuditIngestStore(ctx context.Context, fn func(*app.App, *store.Store) error) error {
	return withPurposeStore(ctx, app.PurposeAuditIngest, fn)
}
