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

// Execute runs the root command.
func Execute() error {
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
	}
	root.AddCommand(
		loginCmd(), logoutCmd(), tokenCmd(), execCmd(), agentCmd(),
		sshCmd(), lsCmd(), syncCmd(), statusCmd(), auditCmd(), trustCACmd(), caCmd(),
		sessionCmd(), sessionStartCmd(), collectCmd(), pruneCmd(), watchSessionsCmd(), nodeAgentCmd(),
	)
	return root.Execute()
}

func newApp() (*app.App, error) {
	return app.New()
}

// withStore builds the app, opens the inventory store (rw=true for write roles),
// and runs fn with both — closing the store afterward. It collapses the
// new-app + open-store + defer-close preamble repeated by every store-backed
// command into one call.
func withStore(ctx context.Context, rw bool, fn func(*app.App, *store.Store) error) error {
	a, err := newApp()
	if err != nil {
		return err
	}
	st, err := a.OpenStore(ctx, rw)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(a, st)
}
