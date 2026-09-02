// Package cli defines the vctl Cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/cli/openstack"
	"github.com/ghdwlsgur/vctl/internal/timing"
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
// The context carries interrupt handling. Without it, ^C killed the process
// wherever it happened to be — nothing cancelled a query stuck behind a lock
// or a Vault round trip against a wedged server, and cobra handed commands a
// context nothing could cancel. Now the first signal cancels in-flight work
// through cmd.Context(); the goroutine below then restores the default
// disposition, so a second ^C kills a command stuck in cleanup instead of
// being swallowed. Commands that manage signals themselves keep doing so:
// exec ignores SIGINT while the remote command runs (Ignore also unregisters
// this handler), and the agent daemon installs its own shutdown context.
//
// The timing report is printed here rather than in a post-run hook because a
// command that failed is exactly the one worth measuring, and PersistentPostRun
// does not run for those.
func Execute() error {
	return run(NewRoot(Dependencies{}))
}

// run executes a built tree under the interrupt handling both binaries share.
func run(root *cobra.Command) error {
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	err := root.ExecuteContext(ctx)
	timing.Report(os.Stderr)
	if err != nil && ctx.Err() != nil && errors.Is(err, context.Canceled) {
		// The operator interrupted; the cancellation is the message, and
		// "context canceled" would report the mechanism instead.
		return fmt.Errorf("interrupted")
	}
	return err
}

// NewRoot builds the vctl command tree with the given dependencies. Split out
// from Execute so tests can construct the tree — check wiring, flags, arg rules,
// help/version output — and run commands with a fake app, instead of only being
// reachable through main with a real Vault.
func NewRoot(deps Dependencies) *cobra.Command {
	env := cmdkit.Env{NewApp: deps.withDefaults().NewApp}

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
  vctl openstack        explore farms, physical hosts and VMs
  vctl kv search <word> find where a credential lives in Vault`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// App-layer RBAC (layer 2) gate. Runs before every command; ungated
		// commands (no rbac annotation) pass through. vctl-admin bypasses.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if debugTiming {
				timing.Enable()
			}
			if err := cmdkit.ValidateOutputSelection(cmd); err != nil {
				return err
			}
			return cmdkit.EnforceRBAC(env, cmd)
		},
	}
	// Where a command's wall clock goes. Not hidden: the answer is surprising
	// often enough — the query is rarely the slow part — that somebody
	// wondering why a listing takes half a second should be able to find out
	// without a debugger.
	root.PersistentFlags().BoolVar(&debugTiming, "debug-timing", false,
		"print where the command's time went (auth, credential, connect, query, render)")
	root.PersistentFlags().StringP("output", "o", string(cmdkit.OutputTable),
		"output format for supported commands: table|json|yaml")

	// Mutate/connect commands are gated (default-deny without a grant); the
	// gate's class comes from the authz catalog, which is the one list `vctl
	// rbac grant` validates against. Ungated commands (list/status/audit/
	// session) are allowed to any authenticated user. The `vctl rbac`
	// mutations gate themselves as admin-only.
	root.AddGroup(
		&cobra.Group{ID: "access", Title: "Access Commands:"},
		&cobra.Group{ID: "infrastructure", Title: "Infrastructure Commands:"},
		&cobra.Group{ID: "operations", Title: "Operations Commands:"},
		&cobra.Group{ID: "administration", Title: "Administration Commands:"},
		&cobra.Group{ID: "automation", Title: "Automation Commands:"},
	)
	addCommandGroup(root, "access",
		loginCmd(env), logoutCmd(env), tokenCmd(env), kvCmd(env),
		cmdkit.Gate(execCmd(env), "exec"),
		cmdkit.Gate(sshCmd(env), "ssh"),
		cmdkit.Gate(injectCmd(env), "inject"), cmdkit.Gate(installCmd(env), "install"), caCmd(env), sessionCmd(env),
	)
	addCommandGroup(root, "infrastructure",
		lsCmd(env), ipCmd(env), wgCmd(env), openstack.Cmd(env), statusCmd(env), logCmd(env),
	)
	addCommandGroup(root, "operations",
		cmdkit.Gate(syncCmd(env), "sync"),
		addCmd(env), editCmd(env), deleteCmd(env), auditCmd(env), cacheCmd(env),
		cmdkit.Gate(retentionCmd(env), "retention"),
	)
	addCommandGroup(root, "administration", migrateCmd(env), rbacCmd(env))
	addCommandGroup(root, "automation",
		agentCmd(env), sessionStartCmd(env), collectCmd(env), pruneCmd(env),
		openstack.PruneCmd(env), watchSessionsCmd(env), nodeAgentCmd(env), mcpCmd(env),
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
