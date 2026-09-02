package cli

import (
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/cli/openstack"
	"github.com/ghdwlsgur/vctl/internal/timing"
)

// ExecuteAgent builds the fleet-host command tree and runs it, under the same
// interrupt handling Execute installs.
func ExecuteAgent() error {
	return run(NewAgentRoot(Dependencies{}))
}

// NewAgentRoot builds the tree vctl-agent ships: the daemons and hooks a
// fleet host runs, and nothing an operator would.
//
// The full CLI used to be the only binary, so installing the status agent put
// ssh, list and edit on every server. None of them worked there — the host
// AppRole can only mint status and audit-ingest credentials, and the operator
// commands need a person's login — but least functionality is its own
// requirement: a security review should not have to re-derive the Vault
// policy to conclude the fleet cannot ssh itself.
//
// The command paths match the main binary's (`vctl-agent openstack
// reconcile`), so the systemd units differ from the mono-binary era only in
// which binary they name.
func NewAgentRoot(deps Dependencies) *cobra.Command {
	env := cmdkit.Env{NewApp: deps.withDefaults().NewApp}

	root := &cobra.Command{
		Version: Version,
		Use:     "vctl-agent",
		Short:   "vctl fleet host agent (status, kernel audit, farm reconcile)",
		Long: `vctl-agent is the host-side slice of vctl: the daemons a fleet machine
runs under systemd, without the operator commands.

  vctl-agent node-agent           report runtime status to server_status
  vctl-agent collect              ingest Tetragon kernel events
  vctl-agent watch-sessions       register SSH sessions from PAM markers
  vctl-agent openstack reconcile  confirm farm membership (farm controllers)`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// No RBAC hook, on purpose: nothing in this tree is gated. The agents
		// are authorized by the host AppRole's Vault policy, not by
		// per-person grants — and TestAgentTreeCarriesNoGates is what keeps a
		// gated command from being added here where nothing would enforce it.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if debugTiming {
				timing.Enable()
			}
			return cmdkit.ValidateOutputSelection(cmd)
		},
	}
	root.PersistentFlags().BoolVar(&debugTiming, "debug-timing", false,
		"print where the command's time went (auth, credential, connect, query, render)")
	root.PersistentFlags().StringP("output", "o", string(cmdkit.OutputTable),
		"output format for supported commands: table|json|yaml")

	// The reconcile keeps its `openstack` parent so the unit's command line is
	// the same words on either binary.
	openstackParent := &cobra.Command{
		Use:   "openstack",
		Short: "Farm control-plane tasks a controller host runs",
	}
	openstackParent.AddCommand(openstack.ReconcileCmd(env))

	root.AddCommand(
		nodeAgentCmd(env),
		collectCmd(env),
		watchSessionsCmd(env),
		sessionStartCmd(env),
		openstackParent,
	)
	return root
}
