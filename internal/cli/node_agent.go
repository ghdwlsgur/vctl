package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/nodeagent"
)

// The daemon itself is internal/nodeagent. What is here is what a command is
// for: flags, the host's own name, and handing it a way to reach the database.
//
// The two clocks, the startup offsets, the --once ordering, the shared handle
// and its reconnect policy all used to be in this file, under a RunE. None of
// it could be exercised without building a command tree, and all of it is
// invariant somebody learned the hard way.
func nodeAgentCmd(env CommandEnv) *cobra.Command {
	agent := &nodeagent.Agent{Version: Version}
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Report lightweight host runtime status",
		Long: `node-agent reports observed host state to server_status.

It never creates inventory. The host must already exist in the servers table;
otherwise the heartbeat is ignored. Use AppRole credentials and a narrow
database role for low-risk, low-resource status reporting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := env.newApp()
			if err != nil {
				return err
			}
			if agent.Hostname == "" {
				agent.Hostname, _ = os.Hostname()
			}
			if agent.Hostname == "" {
				return fmt.Errorf("hostname is required")
			}
			// The banner's fixed lines are org identity, which is config's
			// domain — the flag only says where the file goes.
			agent.MOTDHeader = a.Cfg.MOTDHeader
			agent.MOTDManagedBy = a.Cfg.MOTDManagedBy
			agent.MOTDColor = a.Cfg.MOTDColor
			// Opened on demand and reopened after a failure, so the whole path
			// — AppRole login, then a fresh dynamic credential — runs again.
			agent.OpenSink = func(ctx context.Context) (nodeagent.Sink, error) {
				return a.OpenStore(ctx, app.PurposeStatus)
			}
			// Logging stays on the agent's defaults: sdlog, which speaks
			// journald priorities when systemd owns the stream. Injecting the
			// terminal styles here is how the daemon's warnings used to reach
			// the journal unfilterable.
			return agent.Run(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&agent.Hostname, "hostname", "", "inventory hostname to report; defaults to os hostname")
	registerCompletion(cmd, "hostname", completeInventoryHost(env))
	cmd.Flags().DurationVar(&agent.Interval, "interval", 5*time.Minute, "heartbeat interval")
	cmd.Flags().DurationVar(&agent.ProbeInterval, "probe-interval", time.Hour,
		"how often to run platform capability probes (OpenStack, ...); 0 disables them")
	cmd.Flags().BoolVar(&agent.Once, "once", false, "report once and exit")
	cmd.Flags().StringVar(&agent.MOTDPath, "motd", "",
		"keep this file rendered as a login banner from the host's OpenStack farm topology (empty disables; hosts in no farm are left untouched)")
	return cmd
}
