package cli

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/agent"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func agentCmd() *cobra.Command {
	var sinks []string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Keep a Vault token alive and write sink files",
		Long: `vctl agent provides the core Vault Agent behavior without a daemon:
  - auto-auth with AppRole when available
  - renew-self before expiry
  - re-authenticate when renewal is no longer possible
  - write valid tokens to sink files for other tools

  vctl agent
  vctl agent --sink /run/vault-token
  VAULT_TOKEN=$(cat ~/.vctl/token-sink) vault kv get ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			all := append([]string{a.Cfg.SinkPath}, sinks...)

			ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
			defer stop()

			m := &agent.Manager{App: a, Sinks: all}
			if err := m.Run(ctx); err != nil {
				return err
			}
			ui.Successf(os.Stderr, "agent stopped cleanly")
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&sinks, "sink", nil, "additional token sink path; repeatable")
	return cmd
}
