package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/agent"
)

func execCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run a child process with VAULT_TOKEN and VAULT_ADDR",
		Long: `Runs a command with Vault environment variables injected.
vctl renews or re-authenticates the token while the child process is alive.

  vctl exec -- terraform apply
  vctl exec -- env | grep VAULT`,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("missing command: vctl exec -- <command>")
			}
			a, err := newApp()
			if err != nil {
				return err
			}
			parent := cmd.Context()
			if err := a.EnsureLogin(parent); err != nil {
				return err
			}

			// Keep the token alive while the child process runs.
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			go agent.Keepalive(ctx, a)

			child := exec.CommandContext(parent, args[0], args[1:]...)
			child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
			child.Env = append(os.Environ(),
				"VAULT_ADDR="+a.Cfg.VaultAddr,
				"VAULT_TOKEN="+a.Vault.Token(),
			)
			// Let the child process receive SIGINT.
			signal.Ignore(syscall.SIGINT)
			defer signal.Reset(syscall.SIGINT)

			if err := child.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	return cmd
}
