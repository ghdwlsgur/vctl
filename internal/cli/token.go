package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
)

func tokenCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "Print a valid Vault token after renewal or re-authentication",
		Long: `Ensures a valid token and prints it to stdout.

  export VAULT_TOKEN=$(vctl token)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := env.App()
			if err != nil {
				return err
			}
			if err := a.EnsureLogin(cmd.Context()); err != nil {
				return err
			}
			fmt.Println(a.Vault.Token())
			return nil
		},
	}
}
