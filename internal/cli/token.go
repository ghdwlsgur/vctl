package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func tokenCmd(env CommandEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "Print a valid Vault token after renewal or re-authentication",
		Long: `Ensures a valid token and prints it to stdout.

  export VAULT_TOKEN=$(vctl token)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := env.newApp()
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
