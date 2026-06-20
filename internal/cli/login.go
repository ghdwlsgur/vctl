package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func loginCmd() *cobra.Command {
	var method string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Vault and cache the token in ~/.vctl/token",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			m := method
			if m == "" {
				m = a.Cfg.AuthMethod
			}
			return a.Login(cmd.Context(), m)
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "auth method: userpass | oidc | approle")
	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the cached Vault token",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			if err := a.Vault.Logout(); err != nil {
				return err
			}
			ui.Successf(os.Stdout, "logged out")
			return nil
		},
	}
}
