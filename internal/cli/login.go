package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func loginCmd() *cobra.Command {
	var (
		method     string
		noRegister bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Vault and register the approle agent for future auto-auth",
		Long: `login authenticates to Vault (userpass/oidc/approle) and caches the token.

By default it then "registers the agent": fetches the configured approle's
role_id and a fresh secret_id and stores them under ~/.vctl, so subsequent
commands re-authenticate automatically without prompting. Use --no-register to
skip (e.g. logging in as approle already, or without secret-id permission).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			m := method
			if m == "" {
				m = a.Cfg.AuthMethod
			}
			if err := a.Login(ctx, m); err != nil {
				return err
			}
			if !noRegister {
				if err := a.RegisterAgent(ctx); err != nil {
					ui.Warnf(os.Stderr, "agent not registered (will prompt again next time): %v", err)
				} else if _, _, ok := a.AppRoleCreds(); ok {
					ui.Successf(os.Stderr, "agent registered (%s) — future logins are automatic", a.Cfg.AppRoleSelfRole)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "auth method: userpass | oidc | approle")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "skip approle agent registration")
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
