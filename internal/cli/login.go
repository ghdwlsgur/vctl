package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func loginCmd(env CommandEnv) *cobra.Command {
	var (
		method   string
		register bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Vault (per-person GitLab SSO by default)",
		Long: `login authenticates to Vault (oidc/userpass/approle) and caches the token.

Human logins stay per-person: the OIDC (GitLab SSO) token is what every later
command uses, so access_log / Vault audit attribute to *you*. Re-run login when
the token expires (max 8h).

--register additionally caches the configured approle (role_id + a fresh
secret_id) under ~/.vctl for non-interactive auto-auth. That approle is a SHARED
identity — once it takes over, audit attributes to the approle, not the person —
so use it only for automation/bootstrap, never for day-to-day human access.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
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
			// Register the person in seen_users so `vctl rbac assign` can offer
			// them without a prior ssh. Best-effort, human methods only —
			// approle is a shared identity and kubernetes is a workload, and
			// neither belongs in a picker of people. Done before --register
			// flips the cached token to the approle.
			if m != "approle" && m != "kubernetes" {
				if id, err := a.Vault.Identity(ctx); err == nil && id != "" {
					if st, err := a.OpenStore(ctx, app.PurposeIdentity); err == nil {
						if err := st.RecordSeenUser(ctx, id, Version); err != nil {
							ui.Warnf(os.Stderr, "rbac: could not register identity %q: %v", id, err)
						}
						st.Close()
					}
				}
			}
			if register {
				if err := a.RegisterAgent(ctx); err != nil {
					ui.Warnf(os.Stderr, "agent not registered: %v", err)
				} else if _, _, ok := a.AppRoleCreds(); ok {
					ui.Successf(os.Stderr, "agent registered (%s) — auto-auth via shared approle", a.Cfg.AppRoleSelfRole)
				}
			} else {
				ui.Successf(os.Stderr, "logged in")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "auth method: userpass | oidc | approle | kubernetes")
	cmd.Flags().BoolVar(&register, "register", false, "also cache the approle for non-interactive auto-auth (shared identity)")
	return cmd
}

func logoutCmd(env CommandEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the cached Vault token",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := env.newApp()
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
