package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check login and connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			fmt.Printf("Vault      : %s\n", a.Cfg.VaultAddr)
			fmt.Printf("Auth method : %s\n", a.Cfg.AuthMethod)
			if a.Vault.HasValidToken() {
				fmt.Println("Token       : valid (cached)")
			} else {
				fmt.Println("Token       : missing; run 'vctl login'")
				return nil
			}
			ca, err := a.Vault.CAPublicKey(ctx)
			if err != nil {
				fmt.Printf("SSH CA      : read failed (%v)\n", err)
			} else {
				fmt.Printf("SSH CA     : OK (%.40s...)\n", ca)
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				fmt.Printf("Inventory DB: connection failed (%v)\n", err)
				return nil
			}
			defer st.Close()
			servers, _ := st.List(ctx, "")
			fmt.Printf("Inventory DB: OK (%d hosts)\n", len(servers))
			return nil
		},
	}
}
