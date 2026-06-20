package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
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
			ui.Section(os.Stdout, "vctl status")
			rows := []ui.KV{
				{Key: "Vault", Value: a.Cfg.VaultAddr},
				{Key: "Auth method", Value: a.Cfg.AuthMethod},
			}
			if a.Vault.HasValidToken() {
				rows = append(rows, ui.KV{Key: "Token", Value: "valid (cached)", State: ui.StateOK})
			} else {
				rows = append(rows, ui.KV{Key: "Token", Value: "missing; run 'vctl login'", State: ui.StateWarn})
				ui.KVs(os.Stdout, rows)
				return nil
			}
			ca, err := a.Vault.CAPublicKey(ctx)
			if err != nil {
				rows = append(rows, ui.KV{Key: "SSH CA", Value: "read failed (" + err.Error() + ")", State: ui.StateFail})
			} else {
				rows = append(rows, ui.KV{Key: "SSH CA", Value: fmt.Sprintf("OK (%.40s...)", ca), State: ui.StateOK})
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				rows = append(rows, ui.KV{Key: "Inventory DB", Value: "connection failed (" + err.Error() + ")", State: ui.StateFail})
				ui.KVs(os.Stdout, rows)
				return nil
			}
			defer st.Close()
			servers, _ := st.List(ctx, "")
			rows = append(rows, ui.KV{Key: "Inventory DB", Value: fmt.Sprintf("OK (%d hosts)", len(servers)), State: ui.StateOK})
			ui.KVs(os.Stdout, rows)
			return nil
		},
	}
}
