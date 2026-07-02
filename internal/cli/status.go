package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check login and connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withApp(func(a *app.App) error {
				ctx := cmd.Context()
				ui.Section(os.Stdout, "vctl status")
				rows := []ui.KV{
					{Key: "Vault", Value: a.Cfg.VaultAddr},
					{Key: "Auth method", Value: a.Cfg.AuthMethod},
				}
				if a.Vault.HasValidToken() {
					rows = append(rows, ui.KV{Key: "Token", Value: fmt.Sprintf("valid · %s left", ui.CompactDuration(a.Vault.TTL())), State: ui.StateOK})
				} else {
					rows = append(rows, ui.KV{Key: "Token", Value: "missing; run 'vctl login'", State: ui.StateWarn})
					ui.KVs(os.Stdout, rows)
					return nil
				}
				ca, err := a.Vault.SSHCAPublicKey(ctx)
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
				servers, _ := st.ListWithStatus(ctx, "")
				var withAgent int
				for _, server := range servers {
					if server.Status != nil {
						withAgent++
					}
				}
				rows = append(rows, ui.KV{Key: "Inventory DB", Value: fmt.Sprintf("OK · %d hosts", len(servers)), State: ui.StateOK})
				agentState := agentCoverageState(len(servers), withAgent)
				rows = append(rows, ui.KV{
					Key:   "Node agents",
					State: agentState,
					Raw:   fmt.Sprintf("%s  %s", ui.Badge(agentState, fmt.Sprintf("%d/%d reporting", withAgent, len(servers))), ui.Bar(withAgent, len(servers), 12)),
				})
				ui.KVs(os.Stdout, rows)
				return nil
			})
		},
	}
}

func agentCoverageState(total, reporting int) ui.State {
	if total == 0 || reporting == 0 {
		return ui.StateWarn
	}
	if reporting == total {
		return ui.StateOK
	}
	return ui.StateWarn
}
