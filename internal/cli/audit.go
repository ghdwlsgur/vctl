package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func auditCmd() *cobra.Command {
	var (
		host  string
		user  string
		limit int
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show central SSH access log (who connected to what, via vctl)",
		Long: `audit reads the central access_log table that vctl writes on every
'vctl ssh': vault identity, target host, Vault-issued cert serial, time, and
whether the session connected.

This is the inventory-level audit. The authoritative record of every signing
request lives in the Vault file audit device on the Vault pod
(/vault/audit/vault_audit.log) — use it for forensic / tamper-evident review.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				return err
			}
			defer st.Close()

			entries, err := st.AccessLog(ctx, limit, host, user)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				ui.Warnf(os.Stderr, "no access records yet")
				return nil
			}
			rows := make([][]string, 0, len(entries))
			for _, e := range entries {
				result := ui.Fail("fail")
				if e.OK {
					result = ui.OK("ok")
				}
				vu := e.VaultUser
				if vu == "" {
					vu = ui.Muted("-")
				}
				serial := e.CertSerial
				if serial == "" {
					serial = ui.Muted("-")
				}
				rows = append(rows, []string{e.SignedAt.Local().Format("2006-01-02 15:04:05"), vu, e.Hostname, serial, result})
			}
			ui.Section(os.Stdout, "access log")
			return ui.Table(os.Stdout, []string{"time", "vault user", "host", "serial", "result"}, rows)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "filter by hostname substring")
	cmd.Flags().StringVar(&user, "user", "", "filter by vault user substring")
	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "max rows to show")
	return cmd
}
