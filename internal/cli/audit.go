package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func auditCmd() *cobra.Command {
	var (
		host     string
		user     string
		sourceIP string
		limit    int
		detail   bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show central SSH access log (who connected to what, via vctl)",
		Long: `audit reads the central access_log table that vctl writes on every
'vctl ssh': vault identity, target host, Vault-issued cert serial, time, and
whether the session connected.

This is the inventory-level audit. The authoritative record of every signing
request lives in the Vault file audit device on the Vault pod
(/vault/audit/vault_audit.log) - use it for forensic / tamper-evident review.`,
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

			entries, err := st.AccessLog(ctx, limit, host, user, sourceIP)
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
				row := []string{
					e.SignedAt.Local().Format("2006-01-02 15:04:05"),
					valueOrDash(e.VaultUser),
					e.Hostname,
					valueOrDash(e.SourceIP),
					valueOrDash(e.ClientUser),
					valueOrDash(e.TargetAddr),
					valueOrDash(e.JumpVia),
					result,
				}
				if detail {
					row = append(row, valueOrDash(e.ClientHost), valueOrDash(e.SourceAddr), valueOrDash(e.CertSerial), valueOrDash(e.Error))
				}
				rows = append(rows, row)
			}
			ui.Section(os.Stdout, "access log")
			headers := []string{"time", "vault user", "host", "source ip", "client user", "target", "jump", "result"}
			if detail {
				headers = append(headers, "client host", "source addr", "serial", "error")
			}
			return ui.Table(os.Stdout, headers, rows)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "filter by hostname substring")
	cmd.Flags().StringVar(&user, "user", "", "filter by vault user substring")
	cmd.Flags().StringVar(&sourceIP, "source-ip", "", "filter by exact source IP")
	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "max rows to show")
	cmd.Flags().BoolVar(&detail, "detail", false, "show client host, source address, cert serial, and error")
	return cmd
}

func valueOrDash(s string) string {
	if s == "" {
		return ui.Muted("-")
	}
	return s
}
