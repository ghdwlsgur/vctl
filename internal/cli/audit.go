package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// auditCmd wires the audit filters; the body is runAudit.
func auditCmd(env cmdkit.Env) *cobra.Command {
	var opts auditOptions
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show central SSH access log (who connected to what, via vctl)",
		Long: `audit reads the central access_log table that vctl writes on every
'vctl ssh': vault identity, target host, Vault-issued cert serial, time, and
whether the session connected.

This is the inventory-level audit. The authoritative record of every signing
request lives in the Vault file audit device on the Vault pod
(/vault/audit/vault_audit.log) - use it for forensic / tamper-evident review.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAudit(cmd, env, opts)
		},
	}
	cmd.Flags().StringVar(&opts.host, "host", "", "filter by hostname substring")
	cmdkit.RegisterCompletion(cmd, "host", cmdkit.CompleteInventoryHost(env))
	cmd.Flags().StringVar(&opts.user, "user", "", "filter by vault user substring")
	cmd.Flags().StringVar(&opts.sourceIP, "source-ip", "", "filter by exact source IP")
	cmd.Flags().IntVarP(&opts.limit, "limit", "n", 50, "max rows to show")
	cmd.Flags().BoolVar(&opts.detail, "detail", false, "show client host, source address, cert serial, and error")
	return cmd
}

type auditOptions struct {
	host     string
	user     string
	sourceIP string
	limit    int
	detail   bool
}

// runAudit reads the central access_log and prints it as a table, filtered
// by the given options.
func runAudit(cmd *cobra.Command, env cmdkit.Env, opts auditOptions) error {
	_, adb, err := env.Audit()
	if err != nil {
		return err
	}
	return adb.Reading(cmd.Context(), func(st audit.Reader) error {
		entries, err := st.AccessLog(cmd.Context(), opts.limit, opts.host, opts.user, opts.sourceIP)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			ui.Warnf(os.Stderr, "no access records yet")
			return nil
		}
		rows := make([][]string, 0, len(entries))
		for _, e := range entries {
			result := ui.Dot(ui.StateFail) + " fail"
			if e.OK {
				result = ui.Dot(ui.StateOK) + " ok"
			}
			row := []string{
				e.SignedAt.Local().Format(ui.TimeLayout) + " " + ui.Ago(e.SignedAt),
				ui.OrDash(e.VaultUser),
				e.Hostname,
				ui.OrDash(e.SourceIP),
				ui.OrDash(e.ClientUser),
				ui.OrDash(e.TargetAddr),
				ui.OrDash(e.JumpVia),
				result,
			}
			if opts.detail {
				row = append(row, ui.OrDash(e.ClientHost), ui.OrDash(e.SourceAddr), ui.OrDash(e.CertSerial), ui.OrDash(e.Error))
			}
			rows = append(rows, row)
		}
		ui.Section(os.Stdout, "access log")
		headers := []string{"time", "vault user", "host", "source ip", "client user", "target", "jump", "result"}
		if opts.detail {
			headers = append(headers, "client host", "source addr", "serial", "error")
		}
		return ui.Table(os.Stdout, headers, rows)
	})
}
