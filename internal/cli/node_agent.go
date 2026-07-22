package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func nodeAgentCmd() *cobra.Command {
	var (
		hostname string
		interval time.Duration
		once     bool
	)
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Report lightweight host runtime status",
		Long: `node-agent reports observed host state to server_status.

It never creates inventory. The host must already exist in the servers table;
otherwise the heartbeat is ignored. Use AppRole credentials and a narrow
database role for low-risk, low-resource status reporting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, app.PurposeStatus)
			if err != nil {
				return err
			}
			defer st.Close()

			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			if hostname == "" {
				return fmt.Errorf("hostname is required")
			}

			report := func() error { return reportStatus(ctx, st, hostname) }
			return runPeriodic(ctx, once, false, interval, 5*time.Minute, report, func(err error) {
				ui.Warnf(os.Stderr, "status report failed: %v", err)
			})
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname to report; defaults to os hostname")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "heartbeat interval")
	cmd.Flags().BoolVar(&once, "once", false, "report once and exit")
	return cmd
}

// reportStatus collects host status and upserts it for an already-registered
// host. A heartbeat for an unknown host is ignored (warned), not an error.
func reportStatus(ctx context.Context, st *store.Store, hostname string) error {
	status := hoststatus.Collect(hostname, Version)
	ok, err := st.UpsertServerStatus(ctx, status)
	if err != nil {
		return err
	}
	if !ok {
		ui.Warnf(os.Stderr, "status ignored: %s is not registered in inventory", hostname)
		return nil
	}
	ui.Infof(os.Stderr, "reported status for %s", hostname)
	return nil
}
