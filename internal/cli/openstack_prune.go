package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func openStackPruneCmd(env CommandEnv) *cobra.Command {
	var days, batchSize int
	cmd := &cobra.Command{
		Use:    "openstack-prune-missing",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.withPurposeStore(cmd.Context(), app.PurposeOpenStackPrune, func(a *app.App, st *store.Store) error {
				if !cmd.Flags().Changed("days") {
					days = a.Cfg.OpenStackMissingRetentionDays
				}
				if days <= 0 || batchSize <= 0 {
					return fmt.Errorf("retention days and batch size must be > 0")
				}
				n, err := st.PruneMissingOpenStackInstances(cmd.Context(), time.Now().AddDate(0, 0, -days), batchSize)
				if err != nil {
					return err
				}
				ui.Successf(os.Stdout, "pruned %d missing OpenStack instance record(s)", n)
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&days, "days", 0, "missing-instance retention in days (default: config)")
	cmd.Flags().IntVar(&batchSize, "batch-size", 5_000, "rows deleted per transaction")
	return cmd
}
