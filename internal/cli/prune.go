package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func pruneCmd() *cobra.Command {
	var (
		days        int
		sessionDays int
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete kernel audit data past its retention horizon",
		Long: `prune enforces kernel-audit retention. Raw kernel_event rows are high-volume
and pruned on a short horizon; sessions are small metadata kept far longer as
the dataset index.

Defaults come from config (kernel_retention_days / session_retention_days).
Run from a CronJob. Use --dry-run to preview counts.

  vctl prune --dry-run
  vctl prune                       # apply config retention
  vctl prune --days 30             # override kernel_event horizon
  vctl prune --session-days 0      # also keep sessions forever (0 = skip)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("days") {
				days = a.Cfg.KernelRetentionDays
			}
			if !cmd.Flags().Changed("session-days") {
				sessionDays = a.Cfg.SessionRetentionDays
			}
			if days <= 0 {
				return fmt.Errorf("kernel retention days must be > 0 (got %d); set --days or kernel_retention_days", days)
			}

			st, err := a.OpenStore(ctx, !dryRun) // RW to delete; RO suffices for dry-run
			if err != nil {
				return err
			}
			defer st.Close()

			now := time.Now()
			eventCut := now.AddDate(0, 0, -days)

			if dryRun {
				n, err := st.CountKernelEventsBefore(ctx, eventCut)
				if err != nil {
					return err
				}
				ui.Infof(os.Stderr, "[dry-run] %d kernel_event rows older than %s (%dd) would be deleted",
					n, eventCut.Format("2006-01-02"), days)
				if sessionDays > 0 {
					ui.Infof(os.Stderr, "[dry-run] sessions older than %dd would also be pruned", sessionDays)
				}
				return nil
			}

			ne, err := st.PruneKernelEvents(ctx, eventCut)
			if err != nil {
				return err
			}
			ui.Successf(os.Stderr, "pruned %d kernel_event rows older than %dd", ne, days)

			if sessionDays > 0 {
				ns, err := st.PruneSessions(ctx, now.AddDate(0, 0, -sessionDays))
				if err != nil {
					return err
				}
				ui.Successf(os.Stderr, "pruned %d audit_session rows older than %dd", ns, sessionDays)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", 0, "kernel_event retention in days (default: config)")
	cmd.Flags().IntVar(&sessionDays, "session-days", 0, "audit_session retention in days; 0 keeps sessions")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report counts without deleting")
	return cmd
}
