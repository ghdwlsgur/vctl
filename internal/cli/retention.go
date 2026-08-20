package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// retentionCmd reports audit retention. It does not delete.
//
// Deleting audit records stays in-cluster behind the hidden prune automation
// command and its dedicated AppRole. No human operator credential carries DELETE;
// an off-schedule run is
// `kubectl create job --from=cronjob/vctl-audit-prune`.
//
// What was missing was not a second deletion path. It was knowing the size — a
// delete-only job returns space to the table's free list rather than the volume,
// so a burst parks the high-water mark and nothing reports it. That is what this
// command answers.
func retentionCmd(env CommandEnv) *cobra.Command {
	var (
		days        int
		sessionDays int
		accessDays  int
	)
	cmd := &cobra.Command{
		Use:   "retention",
		Short: "Report kernel audit retention and on-disk footprint",
		Long: `retention reports what audit data is past its horizon and what it costs on disk.

It never deletes. Deletion runs in-cluster from the prune CronJob with a
delete-only Vault role, so no operator credential carries DELETE on the audit
tables. To run it off schedule:

  kubectl -n vctl create job --from=cronjob/vctl-audit-prune prune-now

Horizons default to config (kernel_retention_days / session_retention_days).

  vctl retention
  vctl retention --days 30          # report against a different event horizon`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, adb, err := env.audit()
			if err != nil {
				return err
			}
			return adb.Reading(cmd.Context(), func(st audit.Reader) error {
				ctx := cmd.Context()
				if !cmd.Flags().Changed("days") {
					days = a.Cfg.KernelRetentionDays
				}
				if !cmd.Flags().Changed("session-days") {
					sessionDays = a.Cfg.SessionRetentionDays
				}
				if !cmd.Flags().Changed("access-days") {
					accessDays = a.Cfg.AccessRetentionDays
				}
				if days <= 0 {
					return fmt.Errorf("kernel retention days must be > 0 (got %d); set --days or kernel_retention_days", days)
				}

				now := time.Now()
				eventCut := now.AddDate(0, 0, -days)
				ne, err := st.CountKernelEventsBefore(ctx, eventCut)
				if err != nil {
					return err
				}
				ui.Infof(os.Stderr, "kernel_event: %d rows older than %s (%dd horizon)",
					ne, eventCut.Format("2006-01-02"), days)

				if sessionDays > 0 {
					sessionCut := now.AddDate(0, 0, -sessionDays)
					ns, err := st.CountSessionsBefore(ctx, sessionCut)
					if err != nil {
						return err
					}
					ui.Infof(os.Stderr, "audit_session: %d ended, unreferenced rows eligible before %s (%dd horizon)",
						ns, sessionCut.Format("2006-01-02"), sessionDays)
				} else {
					ui.Infof(os.Stderr, "audit_session: retention disabled (session_retention_days = 0)")
				}
				if accessDays > 0 {
					accessCut := now.AddDate(0, 0, -accessDays)
					na, err := st.CountAccessLogsBefore(ctx, accessCut)
					if err != nil {
						return err
					}
					ui.Infof(os.Stderr, "access_log: %d rows older than %s (%dd horizon)", na, accessCut.Format("2006-01-02"), accessDays)
				} else {
					ui.Infof(os.Stderr, "access_log: retention disabled (access_retention_days = 0)")
				}

				fp, err := st.AuditFootprint(ctx)
				if err != nil {
					return err
				}
				return printAuditFootprint(fp)
			})
		},
	}
	cmd.Flags().IntVar(&days, "days", 0, "kernel_event horizon in days to report against (default: config)")
	cmd.Flags().IntVar(&sessionDays, "session-days", 0, "audit_session horizon in days; 0 reports retention as disabled")
	cmd.Flags().IntVar(&accessDays, "access-days", 0, "access_log horizon in days; 0 reports retention as disabled")
	return cmd
}

// pruneCmd is the automation interface used by the in-cluster retention
// CronJob. It is hidden because human credentials intentionally cannot obtain
// the delete-only database role; operators use `vctl retention` to inspect and
// Kubernetes to trigger this job off schedule.
func pruneCmd(env CommandEnv) *cobra.Command {
	var days, sessionDays, accessDays, batchSize int
	cmd := &cobra.Command{
		Use:    "prune",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, adb, err := env.audit()
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("days") {
				days = a.Cfg.KernelRetentionDays
			}
			if !cmd.Flags().Changed("session-days") {
				sessionDays = a.Cfg.SessionRetentionDays
			}
			if !cmd.Flags().Changed("access-days") {
				accessDays = a.Cfg.AccessRetentionDays
			}
			if days <= 0 {
				return fmt.Errorf("kernel retention days must be > 0 (got %d)", days)
			}
			if sessionDays < 0 {
				return fmt.Errorf("session retention days must be >= 0 (got %d)", sessionDays)
			}
			if accessDays < 0 {
				return fmt.Errorf("access retention days must be >= 0 (got %d)", accessDays)
			}
			if accessDays > 0 && sessionDays == 0 {
				return fmt.Errorf("access logs cannot expire while sessions are retained forever")
			}
			if accessDays > 0 && sessionDays > 0 && accessDays <= sessionDays {
				return fmt.Errorf("access retention days (%d) must exceed session retention days (%d) to preserve session attribution", accessDays, sessionDays)
			}
			if batchSize <= 0 {
				return fmt.Errorf("batch size must be > 0 (got %d)", batchSize)
			}

			now := time.Now()
			cutoff := store.AuditCutoff{KernelEventsBefore: now.AddDate(0, 0, -days)}
			if sessionDays > 0 {
				sessionCutoff := now.AddDate(0, 0, -sessionDays)
				cutoff.SessionsBefore = &sessionCutoff
			}
			if accessDays > 0 {
				accessCutoff := now.AddDate(0, 0, -accessDays)
				cutoff.AccessLogsBefore = &accessCutoff
			}
			return adb.Pruning(cmd.Context(), func(st audit.Pruner) error {
				result, err := st.PruneAudit(cmd.Context(), cutoff, batchSize)
				if err != nil {
					return err
				}
				ui.Successf(os.Stdout, "pruned %d kernel event(s), %d session(s), and %d access log(s)", result.KernelEvents, result.Sessions, result.AccessLogs)
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&days, "days", 0, "kernel_event retention in days (default: config)")
	cmd.Flags().IntVar(&sessionDays, "session-days", 0, "audit_session retention in days; 0 keeps sessions")
	cmd.Flags().IntVar(&accessDays, "access-days", 0, "access_log retention in days; 0 keeps access logs")
	cmd.Flags().IntVar(&batchSize, "batch-size", 10_000, "rows deleted per transaction")
	return cmd
}

// printAuditFootprint shows the on-disk cost and flags a parked high-water mark.
// A table holding a lot of space for very few rows is the shape that went
// unnoticed, so it gets said out loud rather than left for someone to compute.
func printAuditFootprint(fp []store.TableFootprint) error {
	ui.Section(os.Stdout, "on-disk footprint")
	rows := make([][]string, 0, len(fp))
	for _, f := range fp {
		rows = append(rows, []string{f.Table, humanBytes(f.Bytes), fmt.Sprint(f.Rows), fmt.Sprint(f.Dead)})
	}
	if err := ui.Table(os.Stdout, []string{"TABLE", "SIZE", "ROWS", "DEAD"}, rows); err != nil {
		return err
	}
	for _, f := range fp {
		if f.Bytes > 1<<30 && f.Rows < 100_000 {
			ui.Warnf(os.Stderr,
				"%s holds %s for %d rows — the high-water mark is parked. Reclaiming it rewrites the table under an exclusive lock, so do it in a maintenance window: VACUUM (FULL, ANALYZE) %s;",
				f.Table, humanBytes(f.Bytes), f.Rows, f.Table)
		}
	}
	return nil
}
