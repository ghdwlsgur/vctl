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
// It used to be `vctl prune` and it used to try to delete, through a
// database/creds/vctl-pruner credential. That never worked: no Vault policy grants
// that path, so the command could not authenticate — and app-layer RBAC refused it
// one step earlier anyway, even with --dry-run. Meanwhile the READMEs said
// "retention is enforced by vctl prune (a CronJob)", which was not true either:
// the CronJob runs SQL directly as the table owner and does not involve vctl at
// all. A command nobody could run, described by docs that named the wrong
// mechanism.
//
// Deleting audit records stays where it already is — in-cluster, as the table
// owner, over the pod-local socket. That job needs no credential distribution and
// no network path, and it keeps DELETE on audit tables out of every credential an
// operator carries. Giving the CLI a second way to do the same thing would widen
// that for no operational gain: an off-schedule run is
// `kubectl create job --from=cronjob/vctl-kernel-event-prune`.
//
// What was missing was not a second deletion path. It was knowing the size — a
// delete-only job returns space to the table's free list rather than the volume,
// so a burst parks the high-water mark and nothing reports it. That is what this
// command answers.
func retentionCmd(env CommandEnv) *cobra.Command {
	var (
		days        int
		sessionDays int
	)
	cmd := &cobra.Command{
		Use:   "retention",
		Short: "Report kernel audit retention and on-disk footprint",
		Long: `retention reports what audit data is past its horizon and what it costs on disk.

It never deletes. Deletion runs in-cluster from the prune CronJob, as the table
owner over the pod-local socket, so no operator credential carries DELETE on the
audit tables. To run it off schedule:

  kubectl -n vctl create job --from=cronjob/vctl-kernel-event-prune prune-now

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
					ui.Infof(os.Stderr, "audit_session: %d rows older than %s (%dd horizon)",
						ns, sessionCut.Format("2006-01-02"), sessionDays)
				} else {
					ui.Infof(os.Stderr, "audit_session: retention disabled (session_retention_days = 0)")
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
