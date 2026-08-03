package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/syncx"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func syncCmd() *cobra.Command {
	var (
		prefix    string
		path      string
		doMigrate bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync central inventory from ~/.ssh/config and probes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}

			// Kept working, but routed through the same function `vctl migrate`
			// uses rather than a second copy. Two migrators that could drift apart
			// is exactly what the ledger exists to prevent.
			if doMigrate {
				if err := applyMigrations(ctx, a); err != nil {
					return err
				}
			}

			st, err := a.OpenStore(ctx, app.PurposeInventoryWrite)
			if err != nil {
				return err
			}
			defer st.Close()

			if path == "" {
				path = syncx.DefaultConfigPath()
			}
			blocks, err := syncx.Parse(path)
			if err != nil {
				return err
			}
			servers := syncx.BuildWithOptions(blocks, a.Cfg.SyncBuildOptions(prefix))

			var ok, up int
			for _, s := range servers {
				if err := st.Upsert(ctx, s); err != nil {
					ui.Errorf(os.Stderr, "%s: %v", s.Hostname, err)
					continue
				}
				ok++
				if s.LastSeenUp != nil {
					up++
				}
			}
			ui.Successf(os.Stderr, "sync complete: %d upserted", ok)

			// sync is the command that changes inventory, so it leaves the local
			// snapshot current instead of waiting for the refresh interval to
			// notice. Without this the operator who just added a host has the one
			// cache that does not know about it. Best-effort: a cache problem must
			// not fail a sync that already succeeded.
			if _, err := a.CaptureSnapshot(ctx, st); err != nil && !errors.Is(err, app.ErrCacheDisabled) {
				ui.Warnf(os.Stderr, "local snapshot not refreshed: %v", err)
			}
			ui.KVs(os.Stderr, []ui.KV{
				{Key: "Reachable", Value: fmt.Sprintf("%d", up), State: ui.StateOK},
				{Key: "Unreachable", Value: fmt.Sprintf("%d", ok-up), State: ui.StateWarn},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "sre", "only include ssh config aliases with this prefix")
	cmd.Flags().StringVar(&path, "config", "", "ssh config path; defaults to ~/.ssh/config")
	cmd.Flags().BoolVar(&doMigrate, "migrate", false, "run schema migrations before sync")
	// Deprecated rather than removed: it is in people's shell history and in
	// runbooks, and breaking it would make the split feel like an outage. The
	// notice points at the command that does one thing.
	_ = cmd.Flags().MarkDeprecated("migrate", "use `vctl migrate` — a schema change and an inventory refresh are separate operations")
	return cmd
}
