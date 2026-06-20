package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

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

			if doMigrate {
				mst, err := a.OpenStoreRole(ctx, a.Cfg.DBRoleMigrate)
				if err != nil {
					return err
				}
				if err := mst.MigrateAsOwner(ctx, a.Cfg.DBMigrationOwner); err != nil {
					mst.Close()
					return err
				}
				mst.Close()
				ui.Successf(os.Stderr, "schema migration complete")
			}

			st, err := a.OpenStore(ctx, true) // write role
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
	return cmd
}
