package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/syncx"
)

func syncCmd() *cobra.Command {
	var (
		prefix    string
		path      string
		doMigrate bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "~/.ssh/config + 프로브로 중앙 인벤토리 갱신 (관리자, 쓰기 자격 필요)",
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
				fmt.Fprintln(os.Stderr, "스키마 마이그레이션 완료.")
			}

			st, err := a.OpenStore(ctx, true) // 쓰기 role
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
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", s.Hostname, err)
					continue
				}
				ok++
				if s.LastSeenUp != nil {
					up++
				}
			}
			fmt.Fprintf(os.Stderr, "동기화 완료: %d대 upsert (도달 %d / 미도달 %d)\n", ok, up, ok-up)
			return nil
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "sre", "이 prefix 로 시작하는 ssh config alias 만 대상")
	cmd.Flags().StringVar(&path, "config", "", "ssh config 경로 (기본: ~/.ssh/config)")
	cmd.Flags().BoolVar(&doMigrate, "migrate", false, "실행 전 스키마 마이그레이션 수행")
	return cmd
}
