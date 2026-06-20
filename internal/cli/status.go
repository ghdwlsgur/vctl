package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "로그인·연결 상태 점검",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			fmt.Printf("Vault      : %s\n", a.Cfg.VaultAddr)
			fmt.Printf("인증 방식  : %s\n", a.Cfg.AuthMethod)
			if a.Vault.HasValidToken() {
				fmt.Println("토큰       : 유효 (캐시됨)")
			} else {
				fmt.Println("토큰       : 없음 — 'vctl login' 필요")
				return nil
			}
			ca, err := a.Vault.CAPublicKey(ctx)
			if err != nil {
				fmt.Printf("SSH CA     : 읽기 실패 (%v)\n", err)
			} else {
				fmt.Printf("SSH CA     : OK (%.40s...)\n", ca)
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				fmt.Printf("인벤토리DB : 연결 실패 (%v)\n", err)
				return nil
			}
			defer st.Close()
			servers, _ := st.List(ctx, "")
			fmt.Printf("인벤토리DB : OK (%d대 등록)\n", len(servers))
			return nil
		},
	}
}
