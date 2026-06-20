package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func loginCmd() *cobra.Command {
	var method string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Vault 에 로그인 (토큰을 ~/.vctl/token 에 캐시)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			m := method
			if m == "" {
				m = a.Cfg.AuthMethod
			}
			return a.Login(cmd.Context(), m)
		},
	}
	cmd.Flags().StringVar(&method, "method", "", "인증 방식: userpass | oidc (기본: 설정값)")
	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "캐시된 Vault 토큰 폐기",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			if err := a.Vault.Logout(); err != nil {
				return err
			}
			fmt.Println("로그아웃 완료.")
			return nil
		},
	}
}
