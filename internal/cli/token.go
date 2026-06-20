package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func tokenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "유효한 Vault 토큰을 출력 (필요 시 자동 갱신/재인증)",
		Long: `유효 토큰을 보장한 뒤 표준출력으로 인쇄한다.

  export VAULT_TOKEN=$(vctl token)   # 기존 vault CLI 와 연동`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			if err := a.EnsureLogin(cmd.Context()); err != nil {
				return err
			}
			fmt.Println(a.Vault.Token())
			return nil
		},
	}
}
