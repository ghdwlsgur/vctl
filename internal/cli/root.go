// Package cli 는 vctl 의 cobra 명령 트리를 정의한다.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// Version 은 main 에서 주입한다(--version 표시용).
var Version = "dev"

// Execute 는 루트 명령을 실행한다(main 에서 호출).
func Execute() error {
	root := &cobra.Command{
		Version: Version,
		Use:     "vctl",
		Short:   "Vault Agent 없이 Vault 토큰을 직접 관리하는 CLI (+ SSH CA 접속)",
		Long: `vctl — 별도 데몬 없이 "에이전트처럼" Vault 토큰을 다룬다.

토큰 수명 관리 (Vault Agent 대체):
  vctl login            Vault 로그인 (userpass | oidc | approle)
  vctl token            유효 토큰 출력 (자동 갱신/재인증)  →  export VAULT_TOKEN=$(vctl token)
  vctl exec -- <cmd>    VAULT_TOKEN 주입해 자식 실행 (실행 동안 토큰 자동 유지)
  vctl agent            상주 모드 — 자동 갱신 + 토큰 싱크 파일 기록

서버 접속 (SSH CA):
  vctl ssh <이름>        중앙 인벤토리에서 찾아 단명 cert 로 접속
  vctl list             접속 가능한 서버 목록
  vctl sync             ~/.ssh/config + 프로브로 인벤토리 갱신(관리자)

비밀은 어디에도 저장되지 않습니다. 토큰은 만료 전 자동 갱신되고, 접속마다 Vault 가 단명 인증서를 발급합니다.`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		loginCmd(), logoutCmd(), tokenCmd(), execCmd(), agentCmd(),
		sshCmd(), lsCmd(), syncCmd(), statusCmd(),
	)
	return root.Execute()
}

func newApp() (*app.App, error) {
	return app.New()
}
