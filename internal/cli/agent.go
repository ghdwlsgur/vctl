package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/agent"
)

func agentCmd() *cobra.Command {
	var sinks []string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "토큰을 자동 유지하는 상주 모드 (Vault Agent auto-auth + sink 대체)",
		Long: `데몬 없이 'vctl agent' 한 줄로 Vault Agent 의 핵심을 대신한다:
  · auto-auth (approle 자격 있으면 무인, 없으면 대화식 1회)
  · 만료 전 자동 renew-self, 갱신 불가 시 자동 재인증
  · 유효 토큰을 싱크 파일에 기록 → 다른 도구가 그대로 사용

  vctl agent                          # 기본 싱크(~/.vctl/token-sink)
  vctl agent --sink /run/vault-token  # 추가 싱크
  VAULT_TOKEN=$(cat ~/.vctl/token-sink) vault kv get ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := newApp()
			if err != nil {
				return err
			}
			all := append([]string{a.Cfg.SinkPath}, sinks...)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			m := &agent.Manager{App: a, Sinks: all}
			if err := m.Run(ctx); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "agent 정상 종료.")
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&sinks, "sink", nil, "추가 토큰 싱크 파일 경로 (반복 가능)")
	return cmd
}
