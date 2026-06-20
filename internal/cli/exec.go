package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/agent"
)

func execCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "VAULT_TOKEN/VAULT_ADDR 를 주입해 자식 프로세스 실행 (실행 동안 토큰 자동 유지)",
		Long: `Vault Agent 의 'exec' 처럼, 토큰을 환경변수로 주입한 채 명령을 실행한다.
자식이 사는 동안 백그라운드로 토큰을 갱신/재인증해 끊기지 않게 한다.

  vctl exec -- terraform apply
  vctl exec -- env | grep VAULT`,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("실행할 명령이 필요합니다: vctl exec -- <command>")
			}
			a, err := newApp()
			if err != nil {
				return err
			}
			parent := cmd.Context()
			if err := a.EnsureLogin(parent); err != nil {
				return err
			}

			// 자식 수명 동안 토큰 keepalive
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			go agent.Keepalive(ctx, a)

			child := exec.CommandContext(parent, args[0], args[1:]...)
			child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
			child.Env = append(os.Environ(),
				"VAULT_ADDR="+a.Cfg.VaultAddr,
				"VAULT_TOKEN="+a.Vault.Token(),
			)
			// 시그널은 자식이 받도록 전파
			signal.Ignore(syscall.SIGINT)
			defer signal.Reset(syscall.SIGINT)

			if err := child.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	return cmd
}
