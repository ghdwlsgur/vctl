package cli

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
)

func sshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh [host]",
		Short: "서버에 접속 (이름 일부만 알아도, 몰라도 OK)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				return err
			}
			defer st.Close()

			target, err := pick(ctx, st, args)
			if err != nil {
				return err
			}

			tgt, err := buildTarget(ctx, st, target)
			if err != nil {
				return err
			}

			sign := func(role, pub string, principals []string) (string, error) {
				return a.Vault.SignSSH(ctx, role, pub, principals, a.Cfg.SSHSign)
			}

			fmt.Fprintf(os.Stderr, "→ %s (%s@%s) 접속 중...\n", tgt.Name, tgt.User, tgt.Addr)
			return sshc.Connect(ctx, tgt, sign)
		},
	}
}

// pick 은 인자/퍼지매칭/인터랙티브 피커로 서버 1대를 고른다.
func pick(ctx context.Context, st *store.Store, args []string) (*store.Server, error) {
	if len(args) == 1 {
		sv, cands, err := st.Resolve(ctx, args[0])
		if err != nil {
			return nil, err
		}
		if sv != nil {
			return sv, nil
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("%q 와 일치하는 서버가 없습니다", args[0])
		}
		return chooseFrom(cands)
	}
	// 인자 없음 → 전체 목록에서 고르기
	all, err := st.List(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("인벤토리가 비어 있습니다. 먼저 'vctl sync' 를 실행하세요")
	}
	return chooseFrom(all)
}

func chooseFrom(cands []store.Server) (*store.Server, error) {
	fmt.Fprintln(os.Stderr, "여러 서버가 매칭됩니다 — 번호를 고르세요:")
	for i, c := range cands {
		up := "·"
		if c.LastSeenUp != nil {
			up = "up"
		}
		fmt.Fprintf(os.Stderr, "  %2d) %-28s %-16s %-12s [%s]\n", i+1, c.Hostname, c.IP, c.DC, up)
	}
	fmt.Fprint(os.Stderr, "번호: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("잘못된 선택")
	}
	return &cands[n-1], nil
}

// buildTarget 은 서버와 점프 체인을 sshc.Target 으로 변환한다(점프는 재귀 조회).
func buildTarget(ctx context.Context, st *store.Store, sv *store.Server) (*sshc.Target, error) {
	return buildTargetSeen(ctx, st, sv, map[string]bool{})
}

func buildTargetSeen(ctx context.Context, st *store.Store, sv *store.Server, seen map[string]bool) (*sshc.Target, error) {
	if seen[sv.Hostname] {
		return nil, fmt.Errorf("점프 호스트 순환 참조: %s", sv.Hostname)
	}
	seen[sv.Hostname] = true

	t := &sshc.Target{
		Name: sv.Hostname,
		Addr: net.JoinHostPort(sv.IP, strconv.Itoa(sv.Port)),
		User: sv.User,
		Role: sv.CARole,
	}
	if sv.JumpVia != "" {
		jsv, err := st.Get(ctx, sv.JumpVia)
		if err != nil {
			return nil, fmt.Errorf("점프 호스트 %q 조회 실패: %w", sv.JumpVia, err)
		}
		jt, err := buildTargetSeen(ctx, st, jsv, seen)
		if err != nil {
			return nil, err
		}
		t.Jump = jt
	}
	return t, nil
}
