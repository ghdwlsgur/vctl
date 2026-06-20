// Package agent 는 Vault Agent 없이 "에이전트처럼" 토큰 수명을 관리한다.
//
//   - 자동 갱신(renew-self): 만료 전에 미리 토큰 수명을 늘린다.
//   - 자동 재인증: 더 못 늘리면(max_ttl) approle/대화식으로 새 토큰.
//   - 토큰 싱크: 유효 토큰을 파일로 떨궈 다른 도구(raw vault CLI 등)가 쓰게 한다.
package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// renewWait 는 남은 TTL 의 약 1/3 지점에서 갱신하도록 대기 시간을 정한다.
func renewWait(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 5 * time.Second
	}
	w := ttl * 2 / 3
	if w < 5*time.Second {
		w = 5 * time.Second
	}
	if w > 30*time.Minute {
		w = 30 * time.Minute // 너무 오래 자지 않도록 상한
	}
	return w
}

// Keepalive 는 ctx 가 끝날 때까지 토큰을 백그라운드로 살려둔다(exec 용).
//
// 자식이 stdin 을 점유하므로 대화식 재인증을 절대 하지 않는다 — renew-self,
// 그리고 approle 무인 재인증까지만 시도한다. 둘 다 불가하면(예: max_ttl 도달 +
// approle 없음) 경고만 남기고 멈춘다. 자식은 현재 토큰이 만료될 때까지 동작한다.
func Keepalive(ctx context.Context, a *app.App) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(renewWait(a.Vault.TTL())):
		}
		if err := a.Vault.Renew(ctx); err == nil {
			continue
		}
		// 갱신 불가 → 무인 재인증만 시도(프롬프트 금지)
		if err := a.ReAuthNonInteractive(ctx); err != nil {
			fmt.Fprintf(os.Stderr,
				"vctl exec: 토큰 자동연장 불가(%v). 자식은 현재 토큰 만료까지만 유효합니다.\n", err)
			return
		}
	}
}

// Manager 는 'vctl agent' 데몬을 구동한다.
type Manager struct {
	App   *app.App
	Sinks []string
}

// Run 은 초기 인증 후 갱신 루프를 돌며 토큰을 싱크에 기록한다(ctx 취소 시 종료).
func (m *Manager) Run(ctx context.Context) error {
	if err := m.App.EnsureLogin(ctx); err != nil {
		return err
	}
	if err := m.writeSinks(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "vctl agent: 토큰 관리 시작 (TTL %s, 싱크 %v)\n",
		m.App.Vault.TTL().Round(time.Second), m.Sinks)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "vctl agent: 종료")
			return nil
		case <-time.After(renewWait(m.App.Vault.TTL())):
		}

		if err := m.App.Vault.Renew(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "vctl agent: 갱신 불가(%v) → 재인증 시도\n", err)
			if err := m.App.ReAuth(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "vctl agent: 재인증 실패(%v), 10초 후 재시도\n", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(10 * time.Second):
				}
				continue
			}
		}
		if err := m.writeSinks(); err != nil {
			fmt.Fprintf(os.Stderr, "vctl agent: 싱크 기록 실패: %v\n", err)
		}
	}
}

func (m *Manager) writeSinks() error {
	token := m.App.Vault.Token()
	for _, s := range m.Sinks {
		if s == "" {
			continue
		}
		if err := writeFileAtomic(s, []byte(token), 0o600); err != nil {
			return fmt.Errorf("싱크 %s: %w", s, err)
		}
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
