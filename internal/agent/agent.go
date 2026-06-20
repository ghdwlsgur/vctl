// Package agent manages token lifetime without running Vault Agent.
//
//   - renew-self before expiry
//   - re-authenticate when max_ttl prevents further renewal
//   - write token sink files for other tools
package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// renewWait schedules renewal after roughly two thirds of the remaining TTL.
func renewWait(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 5 * time.Second
	}
	w := ttl * 2 / 3
	if w < 5*time.Second {
		w = 5 * time.Second
	}
	if w > 30*time.Minute {
		w = 30 * time.Minute
	}
	return w
}

// Keepalive keeps a token alive until ctx ends. It is used by exec.
//
// It never prompts because stdin belongs to the child process. It attempts
// renew-self and non-interactive AppRole re-auth only.
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
		// Renewal failed; try non-interactive re-auth only.
		if err := a.ReAuthNonInteractive(ctx); err != nil {
			fmt.Fprintf(os.Stderr,
				"vctl exec: token keepalive failed (%v). The child process can use only the current token until it expires.\n", err)
			return
		}
	}
}

// Manager runs vctl agent mode.
type Manager struct {
	App   *app.App
	Sinks []string
}

// Run authenticates, renews in a loop, and writes token sinks until ctx ends.
func (m *Manager) Run(ctx context.Context) error {
	if err := m.App.EnsureLogin(ctx); err != nil {
		return err
	}
	if err := m.writeSinks(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "vctl agent: token management started (TTL %s, sinks %v)\n",
		m.App.Vault.TTL().Round(time.Second), m.Sinks)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "vctl agent: stopped")
			return nil
		case <-time.After(renewWait(m.App.Vault.TTL())):
		}

		if err := m.App.Vault.Renew(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "vctl agent: renewal failed (%v); trying re-auth\n", err)
			if err := m.App.ReAuth(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "vctl agent: re-auth failed (%v), retrying in 10s\n", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(10 * time.Second):
				}
				continue
			}
		}
		if err := m.writeSinks(); err != nil {
			fmt.Fprintf(os.Stderr, "vctl agent: sink write failed: %v\n", err)
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
			return fmt.Errorf("sink %s: %w", s, err)
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
