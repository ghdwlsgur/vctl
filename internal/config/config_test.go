package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReadsRepoLocalConfigPath(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
vault_addr: https://vault.test.local
ssh_default_user: rocky
sync_probe_timeout: 250ms
sync_probe_concurrency: 7
ssh_direct_first: false
dc_rules:
  - name: test-dc
    prefixes: ["172.20."]
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	t.Setenv("VCTL_CONFIG", cfgPath)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VCTL_VAULT_ADDR", "")
	t.Setenv("VCTL_SSH_DEFAULT_USER", "")
	t.Setenv("VCTL_SSH_DIRECT_FIRST", "")
	t.Setenv("VCTL_SYNC_PROBE_TIMEOUT", "")
	t.Setenv("VCTL_SYNC_PROBE_CONCURRENCY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigPath != cfgPath {
		t.Fatalf("ConfigPath = %q, want %q", cfg.ConfigPath, cfgPath)
	}
	if cfg.StateDir != filepath.Join(home, ".vctl") {
		t.Fatalf("StateDir = %q", cfg.StateDir)
	}
	if cfg.VaultAddr != "https://vault.test.local" {
		t.Fatalf("VaultAddr = %q", cfg.VaultAddr)
	}
	if cfg.SSHDefaultUser != "rocky" {
		t.Fatalf("SSHDefaultUser = %q", cfg.SSHDefaultUser)
	}
	if cfg.SyncProbeConcurrency != 7 {
		t.Fatalf("SyncProbeConcurrency = %d", cfg.SyncProbeConcurrency)
	}
	if cfg.SSHDirectFirst {
		t.Fatal("SSHDirectFirst = true, want false")
	}
	if len(cfg.DCRules) != 1 || cfg.DCRules[0].Name != "test-dc" {
		t.Fatalf("DCRules = %+v", cfg.DCRules)
	}
}
