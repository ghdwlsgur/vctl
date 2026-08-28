package cli

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// The search walk against a real Vault and a real policy: the fixture
// verify-stack.sh writes has a folder the test identity may not list beside
// the ones it may, which is the case the unit tests can only fake.
//
// Integration — needs VCTL_TEST_VAULT_ADDR / _USER / _PASS from
// scripts/verify-stack.sh, and skips without them.
func TestWalkKVAgainstVaultReportsThePrivateFolder(t *testing.T) {
	addr := os.Getenv("VCTL_TEST_VAULT_ADDR")
	user, pass := os.Getenv("VCTL_TEST_VAULT_USER"), os.Getenv("VCTL_TEST_VAULT_PASS")
	if addr == "" || user == "" || pass == "" {
		t.Skip("VCTL_TEST_VAULT_* not set; run scripts/verify-stack.sh up")
	}
	c, err := vaultc.New(addr, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.LoginUserpass(ctx, user, pass); err != nil {
		t.Fatalf("userpass login: %v", err)
	}

	walk, err := walkKV(ctx, c, "kv", 1000)
	if err != nil {
		t.Fatalf("walkKV: %v", err)
	}
	for _, want := range []string{"kv/teams/test/alpha", "kv/teams/test/beta", "kv/teams/test/beta/nested"} {
		if !slices.Contains(walk.Secrets, want) {
			t.Errorf("Secrets = %v, want %q among them", walk.Secrets, want)
		}
	}
	if !slices.Contains(walk.Denied, "kv/teams/private") {
		t.Errorf("Denied = %v, want the private folder reported", walk.Denied)
	}
	if slices.Contains(walk.Secrets, "kv/teams/private/gamma") {
		t.Error("a secret behind a denied folder was listed")
	}
}
