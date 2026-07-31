package dbcreds_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/dbcreds"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// The unit tests drive a fake issuer, which proves the expiry arithmetic but not
// that a real Vault agrees with it: whether leases come back renewable, and
// whether reusing one credential across many callers actually stops Postgres
// roles from accumulating. That is the claim worth measuring, so it is measured
// against the live stack rather than asserted.
//
// Run with scripts/verify-stack.sh up; skipped otherwise.
func TestCacheIssuesOneCredentialForManyCallers(t *testing.T) {
	addr := os.Getenv("VCTL_TEST_VAULT_ADDR")
	user, pass := os.Getenv("VCTL_TEST_VAULT_USER"), os.Getenv("VCTL_TEST_VAULT_PASS")
	if addr == "" || user == "" || pass == "" {
		t.Skip("VCTL_TEST_VAULT_* not set; skipping live credential cache test")
	}
	ctx := context.Background()

	c, err := vaultc.New(addr, caPEM(t), t.TempDir())
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	if err := c.LoginUserpass(ctx, user, pass); err != nil {
		t.Fatalf("login: %v", err)
	}

	// The floor is derived the same way production derives it, so this test
	// fails if the pool's lifetime is ever raised past what a lease can cover.
	minRemaining := store.MaxConnAge() + 5*time.Minute
	cache := dbcreds.New(issuer{c: c, role: "vctl-ro"}, minRemaining, 24*time.Hour)

	// Stand in for a pool opening connections repeatedly. Every one of these was
	// a CREATE ROLE before the cache existed.
	const calls = 12
	first, _, err := cache.Get(ctx)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	for i := 1; i < calls; i++ {
		u, _, err := cache.Get(ctx)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		if u != first {
			t.Fatalf("call %d returned user %q, want the cached %q: each connection is still issuing its own credential", i, u, first)
		}
	}
	t.Logf("%d calls served by one credential (%s)", calls, first)
}

// issuer adapts the Vault client, mirroring the adapter in internal/app.
type issuer struct {
	c    *vaultc.Client
	role string
}

func (i issuer) Issue(ctx context.Context) (vaultc.DBLease, error) {
	return i.c.DBCreds(ctx, i.role)
}

func (i issuer) Renew(ctx context.Context, leaseID string, inc time.Duration) (time.Duration, bool, error) {
	return i.c.RenewLease(ctx, leaseID, inc)
}

func caPEM(t *testing.T) []byte {
	t.Helper()
	if p := os.Getenv("VCTL_TEST_TLS_CA"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read CA: %v", err)
		}
		return b
	}
	return config.SRERootCA
}
