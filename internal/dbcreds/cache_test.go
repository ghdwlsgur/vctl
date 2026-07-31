package dbcreds

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// fakeIssuer records what the cache asked for and lets a test drive Vault's
// answers, including the clamped renewals a real server only produces near
// max_ttl.
type fakeIssuer struct {
	issued  int
	renewed int

	ttl       time.Duration // TTL granted on issue
	renewable bool          // whether issued leases are renewable

	// renewTTL is the TTL a renewal grants. Zero means "as much as an issue
	// grants", which is the normal case; a small value models Vault clamping the
	// renewal against max_ttl.
	renewTTL time.Duration
	renewErr error
}

func (f *fakeIssuer) Issue(context.Context) (vaultc.DBLease, error) {
	f.issued++
	return vaultc.DBLease{
		User:      "v-token-" + time.Duration(f.issued).String(),
		Pass:      "pw",
		ID:        "lease/" + time.Duration(f.issued).String(),
		TTL:       f.ttl,
		Renewable: f.renewable,
	}, nil
}

func (f *fakeIssuer) Renew(_ context.Context, _ string, _ time.Duration) (time.Duration, bool, error) {
	f.renewed++
	if f.renewErr != nil {
		return 0, false, f.renewErr
	}
	if f.renewTTL != 0 {
		return f.renewTTL, true, nil
	}
	return f.ttl, true, nil
}

// clock lets the test advance time without sleeping. Every failure this package
// can have is an expiry comparison, so the clock is the subject under test as
// much as the cache is.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(iss Issuer, minRemaining time.Duration) (*Cache, *clock) {
	c := New(iss, minRemaining, time.Hour)
	ck := &clock{t: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
	c.now = ck.now
	return c, ck
}

// The whole point of the cache: repeated calls within the lease reuse one
// credential. Issuing per call is what created 114 Postgres roles an hour.
func TestRepeatedGetsReuseOneCredential(t *testing.T) {
	iss := &fakeIssuer{ttl: time.Hour, renewable: true}
	c, ck := newTestCache(iss, 50*time.Minute)
	ctx := context.Background()

	u1, _, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	ck.add(30 * time.Second)
	u2, _, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if u1 != u2 {
		t.Errorf("got two different users (%q, %q): the cache is not reusing the credential", u1, u2)
	}
	if iss.issued != 1 {
		t.Errorf("issued %d credentials, want 1", iss.issued)
	}
}

// When the lease drops below the floor, renewal must be preferred to issuing.
// Renewal moves the expiry without touching Postgres; issuing creates a role.
func TestExpiringLeaseIsRenewedNotReissued(t *testing.T) {
	iss := &fakeIssuer{ttl: time.Hour, renewable: true}
	c, ck := newTestCache(iss, 50*time.Minute)
	ctx := context.Background()

	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	// 20 minutes in, only 40 remain — under the 50m floor.
	ck.add(20 * time.Minute)
	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if iss.renewed != 1 {
		t.Errorf("renewed %d times, want 1", iss.renewed)
	}
	if iss.issued != 1 {
		t.Errorf("issued %d credentials, want 1: renewal should have sufficed", iss.issued)
	}
}

// Vault clamps a renewal to what remains of max_ttl, so near that ceiling a
// renewal succeeds and still leaves the credential expiring too soon. Treating
// that as success hands out a credential that dies inside a live connection —
// the failure this cache exists to avoid, and the one an "err == nil" check
// alone would miss.
func TestClampedRenewalFallsBackToIssuing(t *testing.T) {
	iss := &fakeIssuer{
		ttl:       time.Hour,
		renewable: true,
		// Vault clamped the renewal against max_ttl: it succeeded, but bought
		// far less than the 50m floor.
		renewTTL: 5 * time.Minute,
	}
	c, ck := newTestCache(iss, 50*time.Minute)
	ctx := context.Background()

	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	ck.add(20 * time.Minute)
	u, _, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if iss.renewed != 1 {
		t.Errorf("renewed %d times, want 1 attempt before giving up", iss.renewed)
	}
	if iss.issued != 2 {
		t.Errorf("issued %d credentials, want 2: a clamped renewal must fall through to a fresh issue", iss.issued)
	}
	if u == "" {
		t.Error("Get returned an empty user")
	}
}

// A revoked or unknown lease makes renewal fail outright. That is recoverable —
// issuing a new credential still satisfies the caller — so it must not surface
// as an error to a command that could have proceeded.
func TestFailedRenewalIsNotFatal(t *testing.T) {
	iss := &fakeIssuer{ttl: time.Hour, renewable: true, renewErr: errors.New("lease not found")}
	c, ck := newTestCache(iss, 50*time.Minute)
	ctx := context.Background()

	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	ck.add(20 * time.Minute)
	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("Get after a failed renewal returned %v, want a fresh credential", err)
	}
	if iss.issued != 2 {
		t.Errorf("issued %d credentials, want 2", iss.issued)
	}
}

// A non-renewable lease should not waste a round trip on renewal.
func TestNonRenewableLeaseSkipsRenewal(t *testing.T) {
	iss := &fakeIssuer{ttl: time.Hour, renewable: false}
	c, ck := newTestCache(iss, 50*time.Minute)
	ctx := context.Background()

	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	ck.add(20 * time.Minute)
	if _, _, err := c.Get(ctx); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if iss.renewed != 0 {
		t.Errorf("attempted %d renewals on a non-renewable lease, want 0", iss.renewed)
	}
	if iss.issued != 2 {
		t.Errorf("issued %d credentials, want 2", iss.issued)
	}
}

// A role whose TTL is shorter than a connection's maximum age can never satisfy
// the caller. Saying so names the misconfiguration; the alternative is
// connections dying on a cadence nobody traces back to a Vault role definition.
func TestTooShortRoleTTLIsReported(t *testing.T) {
	iss := &fakeIssuer{ttl: 10 * time.Minute, renewable: true}
	c, _ := newTestCache(iss, 50*time.Minute)

	_, _, err := c.Get(context.Background())
	if err == nil {
		t.Fatal("Get succeeded with a credential shorter than the connection lifetime")
	}
	if got := err.Error(); !contains(got, "default_ttl") {
		t.Errorf("error %q does not point at the Vault role's default_ttl", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
