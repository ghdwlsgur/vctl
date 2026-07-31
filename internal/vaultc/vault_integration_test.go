package vaultc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ghdwlsgur/vctl/internal/sshc"
)

// These exercise the Vault half of vctl against a real server: authentication,
// the token lifecycle the CLI depends on instead of a Vault Agent, SSH
// certificate signing, and dynamic database credentials.
//
// The offline inventory cache deliberately does not cache any of this — token
// policies are the authoritative boundary and are always looked up live — so
// this is the path that must keep working for `vctl ssh` to work at all, cache
// or no cache.
//
// Integration — needs a stack from scripts/verify-stack.sh, which exports
// VCTL_TEST_VAULT_ADDR plus the userpass identity it generated
// (VCTL_TEST_VAULT_USER / VCTL_TEST_VAULT_PASS). Credentials come from the
// environment rather than being written here: this repo is public, and a
// literal password in a test is indistinguishable from a real one to anything
// scanning the history.
func testClient(t *testing.T) *Client {
	t.Helper()
	addr := os.Getenv("VCTL_TEST_VAULT_ADDR")
	if addr == "" {
		t.Skip("VCTL_TEST_VAULT_ADDR not set; skipping Vault integration test")
	}
	c, err := New(addr, nil, t.TempDir())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func loggedIn(t *testing.T) *Client {
	t.Helper()
	c := testClient(t)
	if err := c.LoginUserpass(context.Background(), testIdentity(t), testPassword(t)); err != nil {
		t.Fatalf("userpass login: %v", err)
	}
	return c
}

func testIdentity(t *testing.T) string { return requireEnv(t, "VCTL_TEST_VAULT_USER") }
func testPassword(t *testing.T) string { return requireEnv(t, "VCTL_TEST_VAULT_PASS") }

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; run scripts/verify-stack.sh up", key)
	}
	return v
}

func TestUserpassLoginCachesUsableToken(t *testing.T) {
	c := loggedIn(t)
	if !c.HasValidToken() {
		t.Fatal("no valid token after a successful login")
	}
	if c.TTL() <= 0 {
		t.Fatalf("TTL = %v, want a positive lease", c.TTL())
	}
}

// The RBAC gate calls TokenPolicies and Identity on every gated command, and
// authz fails closed when they error. Both are live Vault round-trips by design.
func TestTokenPoliciesAndIdentity(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()

	pols, err := c.TokenPolicies(ctx)
	if err != nil {
		t.Fatalf("TokenPolicies: %v", err)
	}
	want := map[string]bool{"vctl-user": false, "vctl-ssh": false}
	for _, p := range pols {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("policy %q missing from %v", p, pols)
		}
	}

	if want := testIdentity(t); c.Identity(ctx) != want {
		t.Errorf("Identity = %q, want the authenticated user %q", c.Identity(ctx), want)
	}
}

// Renewal before expiry is what lets vctl act as its own agent.
func TestRenewKeepsTheSameToken(t *testing.T) {
	c := loggedIn(t)
	before := c.Expiry()
	if err := c.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !c.HasValidToken() {
		t.Fatal("token invalid after renewal")
	}
	if c.Expiry().Before(before) {
		t.Errorf("expiry moved backwards: %s -> %s", before, c.Expiry())
	}
}

// SSH signing is the step no cache can substitute for: during a Postgres outage
// the snapshot supplies the host, but the certificate still has to come from
// Vault. If this breaks, offline `vctl ssh` is impossible by construction.
func TestSignSSHIssuesACertificate(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()

	caPub, err := c.SSHCAPublicKey(ctx)
	if err != nil {
		t.Fatalf("SSHCAPublicKey: %v", err)
	}
	if !strings.HasPrefix(caPub, "ssh-") {
		t.Fatalf("CA public key = %q, want an OpenSSH key", caPub)
	}

	// A throwaway ed25519 public key in OpenSSH wire format.
	pub := testPublicKey(t)
	cert, err := c.SignSSH(ctx, "sre-core", pub, []string{"ubuntu"}, "5m", nil)
	if err != nil {
		t.Fatalf("SignSSH: %v", err)
	}
	if !strings.Contains(cert, "-cert-v01@openssh.com") {
		t.Fatalf("signed key is not a certificate: %.60s", cert)
	}
	if serial := sshc.CertSerial(cert); serial == "" {
		t.Error("certificate carries no serial — audit rows could not reference it")
	}
}

// testPublicKey generates a throwaway ed25519 key in OpenSSH authorized_keys
// form, the same shape vctl produces per connection and never writes to disk.
func testPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// Dynamic database credentials replace a static DSN; every store open fetches a
// fresh pair through this call.
func TestDBCredsAreDynamic(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()

	l1, err := c.DBCreds(ctx, "vctl-ro")
	if err != nil {
		t.Fatalf("DBCreds: %v", err)
	}
	if l1.User == "" || l1.Pass == "" {
		t.Fatal("DBCreds returned an empty credential")
	}
	// The lease id is what makes renewal possible instead of re-issuing, so an
	// empty one is a silent regression to a role created per connection.
	if l1.ID == "" {
		t.Error("DBCreds returned no lease id: the credential cannot be renewed")
	}
	l2, err := c.DBCreds(ctx, "vctl-ro")
	if err != nil {
		t.Fatalf("DBCreds second call: %v", err)
	}
	if l1.User == l2.User {
		t.Errorf("both calls returned %q — credentials are not dynamic", l1.User)
	}
}

// Renewal is the cheap path the pool depends on: it moves a credential's expiry
// without creating another Postgres role. If leases come back non-renewable, the
// cache silently degrades to issuing one credential per connection recycle.
func TestDBCredsLeaseRenews(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()

	l, err := c.DBCreds(ctx, "vctl-ro")
	if err != nil {
		t.Fatalf("DBCreds: %v", err)
	}
	if !l.Renewable {
		t.Fatalf("lease for vctl-ro is not renewable; the credential cache cannot extend it")
	}
	ttl, renewable, err := c.RenewLease(ctx, l.ID, time.Hour)
	if err != nil {
		t.Fatalf("RenewLease: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("renewal granted TTL %v, want a positive duration", ttl)
	}
	_ = renewable
}

// A role the token's policy does not cover must fail, not silently succeed:
// per-purpose DB roles are the least-privilege boundary between read paths and
// write paths.
func TestDBCredsDeniedWithoutPolicy(t *testing.T) {
	c := loggedIn(t)
	if _, err := c.DBCreds(context.Background(), "vctl-rw"); err == nil {
		t.Fatal("vctl-rw credentials were issued to a token without the policy")
	}
}
