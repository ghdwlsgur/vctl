package vaultc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

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
// Integration — needs VCTL_TEST_VAULT_ADDR (dev-mode Vault) and the fixtures
// created by the verification script: userpass user "albert", ssh role
// "sre-core", database roles under database/creds/.
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
	if err := c.LoginUserpass(context.Background(), "albert", "devpass"); err != nil {
		t.Fatalf("userpass login: %v", err)
	}
	return c
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

	if id := c.Identity(ctx); id != "albert" {
		t.Errorf("Identity = %q, want the authenticated user", id)
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

	u1, p1, _, err := c.DBCreds(ctx, "vctl-ro")
	if err != nil {
		t.Fatalf("DBCreds: %v", err)
	}
	if u1 == "" || p1 == "" {
		t.Fatal("DBCreds returned an empty credential")
	}
	u2, _, _, err := c.DBCreds(ctx, "vctl-ro")
	if err != nil {
		t.Fatalf("DBCreds second call: %v", err)
	}
	if u1 == u2 {
		t.Errorf("both calls returned %q — credentials are not dynamic", u1)
	}
}

// A role the token's policy does not cover must fail, not silently succeed:
// per-purpose DB roles are the least-privilege boundary between read paths and
// write paths.
func TestDBCredsDeniedWithoutPolicy(t *testing.T) {
	c := loggedIn(t)
	if _, _, _, err := c.DBCreds(context.Background(), "vctl-rw"); err == nil {
		t.Fatal("vctl-rw credentials were issued to a token without the policy")
	}
}
