package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// A token can be revoked server-side long before the cached expiry record
// runs out, and EnsureLogin used to trust that record: it returned nil with
// the dead token armed, every request answered 403 permission denied, and a
// restart re-armed the same corpse from disk. Measured on sre-srv-0032
// (2026-08-31): a day and a half of failed heartbeats, motd passes and
// probes, unhealed by a restart AND by a fresh secret_id, until the cache
// file was deleted by hand.
//
// The fix: with a locally-valid token, EnsureLogin asks Vault (lookup-self)
// before believing the cache. Vault saying 403 outranks the local clock —
// the corpse is dropped and AppRole logs in fresh.
func TestEnsureLoginDistrustsACachedTokenVaultHasRevoked(t *testing.T) {
	var lookups, logins int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			lookups++
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		case "/v1/auth/approle/login":
			logins++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "fresh-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		default:
			t.Errorf("unexpected Vault call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// The corpse: a cache whose own record says it lives for another day —
	// exactly what the fleet host had on disk after the server-side revocation.
	stateDir := t.TempDir()
	cache, _ := json.Marshal(map[string]any{
		"token":     "dead-token",
		"expires":   time.Now().Add(24 * time.Hour).Format(time.RFC3339Nano),
		"renewable": true,
	})
	if err := os.WriteFile(filepath.Join(stateDir, "token"), cache, 0o600); err != nil {
		t.Fatal(err)
	}

	vc, err := vaultc.New(srv.URL, nil, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !vc.HasValidToken() {
		t.Fatal("precondition: the cache must arm the locally-valid dead token")
	}

	a := &App{
		Cfg: &config.Config{
			AppRoleMount:    "approle",
			AppRoleID:       "role-id",
			AppRoleSecretID: "secret-id",
		},
		Vault:       vc,
		Interactive: func() bool { return false },
	}
	if err := a.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}
	if lookups == 0 {
		t.Error("EnsureLogin never asked Vault about the cached token")
	}
	if logins != 1 {
		t.Errorf("AppRole logins = %d, want exactly 1 fresh login", logins)
	}
	if got := vc.Token(); got != "fresh-token" {
		t.Errorf("armed token = %q, want the fresh login's token", got)
	}
}

// Transport trouble is not a verdict on the token. A network blip during the
// lookup must not throw away a good token — for a person that would burn an
// interactive SSO round; for a daemon the very next call fails the same way
// and surfaces the real error.
func TestEnsureLoginKeepsTheTokenWhenVaultIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	stateDir := t.TempDir()
	cache, _ := json.Marshal(map[string]any{
		"token":     "good-token",
		"expires":   time.Now().Add(time.Hour).Format(time.RFC3339Nano),
		"renewable": true,
	})
	if err := os.WriteFile(filepath.Join(stateDir, "token"), cache, 0o600); err != nil {
		t.Fatal(err)
	}
	vc, err := vaultc.New(srv.URL, nil, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // now even the transport is gone

	a := &App{
		Cfg:         &config.Config{AppRoleMount: "approle"},
		Vault:       vc,
		Interactive: func() bool { return false },
	}
	if err := a.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}
	if got := vc.Token(); got != "good-token" {
		t.Errorf("armed token = %q, want the cached token kept", got)
	}
}
