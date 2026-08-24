package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type stubPolicies struct {
	pols     []string
	identity string
}

func (s stubPolicies) TokenIdentity(context.Context) (string, []string, error) {
	return s.identity, s.pols, nil
}

var errDBDown = errors.New("postgres connect: connection refused")

// offlineAuthorizer builds an authorizer whose grant source is unreachable —
// the Postgres-is-down situation — with a cached grant confirmed `age` ago.
func offlineAuthorizer(t *testing.T, cached []string, age, window time.Duration) (*Authorizer, *[]string) {
	t.Helper()
	now := time.Now()
	var degraded []string
	a := New(stubPolicies{pols: []string{"vctl-user"}, identity: "albert"},
		func(context.Context) (GrantSource, func(), error) { return nil, nil, errDBDown },
	).WithOffline(&Offline{
		Lookup: func(identity string) (CachedGrant, bool) {
			if cached == nil || identity != "albert" {
				return CachedGrant{}, false
			}
			return CachedGrant{Commands: cached, ConfirmedAt: now.Add(-age)}, true
		},
		Window:     window,
		Now:        func() time.Time { return now },
		OnDegraded: func(cmd string, _ time.Duration) { degraded = append(degraded, cmd) },
	})
	return a, &degraded
}

func TestOfflineAllowsSSHWithFreshCachedGrant(t *testing.T) {
	a, degraded := offlineAuthorizer(t, []string{"ssh"}, time.Hour, 24*time.Hour)
	if err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err != nil {
		t.Fatalf("ssh denied with a fresh cached grant: %v", err)
	}
	if len(*degraded) != 1 || (*degraded)[0] != "ssh" {
		t.Errorf("degraded-mode use was not reported: %v", *degraded)
	}
}

// The whole point of the window: a grant revoked during a long outage must not
// stay usable on a laptop that never reconnects.
func TestOfflineExpiredGrantFailsClosed(t *testing.T) {
	a, _ := offlineAuthorizer(t, []string{"ssh"}, 48*time.Hour, 24*time.Hour)
	err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if err == nil {
		t.Fatal("an expired cached grant still authorized ssh")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error does not explain expiry: %v", err)
	}
}

// Degraded mode must never be a way to gain authority. A user with no ssh grant
// must not obtain one by making their own database unreachable.
func TestOfflineCannotEscalateBeyondCachedGrants(t *testing.T) {
	a, _ := offlineAuthorizer(t, []string{"list"}, time.Minute, 24*time.Hour)
	if err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err == nil {
		t.Fatal("ssh was authorized offline without a cached ssh grant")
	}
}

// Commands outside the offline allowlist are refused even when the cached grant
// covers them — they all need the database anyway.
func TestOfflineRefusesNonAllowlistedCommands(t *testing.T) {
	a, _ := offlineAuthorizer(t, []string{"*"}, time.Minute, 24*time.Hour)
	for _, cmd := range []string{"sync", "prune", "trust-ca"} {
		err := a.Check(context.Background(), Command{Name: cmd, Class: ClassMutate})
		if err == nil {
			t.Errorf("%q was authorized offline despite needing the database", cmd)
			continue
		}
		if !strings.Contains(err.Error(), "unreachable") {
			t.Errorf("%q error does not name the cause: %v", cmd, err)
		}
	}
}

// A wildcard grant still works offline, but only for allowlisted commands.
func TestOfflineWildcardGrantCoversSSH(t *testing.T) {
	a, _ := offlineAuthorizer(t, []string{"*"}, time.Minute, 24*time.Hour)
	if err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err != nil {
		t.Fatalf("wildcard grant did not cover ssh offline: %v", err)
	}
}

// With no prior online confirmation there is nothing to fall back to, and the
// operator needs to be told that connecting once while the database is up is
// what fixes it.
func TestOfflineWithoutCachedGrantExplainsItself(t *testing.T) {
	a, _ := offlineAuthorizer(t, nil, 0, 24*time.Hour)
	err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if err == nil {
		t.Fatal("ssh was authorized with no cached grant at all")
	}
	if !strings.Contains(err.Error(), "no cached authorization") {
		t.Errorf("error does not explain the missing cache: %v", err)
	}
}

// Turning the cache off must restore the original behaviour exactly: the
// database error surfaces unchanged.
func TestOfflineDisabledSurfacesTheDatabaseError(t *testing.T) {
	a := New(stubPolicies{pols: []string{"vctl-user"}, identity: "albert"},
		func(context.Context) (GrantSource, func(), error) { return nil, nil, errDBDown })
	err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if !errors.Is(err, errDBDown) {
		t.Fatalf("error = %v, want the underlying database failure", err)
	}
}

// Read commands never consult grants, so an outage must not change them.
func TestOfflineReadCommandsUnaffected(t *testing.T) {
	a, _ := offlineAuthorizer(t, nil, 0, 24*time.Hour)
	if err := a.Check(context.Background(), Command{Name: "list", Class: ClassRead}); err != nil {
		t.Fatalf("read command denied during an outage: %v", err)
	}
}

// Admin policy holders bypass grants entirely, online or off — the decision
// comes from Vault, which is a live lookup.
func TestOfflineAdminPolicyStillBypasses(t *testing.T) {
	a := New(stubPolicies{pols: []string{"vctl-admin"}, identity: "albert"},
		func(context.Context) (GrantSource, func(), error) { return nil, nil, errDBDown })
	if err := a.Check(context.Background(), Command{Name: "sync", Class: ClassMutate}); err != nil {
		t.Fatalf("admin denied during an outage: %v", err)
	}
}

// Grants are cached as a side effect of a successful online check, which is
// what makes the offline path usable without a separate sync step.
func TestOnlineCheckRecordsGrants(t *testing.T) {
	recorded := map[string][]string{}
	a := New(stubPolicies{pols: []string{"vctl-user"}, identity: "albert"},
		func(context.Context) (GrantSource, func(), error) {
			return grantSourceFunc(func(context.Context, string) (map[string]bool, error) {
				return map[string]bool{"ssh": true, "sync": false}, nil
			}), nil, nil
		},
	).WithOffline(&Offline{
		Lookup: func(string) (CachedGrant, bool) { return CachedGrant{}, false },
		Record: func(identity string, cmds []string) { recorded[identity] = cmds },
		Window: 24 * time.Hour,
	})

	if err := a.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err != nil {
		t.Fatal(err)
	}
	got := recorded["albert"]
	if len(got) != 1 || got[0] != "ssh" {
		t.Fatalf("recorded grants = %v, want only the granted commands", got)
	}
}

type grantSourceFunc func(context.Context, string) (map[string]bool, error)

func (f grantSourceFunc) RBACCommandsForUser(ctx context.Context, user string) (map[string]bool, error) {
	return f(ctx, user)
}
