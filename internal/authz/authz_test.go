package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakePolicies is a scripted PolicySource.
type fakePolicies struct {
	identity string
	policies []string
	err      error
}

func (f fakePolicies) TokenIdentity(context.Context) (string, []string, error) {
	return f.identity, f.policies, f.err
}

// fakeGrants is a scripted GrantSource that also counts calls, so tests can
// assert that read/admin decisions never open the grant source.
type fakeGrants struct {
	commands map[string]bool
	err      error
	calls    int
}

func (f *fakeGrants) RBACCommandsForUser(context.Context, string) (map[string]bool, error) {
	f.calls++
	return f.commands, f.err
}

func newAuthorizer(p PolicySource, g GrantSource) (*Authorizer, *int) {
	opens := 0
	az := New(p, func(context.Context) (GrantSource, func(), error) {
		opens++
		return g, nil, nil
	}).WithAdminPolicies(testAdmins)
	return az, &opens
}

// testAdmins mirrors the compiled default (config defaults_sre.go). The names
// are injected now, so the tests inject them the way production wiring does.
var testAdmins = []string{"vctl-admin", "sre-admin"}

func TestCheckUngatedCommandAllowed(t *testing.T) {
	az, opens := newAuthorizer(fakePolicies{}, &fakeGrants{})
	if err := az.Check(context.Background(), Command{Name: "", Class: ClassMutate}); err != nil {
		t.Fatalf("ungated Check = %v, want nil", err)
	}
	if *opens != 0 {
		t.Fatalf("ungated command opened grants %d times, want 0", *opens)
	}
}

func TestCheckAdminBypassesMutate(t *testing.T) {
	p := fakePolicies{identity: "alice", policies: []string{"sre-admin"}}
	g := &fakeGrants{}
	az, opens := newAuthorizer(p, g)
	if err := az.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err != nil {
		t.Fatalf("admin Check(ssh) = %v, want nil", err)
	}
	if *opens != 0 || g.calls != 0 {
		t.Fatal("admin bypass must not consult grants")
	}
}

func TestCheckReadDefaultAllowWithoutGrants(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-users"}}
	g := &fakeGrants{}
	az, opens := newAuthorizer(p, g)
	if err := az.Check(context.Background(), Command{Name: "list", Class: ClassRead}); err != nil {
		t.Fatalf("read Check(list) = %v, want nil", err)
	}
	// Read commands are the hot path for non-admins; they must not open a store.
	if *opens != 0 || g.calls != 0 {
		t.Fatalf("read command consulted grants (opens=%d calls=%d), want 0", *opens, g.calls)
	}
}

func TestCheckAdminClassDeniedForNonAdmin(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-users"}}
	az, opens := newAuthorizer(p, &fakeGrants{})
	err := az.Check(context.Background(), Command{Name: "group create", Class: ClassAdmin})
	if err == nil || !strings.Contains(err.Error(), "admin-only") {
		t.Fatalf("admin-class Check = %v, want admin-only error", err)
	}
	if *opens != 0 {
		t.Fatal("admin-class denial must not open grants")
	}
}

func TestCheckMutateAllowedWithGrant(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-ssh-users"}}
	g := &fakeGrants{commands: map[string]bool{"ssh": true}}
	az, opens := newAuthorizer(p, g)
	if err := az.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate}); err != nil {
		t.Fatalf("granted Check(ssh) = %v, want nil", err)
	}
	if *opens != 1 || g.calls != 1 {
		t.Fatalf("mutate should open grants exactly once (opens=%d calls=%d)", *opens, g.calls)
	}
}

func TestCheckMutateDeniedWithoutGrant(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-ssh-users"}}
	g := &fakeGrants{commands: map[string]bool{"sync": true}} // has sync, not ssh
	az, _ := newAuthorizer(p, g)
	err := az.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("ungranted Check(ssh) = %v, want not-permitted error", err)
	}
}

func TestCheckWildcardGrantAllows(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-ssh-users"}}
	g := &fakeGrants{commands: map[string]bool{"*": true}}
	az, _ := newAuthorizer(p, g)
	if err := az.Check(context.Background(), Command{Name: "sync", Class: ClassMutate}); err != nil {
		t.Fatalf("wildcard Check(sync) = %v, want nil", err)
	}
}

func TestCheckFailsClosedOnPolicyLookupError(t *testing.T) {
	p := fakePolicies{identity: "bob", err: errors.New("vault down")}
	az, _ := newAuthorizer(p, &fakeGrants{})
	err := az.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if err == nil || !strings.Contains(err.Error(), "token lookup") {
		t.Fatalf("policy-lookup failure = %v, want fail-closed token lookup error", err)
	}
}

func TestCheckUninitializedRBACGivesMigrateHint(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-ssh-users"}}
	g := &fakeGrants{err: fmt.Errorf("%w: %s", ErrUninitialized, `ERROR: relation "rbac_grants" does not exist (SQLSTATE 42P01)`)}
	az, _ := newAuthorizer(p, g)
	err := az.Check(context.Background(), Command{Name: "ssh", Class: ClassMutate})
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("uninitialized Check(ssh) = %v, want not-initialized hint", err)
	}
}

func TestSnapshotAdminSkipsGrants(t *testing.T) {
	p := fakePolicies{identity: "alice", policies: []string{"vctl-admin"}}
	g := &fakeGrants{}
	az, opens := newAuthorizer(p, g)
	snap, err := az.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot = %v", err)
	}
	if !snap.Admin || snap.Identity != "alice" {
		t.Fatalf("snapshot = %+v, want admin alice", snap)
	}
	if !snap.Allows("anything") {
		t.Fatal("admin Allows must be true")
	}
	if *opens != 0 || g.calls != 0 {
		t.Fatal("admin Snapshot must not open grants")
	}
}

func TestSnapshotNonAdminLoadsGrants(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-users"}}
	g := &fakeGrants{commands: map[string]bool{"ssh": true}}
	az, _ := newAuthorizer(p, g)
	snap, err := az.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot = %v", err)
	}
	if snap.Admin {
		t.Fatal("non-admin snapshot marked admin")
	}
	if !snap.Allows("ssh") || snap.Allows("sync") {
		t.Fatalf("Allows wrong: ssh=%v sync=%v", snap.Allows("ssh"), snap.Allows("sync"))
	}
}

func TestSnapshotUninitializedIsNotAnError(t *testing.T) {
	p := fakePolicies{identity: "bob", policies: []string{"vctl-users"}}
	g := &fakeGrants{err: fmt.Errorf("grant read: %w", ErrUninitialized)}
	az, _ := newAuthorizer(p, g)
	snap, err := az.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("uninitialized Snapshot = %v, want nil error", err)
	}
	if snap.Commands != nil || snap.Allows("ssh") {
		t.Fatalf("uninitialized snapshot should have no grants, got %+v", snap.Commands)
	}
}

// Classification is by the wrapped sentinel, never by message text. An error
// that merely mentions the SQLSTATE — a table named after it, a quoted query,
// a nested error — used to read as "no grants yet" and skip the grant lookup
// on the path that builds authorization answers.
func TestUninitializedIsClassifiedBySentinelNotByText(t *testing.T) {
	if IsUninitializedRBAC(errors.New(`permission denied for table "audit_42P01_shadow"`)) {
		t.Fatal("an error mentioning 42P01 in prose was classified as uninitialized")
	}
	if !IsUninitializedRBAC(fmt.Errorf("outer: %w", ErrUninitialized)) {
		t.Fatal("a wrapped sentinel was not classified")
	}
}

func TestCatalog(t *testing.T) {
	if c, ok := ClassOf("ssh"); !ok || c != ClassMutate {
		t.Fatalf("ClassOf(ssh) = (%v,%v), want (mutate,true)", c, ok)
	}
	if _, ok := ClassOf("nope"); ok {
		t.Fatal("ClassOf(nope) ok = true, want false")
	}
	if g := Grantable(); len(g) == 0 || g[0] != "*" {
		t.Fatalf("Grantable() = %v, want leading *", g)
	}
	// A grant only ever changes a mutate decision — read is default-allowed
	// and admin follows the Vault policy — so the menu offers exactly the
	// mutate names. A read or admin name in the menu is a grant that lies.
	for _, name := range GrantableCommands() {
		if c, ok := ClassOf(name); !ok || c != ClassMutate {
			t.Errorf("grantable %q has class %v, want mutate", name, c)
		}
	}
	if c, ok := ClassOf("edit"); !ok || c != ClassMutate {
		t.Error("edit is not a mutate catalog entry — its gate demands a grant nobody can give")
	}
	if !HasAdminPolicy([]string{"x", "vctl-admin"}, testAdmins) || HasAdminPolicy([]string{"x"}, testAdmins) {
		t.Fatal("HasAdminPolicy wrong")
	}
	// The names are configuration, not constants: a fork's own admin policy
	// works, and naming no admins admits nobody — the bypass fails closed.
	if !HasAdminPolicy([]string{"acme-root"}, []string{"acme-root"}) {
		t.Fatal("a configured admin policy was not honoured")
	}
	if HasAdminPolicy([]string{"vctl-admin"}, nil) {
		t.Fatal("an empty admin list still admitted an admin")
	}
}
