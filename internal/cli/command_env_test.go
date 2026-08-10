package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// A command takes its app from the env it was built with.
//
// There is no package-level factory to fall back to any more, which is the
// point: the previous shape worked because callers built one tree at a time,
// and that was a convention rather than a guarantee.
func TestACommandTakesItsAppFromTheEnv(t *testing.T) {
	var used bool
	env := CommandEnv{NewApp: func() (*app.App, error) {
		used = true
		return nil, errors.New("env factory")
	}}

	err := env.withStore(context.Background(), false, func(*app.App, *store.Store) error {
		return nil
	})
	if !used {
		t.Fatalf("the env's factory was never called; err = %v", err)
	}
	if err == nil || err.Error() != "env factory" {
		t.Errorf("err = %v, want the env factory's", err)
	}
}

// Two trees built with different dependencies keep them apart.
//
// This is the property the package variable could not offer: a second NewRoot
// overwrote the first's factory, so whichever tree ran later used the other's
// app. Nothing failed — the wrong dependency simply answered — and with no
// parallel tests in this package nothing was ever going to notice.
func TestTwoTreesDoNotShareDependencies(t *testing.T) {
	var ranA, ranB bool
	rootA := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		ranA = true
		return nil, errors.New("A")
	}})
	rootB := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		ranB = true
		return nil, errors.New("B")
	}})

	// Build B second, then run A. Under the old shape A would reach B's factory.
	openstackA := findCmd(rootA, "openstack")
	if openstackA == nil {
		t.Fatal("no openstack command in tree A")
	}
	osA := findCmd(openstackA, "list")
	if osA == nil {
		t.Fatal("no openstack list command in tree A")
	}
	if err := osA.RunE(osA, nil); err == nil {
		t.Fatal("expected tree A's factory to fail")
	}
	if !ranA {
		t.Error("tree A used something other than its own factory")
	}
	if ranB {
		t.Error("tree A reached tree B's factory")
	}

	openstackB := findCmd(rootB, "openstack")
	if openstackB == nil {
		t.Fatal("no openstack command in tree B")
	}
	osB := findCmd(openstackB, "list")
	if osB == nil {
		t.Fatal("no openstack list command in tree B")
	}
	if err := osB.RunE(osB, nil); err == nil {
		t.Fatal("expected tree B's factory to fail")
	}
	if !ranB {
		t.Error("tree B used something other than its own factory")
	}
}

// Every gated command reaches the RBAC pre-run through the same env, so a tree
// built with a fake app does not authenticate against a real Vault.
func TestTheRBACGateUsesTheTreesEnv(t *testing.T) {
	var used bool
	root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		used = true
		return nil, errors.New("injected")
	}})

	ssh := findCmd(root, "ssh")
	if ssh == nil {
		t.Fatal("no ssh command in the tree")
	}
	if root.PersistentPreRunE == nil {
		t.Fatal("the tree has no pre-run gate")
	}
	if err := root.PersistentPreRunE(ssh, nil); err == nil {
		t.Fatal("expected the injected factory's error")
	}
	if !used {
		t.Error("the RBAC gate did not use the tree's factory")
	}
}
