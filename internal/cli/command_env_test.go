package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// A converted subtree has to take its app from the env it was built with, not
// from package state.
//
// Changing the signatures is the easy half and proves nothing on its own: a
// command that accepts a CommandEnv and then calls the package newApp() looks
// converted and is not. This sets the global to something that fails loudly and
// checks the env's factory is what actually runs.
func TestAConvertedCommandTakesItsAppFromTheEnv(t *testing.T) {
	saved := appFactory
	t.Cleanup(func() { appFactory = saved })
	appFactory = func() (*app.App, error) {
		return nil, errors.New("package appFactory was used")
	}

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

// An empty CommandEnv still works. The conversion moves subtree by subtree, so
// for a while some commands are built without one — and a nil factory that
// panicked would turn a half-finished migration into a crash.
func TestAnEmptyEnvFallsBackToThePackageFactory(t *testing.T) {
	saved := appFactory
	t.Cleanup(func() { appFactory = saved })
	var used bool
	appFactory = func() (*app.App, error) {
		used = true
		return nil, errors.New("package factory")
	}

	_ = CommandEnv{}.withApp(func(*app.App) error { return nil })
	if !used {
		t.Error("an empty env did not fall back to the package factory")
	}
}

// The tree wires the resolved dependency into the subtree it hands out, which
// is the whole point: NewRoot's Dependencies must reach the commands.
func TestNewRootGivesTheOpenStackSubtreeItsFactory(t *testing.T) {
	saved := appFactory
	t.Cleanup(func() { appFactory = saved })

	var used bool
	root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		used = true
		return nil, errors.New("injected")
	}})
	// Point the global somewhere else entirely: if the subtree reaches for it,
	// this test fails rather than passing by coincidence.
	appFactory = func() (*app.App, error) { return nil, errors.New("package appFactory was used") }

	os := findCmd(root, "openstack")
	if os == nil {
		t.Fatal("no openstack command in the tree")
	}
	if err := os.RunE(os, nil); err == nil {
		t.Fatal("expected the fake factory's error")
	}
	if !used {
		t.Error("the openstack subtree did not use the injected factory")
	}
}
