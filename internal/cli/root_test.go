package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// fakeDeps injects an app factory that never touches Vault, so building and
// driving the command tree in tests can't hit the network. Restores the global
// factory afterward so later tests see production defaults.
func fakeDeps(t *testing.T) Dependencies {
	t.Cleanup(func() { appFactory = app.New })
	return Dependencies{NewApp: func() (*app.App, error) {
		return nil, errors.New("fake app: no vault in test")
	}}
}

func findCmd(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func TestNewRootRegistersCommands(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	for _, want := range []string{"login", "ssh", "list", "sync", "audit", "rbac", "mcp", "prune", "node-agent"} {
		if findCmd(root, want) == nil {
			t.Errorf("command %q missing from tree", want)
		}
	}
}

func TestGatedCommandsCarryAnnotations(t *testing.T) {
	root := NewRoot(fakeDeps(t))

	ssh := findCmd(root, "ssh")
	if ssh == nil {
		t.Fatal("ssh command missing")
	}
	if ssh.Annotations["rbac.command"] != "ssh" || ssh.Annotations["rbac.class"] != string(classMutate) {
		t.Fatalf("ssh gate annotations = %+v, want mutate", ssh.Annotations)
	}

	// list is a read command: ungated (default-allow), so it carries no rbac tag.
	if ls := findCmd(root, "list"); ls == nil || ls.Annotations["rbac.command"] != "" {
		t.Fatalf("list should be ungated, annotations = %+v", ls.Annotations)
	}
}

func TestVersionGoesToConfiguredWriter(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	if !strings.Contains(out.String(), Version) {
		t.Fatalf("--version output %q missing version %q", out.String(), Version)
	}
}

func TestUnknownCommandErrorsWithoutApp(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"definitely-not-a-command"})
	if err := root.Execute(); err == nil {
		t.Fatal("unknown command should error")
	}
}

func TestDependenciesNewAppInjected(t *testing.T) {
	called := false
	NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		called = true
		return nil, errors.New("sentinel")
	}})
	t.Cleanup(func() { appFactory = app.New })

	a, err := newApp()
	if a != nil || err == nil || !called {
		t.Fatalf("injected NewApp not used: app=%v called=%v err=%v", a, called, err)
	}
}

func TestDefaultDependenciesUseAppNew(t *testing.T) {
	NewRoot(Dependencies{}) // no NewApp → withDefaults() should fill app.New
	t.Cleanup(func() { appFactory = app.New })
	if appFactory == nil {
		t.Fatal("default appFactory is nil")
	}
}
