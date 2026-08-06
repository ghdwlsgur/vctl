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
// driving the command tree in tests can't hit the network.
//
// No cleanup: the factory travels with the tree it was given to, so a test that
// builds one cannot leave anything behind for the next.
func fakeDeps(t *testing.T) Dependencies {
	t.Helper()
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
	for _, want := range []string{"login", "ssh", "list", "sync", "audit", "rbac", "mcp", "retention", "node-agent"} {
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

// The injected factory has to reach the commands, which is the whole reason
// Dependencies exists. Asserted through a command rather than through a package
// variable — there is no longer one to read, and the variable was never the
// thing that mattered.
func TestDependenciesNewAppInjected(t *testing.T) {
	called := false
	root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
		called = true
		return nil, errors.New("sentinel")
	}})

	cmd := findCmd(root, "openstack")
	if cmd == nil {
		t.Fatal("no openstack command in the tree")
	}
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected the injected factory's error")
	}
	if !called {
		t.Error("injected NewApp was not used")
	}
}

func TestDefaultDependenciesUseAppNew(t *testing.T) {
	if (Dependencies{}).withDefaults().NewApp == nil {
		t.Fatal("an unset NewApp was not filled in with app.New")
	}
}
