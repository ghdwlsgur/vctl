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
	for _, want := range []string{"login", "ssh", "list", "sync", "audit", "rbac", "mcp", "retention", "node-agent", "kv"} {
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

func TestRootHelpPresentsTheSREControlPlaneByWorkflow(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}

	help := out.String()
	for _, want := range []string{
		"vctl is the SRE infrastructure control plane",
		"Access Commands:",
		"Infrastructure Commands:",
		"Operations Commands:",
		"Administration Commands:",
		"Automation Commands:",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q:\n%s", want, help)
		}
	}
	if strings.Index(help, "Access Commands:") > strings.Index(help, "Automation Commands:") {
		t.Fatalf("human workflows should appear before automation commands:\n%s", help)
	}
}

func TestRootOffersOneOutputFlagAndRejectsUnsupportedStructuredOutput(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	flag := root.PersistentFlags().Lookup("output")
	if flag == nil || flag.Shorthand != "o" || flag.DefValue != "table" {
		t.Fatalf("output flag = %+v, want -o/--output defaulting to table", flag)
	}

	root.SetArgs([]string{"status", "--output", "json"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), `status does not support --output json`) {
		t.Fatalf("status -o json error = %v", err)
	}
}

func TestStructuredOutputCommandsAcceptJSONAndYAML(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	openstack := findCmd(root, "openstack")
	list := findCmd(openstack, "list")
	for _, format := range []string{"json", "yaml"} {
		if err := list.ParseFlags([]string{"--output", format}); err != nil {
			t.Fatalf("parse -o %s: %v", format, err)
		}
		if err := validateOutputSelection(list); err != nil {
			t.Errorf("openstack list -o %s: %v", format, err)
		}
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

	openstack := findCmd(root, "openstack")
	if openstack == nil {
		t.Fatal("no openstack command in the tree")
	}
	cmd := findCmd(openstack, "list")
	if cmd == nil {
		t.Fatal("no openstack list command in the tree")
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
