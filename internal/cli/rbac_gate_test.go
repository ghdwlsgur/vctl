package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// A gate on a parent command is not a gate.
//
// Cobra runs the leaf, and enforceRBAC reads the annotation off whatever it is
// about to run. `openstack farm` carried "openstack-farm/mutate" and
// `openstack farm state` carried nothing, so the pre-run found an empty name
// and returned immediately — a command that writes a deployment's declared
// state ran with no authorization check at all.
//
// The rule that keeps it from coming back: an annotation only means something
// on a command cobra will actually execute. Anything else is a gate nobody
// passes through.
//
// A gated command may have subcommands when it runs itself and every runnable
// command beneath it carries a gate of its own — `vctl kv [word]` reads a
// secret, and `kv list`, `kv get` and `kv search` are each gated as reads. What
// is forbidden is the shape the farm bug had: a gate above, and something that
// runs below it without one.
func TestEveryGateIsOnACommandThatRuns(t *testing.T) {
	root := NewRoot(Dependencies{})

	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		if name := c.Annotations["rbac.command"]; name != "" {
			if c.RunE == nil && c.Run == nil {
				t.Errorf("%s carries gate %q but never runs; cobra executes its leaves and they are not gated",
					path, name)
			}
			for _, leaf := range ungatedRunnableDescendants(c, path) {
				t.Errorf("%s carries gate %q but %s runs beneath it with no gate of its own; cobra executes the leaf and the parent's gate does not reach it",
					path, name, leaf)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub, path+" "+sub.Name())
		}
	}
	walk(root, "vctl")
}

// ungatedRunnableDescendants names every command under c that cobra could
// execute without passing a gate — the leaves the farm bug hid behind.
func ungatedRunnableDescendants(c *cobra.Command, path string) []string {
	var out []string
	for _, sub := range c.Commands() {
		subPath := path + " " + sub.Name()
		if sub.Annotations["rbac.command"] == "" && (sub.RunE != nil || sub.Run != nil) {
			out = append(out, subPath)
		}
		out = append(out, ungatedRunnableDescendants(sub, subPath)...)
	}
	return out
}

// The two farm commands that write are gated, and the one that reads is not —
// alongside `openstack` and `list`, which any authenticated user may run.
func TestFarmMutationsAreGatedAndTheReadIsNot(t *testing.T) {
	root := NewRoot(Dependencies{})
	farm := findCmd(findCmd(root, "openstack"), "farm")
	if farm == nil {
		t.Fatal("no farm command")
	}
	for _, tc := range []struct {
		leaf, want string
	}{
		{"name", "openstack-farm"},
		{"state", "openstack-farm"},
		{"show", ""},
	} {
		c := findCmd(farm, tc.leaf)
		if c == nil {
			t.Fatalf("no farm %s", tc.leaf)
		}
		if got := c.Annotations["rbac.command"]; got != tc.want {
			t.Errorf("farm %s gate = %q, want %q", tc.leaf, got, tc.want)
		}
	}
}

// Asserting on annotations is not the same as asserting the gate runs. This
// drives the real pre-run for the argv a person types, and fails if it returns
// without having reached for an identity.
func TestTheGateActuallyRunsForAFarmMutation(t *testing.T) {
	for _, tc := range []struct {
		argv    []string
		wantRun bool
	}{
		{[]string{"openstack", "farm", "state"}, true},
		{[]string{"openstack", "farm", "name"}, true},
		// Reads stay open, so nothing should authenticate on their behalf.
		{[]string{"openstack", "farm", "show"}, false},
	} {
		t.Run(tc.argv[len(tc.argv)-1], func(t *testing.T) {
			var reached bool
			root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
				reached = true
				return nil, errors.New("gate reached for an identity")
			}})
			target, _, err := root.Find(tc.argv)
			if err != nil {
				t.Fatalf("find %v: %v", tc.argv, err)
			}
			if root.PersistentPreRunE == nil {
				t.Fatal("the tree has no pre-run gate")
			}
			err = root.PersistentPreRunE(target, nil)
			if tc.wantRun {
				if !reached || err == nil {
					t.Errorf("%v ran unauthorized: reached=%v err=%v", tc.argv, reached, err)
				}
				return
			}
			if reached {
				t.Errorf("%v was gated; reads are open to any authenticated user", tc.argv)
			}
		})
	}
}

// The bare `vctl kv` runs on the parent and its subcommands run as leaves; the
// gate must be reached on all four argv shapes, not asserted on annotations
// alone. A read gate still authenticates — that is the whole of what it does —
// so reaching for an identity is the observable.
func TestTheGateActuallyRunsForEveryKVShape(t *testing.T) {
	for _, argv := range [][]string{
		{"kv"},
		{"kv", "get"},
		{"kv", "list"},
		{"kv", "search"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			var reached bool
			root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
				reached = true
				return nil, errors.New("gate reached for an identity")
			}})
			target, _, err := root.Find(argv)
			if err != nil {
				t.Fatalf("find %v: %v", argv, err)
			}
			if err := root.PersistentPreRunE(target, nil); !reached || err == nil {
				t.Errorf("%v ran unauthorized: reached=%v err=%v", argv, reached, err)
			}
		})
	}
}
