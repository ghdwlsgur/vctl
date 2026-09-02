package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// value returns what a completion would put on the command line, dropping the
// description the shell only displays.
func value(candidate string) string {
	v, _, _ := strings.Cut(candidate, "\t")
	return v
}

func values(candidates []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, value(c))
	}
	return out
}

// fleetValueFlags are the flags whose values are things the fleet knows about,
// rather than free text. Every one of them has to complete.
//
// A list of names rather than a list of (command, flag) pairs, so a command
// that gains a --farm next year is covered by this test on the day it is
// written instead of the day somebody remembers to add it here.
var fleetValueFlags = map[string]bool{
	"farm": true, "host": true, "hostname": true,
	"project": true, "role": true, "server": true, "vm": true,
}

// notFleetValues are the flags that carry one of those words and do not mean
// it. Each is a decision recorded here rather than a hole in the rule, and
// adding to this map should take an argument.
var notFleetValues = map[string]string{
	"vctl add --host":       "the name being registered — by definition not in the inventory yet",
	"vctl ip set --farm":    "a label (A/B/C/D) on an address record, not a deployment",
	"vctl ip set --project": "a free-text purpose on an address record, not a Keystone project",
}

func TestEveryFleetValueFlagCompletes(t *testing.T) {
	root := NewRoot(Dependencies{})
	var walk func(cmd *cobra.Command, path string)
	walk = func(cmd *cobra.Command, path string) {
		for name := range fleetValueFlags {
			if cmd.LocalFlags().Lookup(name) == nil || notFleetValues[path+" --"+name] != "" {
				continue
			}
			if _, ok := cmd.GetFlagCompletionFunc(name); !ok {
				t.Errorf("%s --%s has no completion; it names something the inventory knows, "+
					"so registerCompletion belongs beside the flag "+
					"(or say why not in notFleetValues)", path, name)
			}
		}
		for _, sub := range cmd.Commands() {
			// Hidden commands are run by the host-side stamper and the agents,
			// never typed, so there is no keystroke here to complete.
			if !sub.IsAvailableCommand() {
				continue
			}
			walk(sub, path+" "+sub.Name())
		}
	}
	walk(root, "vctl")
}

// The command tree is built once per process here and completions are
// registered against pflag.Flag pointers, so a second tree must not lose them.
// It did not, but the failure mode — completions that work in the first tree
// and silently not in the second — is invisible without asking.
func TestCompletionsSurviveASecondCommandTree(t *testing.T) {
	_ = NewRoot(Dependencies{})
	second := NewRoot(Dependencies{})
	vm, _, err := second.Find([]string{"openstack", "vm"})
	if err != nil {
		t.Fatalf("find openstack vm: %v", err)
	}
	if _, ok := vm.GetFlagCompletionFunc("farm"); !ok {
		t.Error("the second tree's 'openstack vm --farm' has no completion")
	}
	if vm.ValidArgsFunction == nil {
		t.Error("the second tree's 'openstack vm' has no argument completion")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
