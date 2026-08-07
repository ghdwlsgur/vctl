package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// A command that ignores an argument it was given is a command that ran
// something other than what was asked for.
//
// `vctl openstack seoul` printed the whole fleet and read as a filtered
// listing; `vctl openstack reconcile seoul` reconciled every deployment while
// looking like it reconciled one. Both are typos with no error and a plausible
// result, which is the combination that gets acted on.
func TestCommandsThatTakeNoArgumentsRefuseThem(t *testing.T) {
	root := NewRoot(Dependencies{})
	for _, path := range [][]string{
		{"openstack"},
		{"openstack", "reconcile"},
	} {
		t.Run(strings.Join(path, " "), func(t *testing.T) {
			cmd, _, err := root.Find(path)
			if err != nil {
				t.Fatalf("find: %v", err)
			}
			if cmd.Args == nil {
				t.Fatal("no argument validator; a stray word would be accepted and ignored")
			}
			if err := cmd.Args(cmd, []string{"seoul"}); err == nil {
				t.Error("a stray argument was accepted")
			}
		})
	}
}

// mutuallyExclusiveWith reports the group cobra recorded for a flag, if any.
func mutuallyExclusiveWith(f *pflag.Flag) []string {
	return f.Annotations["cobra_annotation_mutually_exclusive"]
}

// Two flags that contradict each other are a question the command cannot
// answer. --self picks the deployment this host belongs to and --farm names
// one; given both, one of them is being ignored and the run is not the one that
// was asked for.
func TestContradictoryFlagsAreRefused(t *testing.T) {
	root := NewRoot(Dependencies{})
	for _, tc := range []struct{ path, a, b string }{
		{"reconcile", "self", "farm"},
	} {
		rec, _, err := root.Find([]string{"openstack", tc.path})
		if err != nil {
			t.Fatal(err)
		}
		f := rec.Flags().Lookup(tc.a)
		if f == nil {
			t.Fatalf("no --%s on %s", tc.a, tc.path)
		}
		groups := mutuallyExclusiveWith(f)
		if len(groups) == 0 {
			t.Errorf("--%s and --%s are not marked mutually exclusive", tc.a, tc.b)
			continue
		}
		if !strings.Contains(strings.Join(groups, " "), tc.b) {
			t.Errorf("--%s's exclusivity group is %v, want it to include %s", tc.a, groups, tc.b)
		}
	}
}

// --user is the VM path's flag. On a host the login comes from the inventory,
// and on user@addr it is already in the argument — so a --user there does
// nothing, silently, and the connection goes out as somebody else.
func TestUserFlagOnlyMeansSomethingWithAVM(t *testing.T) {
	root := NewRoot(Dependencies{})
	ssh, _, err := root.Find([]string{"ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ssh.Flags().Set("user", "rocky"); err != nil {
		t.Fatal(err)
	}
	// RunE validates before reaching for anything; a nil app would panic if it
	// did not.
	if err := ssh.RunE(ssh, []string{"some-host"}); err == nil ||
		!strings.Contains(err.Error(), "--user") {
		t.Errorf("err = %v, want --user refused without --vm", err)
	}
}

// The positional query is real and the help has to show it, or the only way to
// find it is to read the source.
func TestVMHelpShowsItsPositional(t *testing.T) {
	root := NewRoot(Dependencies{})
	vm, _, err := root.Find([]string{"openstack", "vm"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vm.Use, "[query]") {
		t.Errorf("Use = %q, want the positional named", vm.Use)
	}
}
