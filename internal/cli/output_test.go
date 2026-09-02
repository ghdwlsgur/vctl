package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
)

func TestEveryLegacyJSONCommandSupportsTheUnifiedOutputFlag(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		if command.LocalNonPersistentFlags().Lookup("json") != nil && command.Annotations[cmdkit.StructuredOutputAnnotation] != "true" {
			t.Errorf("%s has --json but does not support -o json|yaml", command.CommandPath())
		}
		for _, child := range command.Commands() {
			walk(child)
		}
	}
	walk(root)
}

func TestLegacyJSONRemainsCompatibleAndRejectsAConflictingFormat(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	list := findCmd(findCmd(root, "openstack"), "list")
	if format, err := cmdkit.CommandOutput(list, true); err != nil || format != cmdkit.OutputJSON {
		t.Fatalf("legacy --json = %q, %v; want json", format, err)
	}

	root = NewRoot(fakeDeps(t))
	list = findCmd(findCmd(root, "openstack"), "list")
	if err := list.ParseFlags([]string{"--output", "yaml"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cmdkit.CommandOutput(list, true); err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("--json -o yaml error = %v", err)
	}
}
