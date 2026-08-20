package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestYAMLOutputUsesTheSameFieldContractAsJSON(t *testing.T) {
	value := struct {
		FarmName string `json:"farm_name"`
		Empty    string `json:"empty,omitempty"`
	}{FarmName: "incheon-main"}

	var out bytes.Buffer
	if err := encodeStructured(&out, outputYAML, value); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "farm_name: incheon-main") {
		t.Errorf("yaml does not preserve the JSON field name:\n%s", got)
	}
	if strings.Contains(got, "empty:") {
		t.Errorf("yaml does not preserve JSON omitempty:\n%s", got)
	}
}

func TestEveryLegacyJSONCommandSupportsTheUnifiedOutputFlag(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		if command.LocalNonPersistentFlags().Lookup("json") != nil && command.Annotations[structuredOutputAnnotation] != "true" {
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
	if format, err := commandOutput(list, true); err != nil || format != outputJSON {
		t.Fatalf("legacy --json = %q, %v; want json", format, err)
	}

	root = NewRoot(fakeDeps(t))
	list = findCmd(findCmd(root, "openstack"), "list")
	if err := list.ParseFlags([]string{"--output", "yaml"}); err != nil {
		t.Fatal(err)
	}
	if _, err := commandOutput(list, true); err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("--json -o yaml error = %v", err)
	}
}
