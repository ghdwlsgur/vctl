package cmdkit

import (
	"bytes"
	"strings"
	"testing"
)

func TestYAMLOutputUsesTheSameFieldContractAsJSON(t *testing.T) {
	value := struct {
		FarmName string `json:"farm_name"`
		Empty    string `json:"empty,omitempty"`
	}{FarmName: "incheon-main"}

	var out bytes.Buffer
	if err := encodeStructured(&out, OutputYAML, value); err != nil {
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
