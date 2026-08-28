package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The default never puts a value on the screen. The keys are there — that is
// what "is the field there" needs — and so is the way to see more.
func TestRenderKVSecretMasksValuesByDefault(t *testing.T) {
	var out bytes.Buffer
	renderKVSecret(&out, sampleSecret(), false)
	text := ui.StripANSI(out.String())
	for _, want := range []string{"kv/teams/sre/example", "v3", "token", "username", "retries", kvHidden, "--reveal", "owner=sre"} {
		if !strings.Contains(text, want) {
			t.Errorf("masked output missing %q:\n%s", want, text)
		}
	}
	for _, leak := range []string{"token-field-value", "someone"} {
		if strings.Contains(text, leak) {
			t.Errorf("masked output shows the value %q:\n%s", leak, text)
		}
	}
}

func TestRenderKVSecretRevealsOnRequest(t *testing.T) {
	var out bytes.Buffer
	renderKVSecret(&out, sampleSecret(), true)
	text := ui.StripANSI(out.String())
	for _, want := range []string{"token-field-value", "someone"} {
		if !strings.Contains(text, want) {
			t.Errorf("revealed output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, kvHidden) || strings.Contains(text, "--reveal") {
		t.Errorf("revealed output still masks or hints:\n%s", text)
	}
}

// An empty field list would read as a secret with no fields. A deleted version
// has fields; they are hidden, and the output has to say so.
func TestRenderKVSecretSaysWhenAVersionIsDeleted(t *testing.T) {
	sec := sampleSecret()
	sec.Data = nil
	sec.DeletedAt = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	renderKVSecret(&out, sec, true)
	if text := ui.StripANSI(out.String()); !strings.Contains(text, "deleted") {
		t.Errorf("deleted version rendered without saying so:\n%s", text)
	}
}

// Structured output follows the same rule as the table: data only on request,
// and then absent rather than masked — a placeholder string is a value to a
// program.
func TestKVGetOutputCarriesDataOnlyWhenRevealed(t *testing.T) {
	sec := sampleSecret()
	hidden, err := json.Marshal(newKVGetOutput(sec, false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hidden), `"data"`) || strings.Contains(string(hidden), "token-field-value") {
		t.Errorf("hidden output carries data: %s", hidden)
	}
	if !strings.Contains(string(hidden), `"keys":["token","username"]`) {
		t.Errorf("hidden output lacks the key list: %s", hidden)
	}
	revealed, err := json.Marshal(newKVGetOutput(sec, true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(revealed), `"token":"token-field-value"`) {
		t.Errorf("revealed output lacks the data: %s", revealed)
	}
}
