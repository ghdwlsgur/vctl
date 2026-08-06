package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// active is the overwhelming majority, so labelling it would bury the rows that
// are not. The column exists to be blank unless somebody has something to say.
func TestStateCellIsBlankForActive(t *testing.T) {
	for _, s := range []string{store.StateActive, ""} {
		if got := stripANSI(stateCell(s)); got != "" {
			t.Errorf("stateCell(%q) = %q, want blank", s, got)
		}
	}
	for _, s := range []string{store.StateBroken, store.StateMaintenance, store.StateRetired} {
		if got := stripANSI(stateCell(s)); got == "" {
			t.Errorf("stateCell(%q) rendered nothing", s)
		}
	}
}

// The declared state must sit beside the observed one, not replace it. A
// listing that showed only "broken" would have thrown away the answer to "is it
// answering right now"; one that showed only "no-agent" cannot tell a filed
// fault from a host nobody has looked at.
func TestRenderInventoryShowsStateBesideObservedLiveness(t *testing.T) {
	fresh := time.Now().Add(-2 * time.Minute)
	rows := []store.InventoryRow{
		{
			Server:    store.Server{Hostname: "aio01", IP: "172.18.0.11", Port: 22, User: "rocky", DC: "incheon"},
			Addresses: []string{"172.18.0.11"}, AgentSeen: &fresh,
		},
		{
			Server:    store.Server{Hostname: "gpu01", IP: "172.18.0.21", Port: 22, User: "rocky", DC: "incheon"},
			Addresses: []string{"172.18.0.21"},
		},
		{
			Server: store.Server{Hostname: "gpu03", IP: "172.18.0.23", Port: 22, User: "rocky", DC: "incheon",
				State: store.StateBroken},
			Addresses: []string{"172.18.0.23"},
		},
	}
	var buf bytes.Buffer
	renderInventory(&buf, rows, false, false)
	out := stripANSI(buf.String())

	var broken, unlabelled string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "gpu03"):
			broken = line
		case strings.Contains(line, "gpu01"):
			unlabelled = line
		}
	}
	if broken == "" || unlabelled == "" {
		t.Fatalf("listing is missing rows:\n%s", out)
	}
	if !strings.Contains(broken, "broken") {
		t.Errorf("the declared state is not on the row: %q", broken)
	}
	if !strings.Contains(broken, "no-agent") {
		t.Errorf("the observed liveness was replaced by the state: %q", broken)
	}
	// The pair is the point: same observation, different meaning.
	if strings.Contains(unlabelled, "broken") {
		t.Errorf("a host with no declared state was labelled: %q", unlabelled)
	}
	if !strings.Contains(unlabelled, "no-agent") {
		t.Errorf("expected the same observed value on the undeclared row: %q", unlabelled)
	}
}

// The state is on the row, so "broken" has to find the broken hosts. Whole word
// only: a prefix match would make "a" select every active host and swallow the
// hostname search, which is what the picker is mostly used for.
func TestPickerFilterMatchesWholeStateWordOnly(t *testing.T) {
	broken := store.ServerWithStatus{Server: store.Server{
		Hostname: "gpu03", IP: "172.18.0.23", DC: "incheon", User: "rocky", State: store.StateBroken,
	}}
	active := store.ServerWithStatus{Server: store.Server{
		Hostname: "zzz01", IP: "172.18.0.24", DC: "incheon", User: "rocky", State: store.StateActive,
	}}
	if !matchServer(broken, "broken") {
		t.Error(`typing "broken" does not find the broken host`)
	}
	if matchServer(active, "broken") {
		t.Error(`"broken" matched an active host`)
	}
	if matchServer(active, "a") {
		t.Error(`"a" matched every active host, which would swallow the hostname search`)
	}
}

// Setting a state is a change like any other; an unset --state means "leave it
// alone", the same contract every other field here follows.
func TestHostEditsTreatsStateLikeTheOtherFields(t *testing.T) {
	if !(hostEdits{}).empty() {
		t.Error("an empty hostEdits is not reported as empty")
	}
	if (hostEdits{State: store.StateBroken}).empty() {
		t.Error("--state was set but hostEdits reports empty")
	}
}

// An unknown state has to fail before any other step writes. The database has
// the same constraint, but hitting it mid-apply leaves the earlier edits
// committed and reports a check-constraint name instead of the valid words.
func TestHostEditsValidateRejectsAnUnknownState(t *testing.T) {
	st := &fakeLister{rows: rowsFull(store.Server{Hostname: "web-01"})}
	err := (hostEdits{State: "down"}).validate(context.Background(), st, "web-01")
	if err == nil {
		t.Fatal(`validate accepted --state down`)
	}
	for _, want := range []string{"down", store.StateBroken} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	for _, s := range store.HostStates {
		if err := (hostEdits{State: s}).validate(context.Background(), st, "web-01"); err != nil {
			t.Errorf("validate rejected the valid state %q: %v", s, err)
		}
	}
}

// The form offers exactly the states the database accepts, rather than free
// text — typing a word the CHECK constraint rejects should fail at the form, not
// after the other edits have been written.
//
// The labels are the bare words: the field is inline, so it shows one option at
// a time and an explanation baked into the label would show one state's meaning
// while hiding the other three.
func TestStateOptionsOfferEveryStateAsItsOwnWord(t *testing.T) {
	opts := stateOptions()
	if len(opts) != len(store.HostStates) {
		t.Fatalf("stateOptions gave %d choices, want %d", len(opts), len(store.HostStates))
	}
	for i, want := range store.HostStates {
		if opts[i].Value != want {
			t.Errorf("option %d is %q, want %q — the order is the listing's", i, opts[i].Value, want)
		}
		if opts[i].Key != want {
			t.Errorf("option %d label is %q, want the bare word %q", i, opts[i].Key, want)
		}
	}
}

// The explanations moved under the field, and all four are shown whichever one
// is selected. Choosing between them needs the alternatives in view — "broken"
// only means something next to "maintenance".
func TestEveryStateIsExplainedUnderTheField(t *testing.T) {
	text := stateMeanings()
	for _, want := range store.HostStates {
		if !strings.Contains(text, want+":") {
			t.Errorf("stateMeanings does not explain %q:\n%s", want, text)
		}
	}
}
