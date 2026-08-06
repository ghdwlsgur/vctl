package reconcile

import (
	"slices"
	"testing"
)

// A dry run must decide exactly what a real run decides. If they differ, the
// preview is worse than not having one — it invites approving a change that
// then does something else.
func TestDryRunMatchesTheRealMatchingRule(t *testing.T) {
	got := Preview(
		[]string{"sre-srv-01", "sre-srv-02", "sre-srv-03"},
		[]string{"sre-srv-01", "sre-srv-02.internal.example", "ghost-99"},
	)

	if !slices.Equal(got.Confirmed, []string{"sre-srv-01", "sre-srv-02"}) {
		t.Errorf("confirmed = %v, want the two matched on exact and short name", got.Confirmed)
	}
	if !slices.Equal(got.LocalOnly, []string{"sre-srv-03"}) {
		t.Errorf("local-only = %v, want the host the control plane never named", got.LocalOnly)
	}
	if !slices.Equal(got.ControlOnly, []string{"ghost-99"}) {
		t.Errorf("control-only = %v, want the nova host with no probe result", got.ControlOnly)
	}
}

// A farm where both sides agree completely has nothing to disagree about, and
// the report should not invent a disagreement to fill the space.
func TestDryRunReportsNoDisagreementWhenThereIsNone(t *testing.T) {
	got := Preview([]string{"a", "b"}, []string{"a", "b"})

	if len(got.LocalOnly) != 0 || len(got.ControlOnly) != 0 {
		t.Errorf("disagreements = %v / %v, want none", got.LocalOnly, got.ControlOnly)
	}
}

// A dry run must decide exactly what a real run decides, including across an
// inventory prefix. The first version restated the matching rule here instead
// of calling it, which is how the two drift apart.
func TestDryRunUsesTheSameMatcherAsTheStore(t *testing.T) {
	local := []string{"incheon-aio01", "incheon-gpu01", "incheon-orphan"}
	control := []string{"aio01", "gpu01", "ghost-99"}

	got := Preview(local, control)

	if !slices.Equal(got.Confirmed, []string{"incheon-aio01", "incheon-gpu01"}) {
		t.Errorf("confirmed = %v, want the two matched across the site prefix", got.Confirmed)
	}
	if !slices.Equal(got.LocalOnly, []string{"incheon-orphan"}) {
		t.Errorf("local-only = %v", got.LocalOnly)
	}
	if !slices.Equal(got.ControlOnly, []string{"ghost-99"}) {
		t.Errorf("control-only = %v", got.ControlOnly)
	}
}

// An ambiguous name is a question about which machine is meant, and it must be
// visible rather than folded into the local-only pile.
func TestDryRunReportsAmbiguity(t *testing.T) {
	got := Preview([]string{"incheon-aio01", "seoul-aio01"}, []string{"aio01"})

	if len(got.Confirmed) != 0 {
		t.Errorf("confirmed = %v, want none", got.Confirmed)
	}
	if !slices.Contains(got.Ambiguous, "aio01") {
		t.Errorf("ambiguous = %v, want the name reported", got.Ambiguous)
	}
}
