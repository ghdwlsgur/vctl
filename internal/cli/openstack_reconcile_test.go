package cli

import (
	"slices"
	"strings"
	"testing"
)

// A dry run must decide exactly what a real run decides. If they differ, the
// preview is worse than not having one — it invites approving a change that
// then does something else.
func TestDryRunMatchesTheRealMatchingRule(t *testing.T) {
	got := previewReconcile(
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
	got := previewReconcile([]string{"a", "b"}, []string{"a", "b"})

	if len(got.LocalOnly) != 0 || len(got.ControlOnly) != 0 {
		t.Errorf("disagreements = %v / %v, want none", got.LocalOnly, got.ControlOnly)
	}
}

// A farm with sixty confirmed hosts should not print sixty names to say it
// agreed.
func TestCountAndNamesAFewAndCountsTheRest(t *testing.T) {
	many := []string{"a", "b", "c", "d", "e", "f"}
	got := countAnd(many)

	if !strings.HasPrefix(got, "6 · ") {
		t.Errorf("countAnd = %q, want the count first", got)
	}
	if !strings.Contains(got, "+2 more") {
		t.Errorf("countAnd = %q, want the remainder counted rather than listed", got)
	}
	if got := countAnd(nil); got != "none" {
		t.Errorf("countAnd(nil) = %q", got)
	}
}

// A colon in a Vault path is legal but awkward everywhere it is then typed.
// The port still has to survive: two deployments can share an address.
func TestVaultFarmKeyIsTypeableAndKeepsThePort(t *testing.T) {
	got := vaultFarmKey("172.16.0.245:5000")
	if strings.Contains(got, ":") {
		t.Errorf("key = %q, still carries a colon", got)
	}
	if !strings.Contains(got, "5000") {
		t.Errorf("key = %q, lost the port — two deployments can share an address", got)
	}
	if vaultFarmKey("10.0.0.1:5000") == vaultFarmKey("10.0.0.1:5001") {
		t.Error("two ports on one address collapsed into one key")
	}
}
