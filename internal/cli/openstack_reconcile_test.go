package cli

import (
	"slices"

	"github.com/spf13/cobra"
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
	// kv/teams/sre is shared with everything else the team stores there.
	if !strings.HasPrefix(got, "vctl-") {
		t.Errorf("key = %q, want the vctl- prefix that keeps these apart", got)
	}
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

// reconcile must not be app-gated. A CronJob authenticating with kubernetes
// auth has no per-person identity, and the gate opened the inventory with
// vctl-ro — a role this workload has no reason to hold. It failed before the
// command it guards could run:
//
//	rbac: 'openstack-reconcile' needs the inventory database and it is
//	unreachable: database/creds/vctl-ro: permission denied
//
// Vault is the boundary instead: kv/teams/sre/vctl-* and database/creds/vctl-rw.
func TestReconcileIsNotAppGated(t *testing.T) {
	var found *cobra.Command
	for _, c := range openstackCmd().Commands() {
		if c.Name() == "reconcile" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("reconcile is not registered under openstack")
	}
	if name := found.Annotations["rbac.command"]; name != "" {
		t.Errorf("reconcile carries the rbac annotation %q; the gate needs an identity a CronJob does not have", name)
	}
}
