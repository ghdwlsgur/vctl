package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A Kubernetes node names its VM as openstack:///<uuid>. Making somebody strip
// that by hand before pasting is the kind of friction that ends in the wrong
// substring being pasted.
func TestProviderIDIsAcceptedAsAnInstanceID(t *testing.T) {
	const uuid = "3de58d36-190f-40b5-9f69-5a6361e3351c"
	for _, in := range []string{uuid, "openstack:///" + uuid, "  openstack:///" + uuid + "  "} {
		if got := normalizeInstanceID(in); got != uuid {
			t.Errorf("normalizeInstanceID(%q) = %q", in, got)
		}
	}
}

// The floating address is the one somebody reaches the VM on, so it leads.
func TestPrimaryAddressPrefersFloating(t *testing.T) {
	v := store.Instance{Addresses: []store.InstanceAddress{
		{Address: "10.0.0.5", Type: "fixed"},
		{Address: "192.0.2.9", Type: "floating"},
	}}
	if got := primaryAddress(v); !strings.Contains(got, "192.0.2.9") {
		t.Errorf("primaryAddress = %q, want the floating one", got)
	}
}

// With only fixed addresses the first is shown and the rest counted, the same
// trade the host listing makes for multi-homed machines.
func TestPrimaryAddressCountsTheRest(t *testing.T) {
	v := store.Instance{Addresses: []store.InstanceAddress{
		{Address: "10.0.0.5", Type: "fixed"},
		{Address: "10.0.1.5", Type: "fixed"},
	}}
	got := primaryAddress(v)
	if !strings.Contains(got, "10.0.0.5") || !strings.Contains(got, "+1") {
		t.Errorf("primaryAddress = %q, want the first and a count", got)
	}
}

// A VM stuck mid-operation is neither running nor stopped, and reporting it as
// ACTIVE hides the only interesting thing about it.
func TestVMStateLeadsWithTheTaskState(t *testing.T) {
	v := store.Instance{Status: "ACTIVE", PowerState: "running", TaskState: "migrating"}
	if got := vmStateCell(v); !strings.Contains(got, "migrating") {
		t.Errorf("state = %q, want the task state", got)
	}
}

// The API and the hypervisor disagreeing is worth seeing rather than smoothing
// over: ACTIVE with a stopped power state is a VM nova thinks is up.
func TestVMStateShowsAPowerStateThatDisagrees(t *testing.T) {
	v := store.Instance{Status: "ACTIVE", PowerState: "shutdown"}
	got := vmStateCell(v)
	if !strings.Contains(got, "ACTIVE") || !strings.Contains(got, "shutdown") {
		t.Errorf("state = %q, want both halves of the disagreement", got)
	}
}

// A VM the control plane no longer lists is shown with how long it has been
// gone — the row is kept precisely so that question can be answered.
func TestMissingVMShowsHowLongItHasBeenGone(t *testing.T) {
	gone := time.Now().Add(-3 * time.Hour)
	v := store.Instance{InstanceID: "uuid-x", Name: "ghost", MissingSince: &gone}

	var buf bytes.Buffer
	renderVMs(&buf, []store.Instance{v}, nil, time.Now())
	if !strings.Contains(buf.String(), "gone") {
		t.Errorf("a missing VM was not marked:\n%s", buf.String())
	}
}

// A VM with no name still has to be identifiable, and the UUID is the only
// thing it definitely has.
func TestUnnamedVMFallsBackToItsUUID(t *testing.T) {
	if got := nameOrID(store.Instance{InstanceID: "uuid-y"}); got != "uuid-y" {
		t.Errorf("nameOrID = %q", got)
	}
}

// The project column falls back to the id. A farm collected before names were
// resolved has the id and nothing else, and a blank cell would read as "no
// owner" rather than "not looked up yet".
func TestProjectLabelFallsBackToTheID(t *testing.T) {
	if got := vmProjectLabel(store.Instance{ProjectID: "abc", ProjectName: "platform"}); got != "platform" {
		t.Errorf("with a name: got %q, want platform", got)
	}
	if got := vmProjectLabel(store.Instance{ProjectID: "abc"}); got != "abc" {
		t.Errorf("without a name: got %q, want the id", got)
	}
}

// An unnamed farm is grouped under its endpoint, not under a placeholder. The
// endpoint is a real answer to "which deployment is this".
func TestFarmLabelFallsBackToTheEndpoint(t *testing.T) {
	names := map[string]string{"a": "lab-a"}
	if got := vmFarmLabel("a", names); got != "lab-a" {
		t.Errorf("named farm: got %q", got)
	}
	if got := vmFarmLabel("172.29.0.100:5000", names); got != "172.29.0.100:5000" {
		t.Errorf("unnamed farm: got %q, want the endpoint", got)
	}
}
