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
	// Even against an operator network: floating exists because somebody
	// attached it to make the VM reachable, which beats a guess from a prefix.
	if got := primaryAddress(v, []string{"10.0.0."}); !strings.Contains(got, "192.0.2.9") {
		t.Errorf("primaryAddress = %q, want the floating one", got)
	}
}

// A VM answers on a tenant network that does not route past its own farm and on
// one an operator can open. Leading with whichever nova listed first was right
// by accident, and the address column is the one people copy out of.
func TestPrimaryAddressPrefersTheOperatorNetwork(t *testing.T) {
	v := store.Instance{Addresses: []store.InstanceAddress{
		{Address: "10.3.1.115", Type: "fixed"},
		{Address: "192.168.201.207", Type: "fixed"},
	}}
	if got := primaryAddress(v, []string{"192.168."}); !strings.Contains(got, "192.168.201.207") {
		t.Errorf("primaryAddress = %q, want the operator-network one", got)
	}
	// With nothing configured there is no preference to apply, and the listing
	// must still show an address rather than nothing.
	if got := primaryAddress(v, nil); got == "" {
		t.Error("primaryAddress gave nothing when no operator network is configured")
	}
}

// With only fixed addresses the first is shown and the rest counted, the same
// trade the host listing makes for multi-homed machines.
func TestPrimaryAddressCountsTheRest(t *testing.T) {
	v := store.Instance{Addresses: []store.InstanceAddress{
		{Address: "10.0.0.5", Type: "fixed"},
		{Address: "10.0.1.5", Type: "fixed"},
	}}
	got := primaryAddress(v, nil)
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
	renderVMs(&buf, []store.Instance{v}, nil, nil, time.Now(), false)
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

// The table prints a project's name and --project used to take only its id, so
// the value on screen was not a value the flag accepted. Copying what you can
// see returned an empty listing — which reads as "this project has no VMs".
func TestProjectSelectorTakesTheNameTheTableShows(t *testing.T) {
	projects := []store.Project{
		{DeploymentID: "farm-a", ID: "1111", Name: "admin", VMs: 4},
		{DeploymentID: "farm-b", ID: "2222", Name: "admin", VMs: 6},
		{DeploymentID: "farm-a", ID: "3333", Name: "platform", VMs: 2},
		// Named "1111" on purpose: an id has to win over a name that copies it.
		{DeploymentID: "farm-b", ID: "4444", Name: "1111", VMs: 1},
	}

	t.Run("a name in one farm resolves to that project", func(t *testing.T) {
		ids, note, err := pickProjects(projects, "", "platform")
		if err != nil {
			t.Fatalf("platform: %v", err)
		}
		if len(ids) != 1 || ids[0] != "3333" {
			t.Fatalf("got %v, want [3333]", ids)
		}
		if note != "" {
			t.Errorf("unambiguous selector should say nothing, got %q", note)
		}
	})

	t.Run("case does not have to be guessed", func(t *testing.T) {
		ids, _, err := pickProjects(projects, "", "Platform")
		if err != nil || len(ids) != 1 || ids[0] != "3333" {
			t.Fatalf("got %v, %v", ids, err)
		}
	})

	t.Run("a name in every farm selects them all and says so", func(t *testing.T) {
		// Not a refusal. Each Keystone has its own "admin", the listing groups
		// by farm and prints the name on every row, so showing both answers the
		// question and shows its own scope.
		ids, note, err := pickProjects(projects, "", "admin")
		if err != nil {
			t.Fatalf("admin: %v", err)
		}
		if len(ids) != 2 {
			t.Fatalf("got %v, want both admin projects", ids)
		}
		if !strings.Contains(note, "2 farms") || !strings.Contains(note, "--farm") {
			t.Errorf("note should say how wide it went and how to narrow: %q", note)
		}
	})

	t.Run("--farm narrows what a name has to be unique within", func(t *testing.T) {
		ids, note, err := pickProjects(projects[:1], "farm-a", "admin")
		if err != nil {
			t.Fatalf("admin in farm-a: %v", err)
		}
		if len(ids) != 1 || ids[0] != "1111" || note != "" {
			t.Fatalf("got %v note=%q, want [1111] and no note", ids, note)
		}
	})

	t.Run("an id wins over a project named after it", func(t *testing.T) {
		ids, _, err := pickProjects(projects, "", "1111")
		if err != nil {
			t.Fatalf("1111: %v", err)
		}
		if len(ids) != 1 || ids[0] != "1111" {
			t.Fatalf("got %v, want the project whose id is 1111", ids)
		}
	})

	t.Run("nothing matching is an error, not an empty table", func(t *testing.T) {
		// An empty listing looks like an answer, and "this project has no VMs"
		// is a very different sentence from "there is no such project".
		_, _, err := pickProjects(projects, "", "typo")
		if err == nil {
			t.Fatal("a selector matching nothing was accepted")
		}
		if !strings.Contains(err.Error(), "typo") {
			t.Errorf("error should quote what was typed: %v", err)
		}
	})

	t.Run("the error names the farm when one was given", func(t *testing.T) {
		_, _, err := pickProjects(nil, "farm-a", "admin")
		if err == nil || !strings.Contains(err.Error(), "farm-a") {
			t.Errorf("error should say where it looked: %v", err)
		}
	})
}
