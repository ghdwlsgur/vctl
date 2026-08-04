package store

import (
	"slices"
	"testing"
	"time"
)

func capRow(host, role string, at time.Time, detected bool) capabilityRow {
	r := capabilityRow{DC: "test-dc", HostState: StateActive}
	r.Hostname, r.Role, r.Detected, r.ObservedAt = host, role, detected, at
	r.Components = map[string]CapabilityComponent{}
	r.Details = map[string]string{}
	return r
}

// Every role one probe pass finds carries that pass's timestamp, so the whole
// pass folds into one host record.
func TestFoldCollectsEveryRoleFromTheLatestPass(t *testing.T) {
	at := time.Now()
	rows := []capabilityRow{
		capRow("h1", "compute", at, true),
		capRow("h1", "network", at, true),
	}
	got := foldCapabilityRows(rows, nil)

	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1", len(got))
	}
	if !slices.Equal(got[0].Roles, []string{"compute", "network"}) {
		t.Errorf("roles = %v, want both roles of the same pass", got[0].Roles)
	}
	if len(got[0].Dropped) != 0 {
		t.Errorf("dropped = %v, want none — nothing has gone away", got[0].Dropped)
	}
}

// The agent has no DELETE on server_capabilities, so a role a host stops
// holding leaves its row behind forever. Reading it as current would keep a
// removed neutron agent in the listing indefinitely, and `--role network` would
// send someone to a host that has not run one in weeks.
func TestFoldSeparatesRolesTheLatestPassNoLongerFinds(t *testing.T) {
	now := time.Now()
	rows := []capabilityRow{
		capRow("h1", "compute", now, true),
		capRow("h1", "network", now.Add(-72*time.Hour), true),
	}
	got := foldCapabilityRows(rows, nil)

	if !slices.Equal(got[0].Roles, []string{"compute"}) {
		t.Errorf("roles = %v, want only what the latest pass found", got[0].Roles)
	}
	if len(got[0].Dropped) != 1 || got[0].Dropped[0].Role != "network" {
		t.Fatalf("dropped = %+v, want network", got[0].Dropped)
	}
	if !got[0].Dropped[0].LastSeen.Equal(now.Add(-72 * time.Hour)) {
		t.Error("the dropped role lost the time it was last seen, so its age cannot be judged")
	}
}

// A lagging row describes software the host no longer runs. Merging its
// components would resurrect versions of a package that has been removed, and
// the listing would report a release nothing on the machine is running.
func TestFoldIgnoresComponentsFromADroppedRole(t *testing.T) {
	now := time.Now()
	fresh := capRow("h1", "compute", now, true)
	fresh.Components["nova-compute"] = CapabilityComponent{Version: "31.2.0", Active: true}
	stale := capRow("h1", "network", now.Add(-30*24*time.Hour), true)
	stale.Components["neutron-l3-agent"] = CapabilityComponent{Version: "24.0.0", Active: true}

	got := foldCapabilityRows([]capabilityRow{fresh, stale}, nil)

	if _, ok := got[0].Components["neutron-l3-agent"]; ok {
		t.Errorf("a component from a role the host no longer holds survived: %+v", got[0].Components)
	}
	if got[0].Components["nova-compute"].Version != "31.2.0" {
		t.Errorf("components = %+v, want the latest pass's", got[0].Components)
	}
}

// "none" is how a probe files "I looked and found nothing". It is a real answer
// and needs a row, but it is not a role and must not be rendered as one.
func TestFoldDoesNotTreatTheAbsenceMarkerAsARole(t *testing.T) {
	got := foldCapabilityRows([]capabilityRow{capRow("h1", roleNone, time.Now(), false)}, nil)

	if len(got[0].Roles) != 0 {
		t.Errorf("roles = %v, want none", got[0].Roles)
	}
	if got[0].Detected {
		t.Error("a host with nothing on it was reported as detected")
	}
}

// A host that used to run nothing and now runs nova must not carry "none" into
// its dropped list, where it would read as a lost capability.
func TestFoldDropsTheAbsenceMarkerWhenSomethingIsFound(t *testing.T) {
	now := time.Now()
	got := foldCapabilityRows([]capabilityRow{
		capRow("h1", roleNone, now.Add(-24*time.Hour), false),
		capRow("h1", "compute", now, true),
	}, nil)

	if len(got[0].Dropped) != 0 {
		t.Errorf("dropped = %+v, want none — 'none' is not a role that was lost", got[0].Dropped)
	}
	if !got[0].Detected {
		t.Error("the newest pass found OpenStack and the host still reads as absent")
	}
}

// The probe writes deployment=unknown on purpose: local evidence cannot tell
// two farms behind one endpoint apart. Grouping on it would turn that refusal
// into a farm named "unknown" holding the whole fleet.
func TestFoldLeavesAHostUnassignedWithoutADeclaration(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "unknown"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "" {
		t.Errorf("farm = %q, want unassigned — the host cannot know this", got[0].Farm)
	}
}

// An identifier somebody placed on the host is a statement, not an inference,
// and is the one local fact allowed to decide membership.
func TestFoldAcceptsADeclaredDeployment(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "incheon-aio01"
	row.Details["deployment_source"] = "declared"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "incheon-aio01" {
		t.Errorf("farm = %q, want the declared id", got[0].Farm)
	}
	if got[0].Confidence != ConfidenceDeclared {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, ConfidenceDeclared)
	}
}

// A deployment id with no source did not come from a declaration. Treating it
// as one would let any value that reached the details map become a farm.
func TestFoldRejectsADeploymentIDWithNoDeclaredSource(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "guessed-from-keystone"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "" {
		t.Errorf("farm = %q, want unassigned — nothing declared this", got[0].Farm)
	}
}

// A membership row is written by whatever can see the control plane, so it
// outranks anything the host says about itself.
func TestFoldPrefersAMembershipOverTheHostsOwnClaim(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "stale-label"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "incheon-aio01", Confidence: ConfidenceConfirmed}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Farm != "incheon-aio01" || got[0].Confidence != ConfidenceConfirmed {
		t.Errorf("farm = %q/%q, want the confirmed membership", got[0].Farm, got[0].Confidence)
	}
}

// Two deployments claiming one host is a real state, not something to resolve
// by picking one. Silently choosing would hide a split-brain inventory.
func TestFoldFlagsAHostClaimedByTwoDeployments(t *testing.T) {
	members := map[string][]OpenStackMembership{
		"h1": {
			{DeploymentID: "farm-a", Confidence: ConfidenceConfirmed},
			{DeploymentID: "farm-b", Confidence: ConfidenceLocalOnly},
		},
	}
	got := foldCapabilityRows([]capabilityRow{capRow("h1", "compute", time.Now(), true)}, members)

	if got[0].Confidence != ConfidenceConflict {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, ConfidenceConflict)
	}
	if len(got[0].Memberships) != 2 {
		t.Errorf("memberships = %d, want both kept so the conflict can be read", len(got[0].Memberships))
	}
}
