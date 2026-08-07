package store

import (
	"context"
	"testing"
)

// The listing answers "what is the fleet running". A host somebody put in a
// maintenance window, or retired, is not an answer to that — it is a decision
// already made, and repeating it as a finding argues with the operator every
// time they read the table.
func TestParkedIsMaintenanceAndRetiredOnly(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  bool
	}{
		{StateActive, false},
		{"", false}, // empty means active
		{StateBroken, false},
		{StateMaintenance, true},
		{StateRetired, true},
	} {
		if got := (OpenStackHost{HostState: tc.state}).Parked(); got != tc.want {
			t.Errorf("state %q: parked = %v, want %v", tc.state, got, tc.want)
		}
	}
}

// Broken is the one that must stay visible. It is a fault somebody diagnosed
// and has not fixed; hiding it would turn the listing into a record of what
// people remembered to look at.
func TestBrokenStaysInService(t *testing.T) {
	in := []OpenStackHost{
		{Hostname: "a", HostState: StateBroken},
		{Hostname: "b", HostState: StateMaintenance},
	}
	out := InService(in, nil)
	if len(out) != 1 || out[0].Hostname != "a" {
		t.Fatalf("InService kept %v, want only the broken host", hostnames(out))
	}
}

// A farm whose hosts are all parked has to disappear from the listing entirely,
// not shrink to a header with nothing under it. The listing groups by farm from
// the host rows, so this is the whole mechanism — if InService drops every host
// of a deployment, nothing is left to group.
func TestAFarmOfOnlyParkedHostsLeavesNothingToGroup(t *testing.T) {
	in := []OpenStackHost{
		{Hostname: "keep", Farm: "live", HostState: StateActive},
		{Hostname: "gone-1", Farm: "parked", HostState: StateMaintenance},
		{Hostname: "gone-2", Farm: "parked", HostState: StateRetired},
	}
	for _, h := range InService(in, nil) {
		if h.Farm == "parked" {
			t.Fatalf("%s survived, so the parked farm still has a row to group under", h.Hostname)
		}
	}
}

// Coverage is a fraction of the fleet something is expected of, and nothing is
// expected of a parked machine — counting it would leave coverage permanently
// short of complete with no way to finish it.
//
// The denominator is read here now, alongside everything it is compared with,
// so the summary and the table cannot come from different moments.
// Integration — needs VCTL_TEST_DSN.
func TestFleetSnapshotDenominatorExcludesMaintenanceHosts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOpenStackHost(t, st, "os-parked-01", StateActive)

	before, err := st.FleetSnapshot(ctx)
	if err != nil {
		t.Fatalf("FleetSnapshot: %v", err)
	}
	seedOpenStackHost(t, st, "os-parked-02", StateMaintenance)
	after, err := st.FleetSnapshot(ctx)
	if err != nil {
		t.Fatalf("FleetSnapshot: %v", err)
	}

	if after.InventoryHosts != before.InventoryHosts {
		t.Errorf("adding a host in maintenance moved the denominator from %d to %d",
			before.InventoryHosts, after.InventoryHosts)
	}
}

// A farm nobody operates goes even though its hosts are perfectly healthy.
// This is the farm-level key: two deployments here are hardware that exists and
// is not being run, and their compute nodes are not in maintenance.
func TestRetiredDeploymentTakesItsHostsOffTheListing(t *testing.T) {
	in := []OpenStackHost{
		{Hostname: "live", Farm: "d-live", HostState: StateActive},
		{Hostname: "shelved", Farm: "d-gone", HostState: StateActive},
	}
	deps := []Deployment{
		{ID: "d-live", State: StateActive},
		{ID: "d-gone", State: StateRetired},
	}
	out := InService(in, deps)
	if len(out) != 1 || out[0].Hostname != "live" {
		t.Fatalf("InService kept %v, want only the host of the live farm", hostnames(out))
	}
}

// One controller in a maintenance window must not take its farm off the
// listing. That is the moment somebody most wants to see the other two.
func TestOneParkedHostDoesNotHideItsFarm(t *testing.T) {
	in := []OpenStackHost{
		{Hostname: "c1", Farm: "d", HostState: StateMaintenance},
		{Hostname: "c2", Farm: "d", HostState: StateActive},
		{Hostname: "c3", Farm: "d", HostState: StateActive},
	}
	out := InService(in, []Deployment{{ID: "d", State: StateActive}})
	if len(out) != 2 {
		t.Fatalf("InService kept %v, want the two hosts still in service", hostnames(out))
	}
}

func hostnames(hosts []OpenStackHost) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Hostname)
	}
	return out
}
