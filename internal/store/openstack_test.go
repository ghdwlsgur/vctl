package store

import (
	"context"
	"testing"
)

func seedOpenStackHost(t *testing.T, st *Store, host, state string) {
	t.Helper()
	ctx := context.Background()
	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.91", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert %s: %v", host, err)
	}
	if state != "" && state != StateActive {
		if _, err := st.SetState(ctx, host, state); err != nil {
			t.Fatalf("SetState %s: %v", host, err)
		}
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_memberships WHERE hostname=$1`, host)
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_capabilities WHERE hostname=$1`, host)
		_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	})
}

// The listing has to fold the per-role rows back into one host and carry the
// membership with them.
// Integration — needs VCTL_TEST_DSN.
func TestOpenStackHostsJoinsRolesAndMembership(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "os-host-01"
	const farm = "test-farm-a"
	seedOpenStackHost(t, st, host, StateActive)

	if _, err := st.pool.Exec(ctx,
		`INSERT INTO openstack_deployments (id, display_name, region) VALUES ($1,$2,$3)
		 ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name`,
		farm, "Test Farm A", "kr-test-1"); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM openstack_deployments WHERE id=$1`, farm) })
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO openstack_memberships (hostname, deployment_id, confidence) VALUES ($1,$2,$3)
		 ON CONFLICT (hostname, deployment_id) DO UPDATE SET confidence=EXCLUDED.confidence`,
		host, farm, ConfidenceConfirmed); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	caps := make([]Capability, 0, 2)
	for _, role := range []string{"compute", "network"} {
		caps = append(caps, Capability{
			Role: role, Detected: true,
			Components: map[string]CapabilityComponent{"nova-compute": {Version: "31.2.0", Active: true}},
			Details:    map[string]string{"deployment": "unknown"},
		})
	}
	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack, caps); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	got := findOpenStackHost(t, st, host)
	if len(got.Roles) != 2 {
		t.Errorf("roles = %v, want both", got.Roles)
	}
	if got.Farm != farm || got.FarmName != "Test Farm A" || got.FarmRegion != "kr-test-1" {
		t.Errorf("farm = %q/%q/%q, want the joined deployment", got.Farm, got.FarmName, got.FarmRegion)
	}
	if got.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", got.Confidence, ConfidenceConfirmed)
	}
	if got.DC != "test-dc" {
		t.Errorf("dc = %q, want the inventory's", got.DC)
	}
}

// What an operator declared about the host travels with the capability, so the
// listing can say whether a silent probe is news.
// Integration — needs VCTL_TEST_DSN.
func TestOpenStackHostsCarriesTheDeclaredHostState(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "os-host-02"
	seedOpenStackHost(t, st, host, StateMaintenance)

	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack,
		[]Capability{{Role: "compute", Detected: true}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	if got := findOpenStackHost(t, st, host).HostState; got != StateMaintenance {
		t.Errorf("host state = %q, want %q — a host under maintenance reads differently", got, StateMaintenance)
	}
}

// A retired host is one nothing is expected of. Counting it against probe
// coverage would leave the fleet permanently short of complete.
// Integration — needs VCTL_TEST_DSN.
func TestOpenStackCoverageExcludesRetiredHosts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	seedOpenStackHost(t, st, "os-host-03", StateActive)

	before, err := st.coverageNow(ctx, t)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	seedOpenStackHost(t, st, "os-host-04", StateRetired)
	after, err := st.coverageNow(ctx, t)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}

	if after.Hosts != before.Hosts {
		t.Errorf("adding a retired host moved the denominator from %d to %d", before.Hosts, after.Hosts)
	}
}

// Probed-and-absent must count as probed. Folding it into "never probed" would
// send someone to redeploy an agent that is working correctly.
// Integration — needs VCTL_TEST_DSN.
func TestOpenStackCoverageSeparatesAbsentFromUnprobed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "os-host-05"
	seedOpenStackHost(t, st, host, StateActive)

	before, err := st.coverageNow(ctx, t)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack,
		[]Capability{{Role: roleNone}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	after, err := st.coverageNow(ctx, t)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}

	if after.Probed != before.Probed+1 {
		t.Errorf("probed went %d -> %d, want +1 — looking and finding nothing is still looking", before.Probed, after.Probed)
	}
	if after.Running != before.Running {
		t.Errorf("running went %d -> %d, want unchanged", before.Running, after.Running)
	}
	if after.Absent != before.Absent+1 {
		t.Errorf("absent went %d -> %d, want +1", before.Absent, after.Absent)
	}
}

func findOpenStackHost(t *testing.T, st *Store, host string) OpenStackHost {
	t.Helper()
	hosts, err := st.OpenStackHosts(context.Background())
	if err != nil {
		t.Fatalf("OpenStackHosts: %v", err)
	}
	for _, h := range hosts {
		if h.Hostname == host {
			return h
		}
	}
	t.Fatalf("%s not in the listing", host)
	return OpenStackHost{}
}

// coverageNow reads the coverage the way the command does: over the folded
// hosts, so the summary cannot disagree with the table above it.
func (s *Store) coverageNow(ctx context.Context, t *testing.T) (OpenStackCoverage, error) {
	t.Helper()
	hosts, err := s.OpenStackHosts(ctx)
	if err != nil {
		return OpenStackCoverage{}, err
	}
	return s.OpenStackCoverageOf(ctx, hosts)
}

// The summary and the table read the same folded hosts. They were two queries
// once, and they disagreed: a controller whose earlier probes failed and whose
// latest one succeeded showed nine roles in the table and "1 could not be
// probed" underneath it, because the stale row was still in the table the
// summary counted.
// Integration — needs VCTL_TEST_DSN.
func TestCoverageAgreesWithTheListingAfterAFailureIsSuperseded(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "os-host-06"
	seedOpenStackHost(t, st, host, StateActive)

	// A probe fails before anything is known, then a later one succeeds.
	if err := st.RecordCapabilityError(ctx, host, KindOpenStack, "probe timed out"); err != nil {
		t.Fatalf("RecordCapabilityError: %v", err)
	}
	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack,
		[]Capability{{Role: "compute", Detected: true}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	got := findOpenStackHost(t, st, host)
	if !got.Detected || got.LastError != "" {
		t.Fatalf("the listing still carries the superseded failure: detected=%v err=%q", got.Detected, got.LastError)
	}
	before, err := st.coverageNow(ctx, t)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	// The host counts as running, and its old error must not also count as a
	// failure — the two together would report it twice, in contradiction.
	if before.Running+before.Failed+before.Absent != before.Probed {
		t.Errorf("counts do not add up: running=%d failed=%d absent=%d probed=%d",
			before.Running, before.Failed, before.Absent, before.Probed)
	}
}

// One farm screen is built from one read, so it describes one moment.
//
// It used to be five independent reads: hosts, instances, control hosts,
// reconcile runs, deployments. A reconcile landing between the second and the
// third put a host count from before it beside a run result from after it, and
// nothing rendered says which number came from when.
// Integration — needs VCTL_TEST_DSN.
func TestFarmSnapshotReadsThePartsTogether(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "snap-host-01"
	const farm = "snap-farm-a"
	seedOpenStackHost(t, st, host, StateActive)
	cleanupDeployment(t, st, farm)

	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack, []Capability{
		{Role: "controller", Detected: true},
		{Role: "compute", Detected: true},
	}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO openstack_deployments (id, display_name) VALUES ($1,$2)
		 ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name`,
		farm, "snap-farm"); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO openstack_memberships (hostname, deployment_id, confidence) VALUES ($1,$2,$3)
		 ON CONFLICT (hostname, deployment_id) DO UPDATE SET confidence=EXCLUDED.confidence`,
		host, farm, ConfidenceConfirmed); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if err := st.SetDeploymentState(ctx, farm, StateBroken, "rabbit is down"); err != nil {
		t.Fatalf("SetDeploymentState: %v", err)
	}

	snap, err := st.FarmSnapshot(ctx, farm)
	if err != nil {
		t.Fatalf("FarmSnapshot: %v", err)
	}
	if len(snap.Hosts) != 1 || snap.Hosts[0].Hostname != host {
		t.Errorf("hosts = %+v, want just %s", snap.Hosts, host)
	}
	if !snap.DeploymentKnown {
		t.Fatal("the deployment row was not read")
	}
	// The note is what the caller used to lose silently when this read failed.
	if snap.Deployment.StateNote != "rabbit is down" {
		t.Errorf("state note = %q, want what was declared", snap.Deployment.StateNote)
	}
	if snap.Deployment.StateChangedAt.IsZero() {
		t.Error("the declaration has no date; a note without one is unreadable a week later")
	}
}

// "Never named" and "the read failed" are different, and the caller used to
// conflate them by discarding the error.
//
// The first of those is the ordinary state of a farm before anyone reconciles
// it: the host points at a Keystone, that URL is the deployment id, and no
// openstack_deployments row exists yet. A membership cannot stand in for it —
// the foreign key means a membership only exists once the deployment row does,
// which is what a first draft of this test got wrong.
// Integration — needs VCTL_TEST_DSN.
func TestFarmSnapshotSeparatesUnnamedFromUnread(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "snap-host-02"
	const farm = "10.90.0.9:5000" // a Keystone nobody has reconciled
	seedOpenStackHost(t, st, host, StateActive)

	if _, err := st.ReplaceCapabilities(ctx, host, KindOpenStack, []Capability{{
		Role: "compute", Detected: true,
		Details: map[string]string{"keystone_url": farm},
	}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	snap, err := st.FarmSnapshot(ctx, farm)
	if err != nil {
		t.Fatalf("FarmSnapshot on an unnamed deployment: %v", err)
	}
	if snap.DeploymentKnown {
		t.Error("a deployment nobody named was reported as read")
	}
	if len(snap.Hosts) != 1 || snap.Hosts[0].Hostname != host {
		t.Errorf("hosts = %+v, want the host to survive having no deployment row", snap.Hosts)
	}
}
