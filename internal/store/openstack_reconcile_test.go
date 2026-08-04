package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

// seedFarmHosts registers hosts and files the probe result that would have put
// them on the reconciler's work list.
//
// Both are needed because that is the real order: LocalOnlyFarms reads the
// capability rows to decide which hosts to ask the control plane about, so a
// host with no probe result never reaches a reconcile at all.
func seedFarmHosts(t *testing.T, st *Store, keystone string, hosts ...string) {
	t.Helper()
	ctx := context.Background()
	for _, h := range hosts {
		seedOpenStackHost(t, st, h, StateActive)
		if _, err := st.UpsertCapability(ctx, Capability{
			Hostname: h, Kind: KindOpenStack, Role: "compute", Detected: true,
			Details:    map[string]string{"keystone_url": keystone},
			ObservedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed capability %s: %v", h, err)
		}
	}
}

func cleanupDeployment(t *testing.T, st *Store, id string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_memberships WHERE deployment_id=$1`, id)
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_deployments WHERE id=$1`, id)
	})
}

// Agreement is the only thing that promotes to confirmed. Pointing at a
// Keystone does not prove membership — two deployments behind one proxy look
// identical from a host — and this is the step that settles it.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileConfirmsWhenBothSidesAgree(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-a"
	seedFarmHosts(t, st, "10.0.0.1:5000", "recon-host-01", "recon-host-02")
	cleanupDeployment(t, st, farm)

	got, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.1:5000",
		LocalHosts:   []string{"recon-host-01", "recon-host-02"},
		ControlHosts: []string{"recon-host-01", "recon-host-02"},
		ObservedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}
	if len(got.Confirmed) != 2 {
		t.Errorf("confirmed = %v, want both hosts", got.Confirmed)
	}

	h := findOpenStackHost(t, st, "recon-host-01")
	if h.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", h.Confidence, ConfidenceConfirmed)
	}
	if h.Farm != farm {
		t.Errorf("farm = %q, want the reconciled deployment", h.Farm)
	}
}

// A host the probe found but the control plane does not list stays local-only.
// Promoting it would be the failure this whole column exists to prevent.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileLeavesAnUnconfirmedHostAlone(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-b"
	seedFarmHosts(t, st, "10.0.0.2:5000", "recon-host-03")
	cleanupDeployment(t, st, farm)

	got, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.2:5000",
		LocalHosts:   []string{"recon-host-03"},
		ControlHosts: []string{"some-other-host"},
		ObservedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}
	if !slices.Contains(got.LocalOnly, "recon-host-03") {
		t.Errorf("local-only = %v, want the unconfirmed host", got.LocalOnly)
	}
	if len(got.Confirmed) != 0 {
		t.Errorf("confirmed = %v, want none — the control plane never named it", got.Confirmed)
	}
	if h := findOpenStackHost(t, st, "recon-host-03"); h.Confidence != ConfidenceLocalOnly {
		t.Errorf("confidence = %q, want %q", h.Confidence, ConfidenceLocalOnly)
	}
}

// nova writes its own hostnames. A short name must meet a fully-qualified
// inventory entry, and no looser than that — pairing by resemblance is how an
// inventory starts claiming the wrong machines.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileMatchesShortAndQualifiedNames(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-c"
	seedFarmHosts(t, st, "10.0.0.3:5000", "recon-host-04")
	cleanupDeployment(t, st, farm)

	got, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.3:5000",
		LocalHosts: []string{"recon-host-04"},
		// nova reports it qualified; the inventory holds the short name.
		ControlHosts: []string{"recon-host-04.internal.example"},
		ObservedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}
	if !slices.Contains(got.Confirmed, "recon-host-04") {
		t.Errorf("confirmed = %v, want the host matched across the domain suffix", got.Confirmed)
	}
}

// A host nova lists that no probe found is reported, not written. A membership
// needs an inventory host, and by definition this one has none.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileReportsControlOnlyHostsWithoutInventingThem(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-d"
	seedFarmHosts(t, st, "10.0.0.4:5000", "recon-host-05")
	cleanupDeployment(t, st, farm)

	got, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.4:5000",
		LocalHosts:   []string{"recon-host-05"},
		ControlHosts: []string{"recon-host-05", "ghost-node-99"},
		ObservedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}
	if !slices.Contains(got.ControlOnly, "ghost-node-99") {
		t.Errorf("control-only = %v, want the unmatched nova host reported", got.ControlOnly)
	}
	var n int
	_ = st.pool.QueryRow(ctx,
		`SELECT count(*) FROM openstack_memberships WHERE hostname='ghost-node-99'`).Scan(&n)
	if n != 0 {
		t.Error("a membership was written for a host that is not in the inventory")
	}
}

// A host that leaves a deployment must stop being confirmed by it. Keeping the
// row would leave it confirmed against evidence that no longer exists.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileDropsAHostThatLeftTheDeployment(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-e"
	seedFarmHosts(t, st, "10.0.0.5:5000", "recon-host-06", "recon-host-07")
	cleanupDeployment(t, st, farm)

	first := time.Now().Add(-time.Hour)
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.5:5000",
		LocalHosts:   []string{"recon-host-06", "recon-host-07"},
		ControlHosts: []string{"recon-host-06", "recon-host-07"},
		ObservedAt:   first,
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// 07 is gone from both sides on the next run.
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.5:5000",
		LocalHosts:   []string{"recon-host-06"},
		ControlHosts: []string{"recon-host-06"},
		ObservedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var n int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM openstack_memberships WHERE deployment_id=$1 AND hostname='recon-host-07'`,
		farm).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Error("a host that left the deployment is still confirmed by it")
	}
}

// The reconciled membership outranks the probe's Keystone inference, which is
// the point of running it.
// Integration — needs VCTL_TEST_DSN.
func TestReconciledMembershipOutranksTheLocalInference(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-f"
	const host = "recon-host-08"
	// The probe inferred a farm from the Keystone it saw.
	seedFarmHosts(t, st, "10.0.0.6:5000", host)
	cleanupDeployment(t, st, farm)

	if got := findOpenStackHost(t, st, host); got.Confidence != ConfidenceLocalOnly {
		t.Fatalf("precondition: confidence = %q, want local-only", got.Confidence)
	}

	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, DisplayName: "Farm F", KeystoneURL: "10.0.0.6:5000",
		LocalHosts:   []string{host},
		ControlHosts: []string{host},
		ObservedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}

	got := findOpenStackHost(t, st, host)
	if got.Farm != farm || got.Confidence != ConfidenceConfirmed {
		t.Errorf("farm = %q/%q, want the confirmed membership to win", got.Farm, got.Confidence)
	}
	if got.FarmName != "Farm F" {
		t.Errorf("farm name = %q, want the deployment's", got.FarmName)
	}
}
