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
		if _, err := st.ReplaceCapabilities(ctx, h, KindOpenStack, []Capability{{
			Role: "compute", Detected: true,
			Details: map[string]string{"keystone_url": keystone},
		}}); err != nil {
			t.Fatalf("seed capability for %s: %v", h, err)
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
		ObservedAt:   time.Now(), Complete: true,
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
		ObservedAt:   time.Now(), Complete: true,
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
		ObservedAt:   time.Now(), Complete: true,
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
		ObservedAt:   time.Now(), Complete: true,
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
		ObservedAt:   first, Complete: true,
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// 07 is gone from both sides on the next run.
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: "10.0.0.5:5000",
		LocalHosts:   []string{"recon-host-06"},
		ControlHosts: []string{"recon-host-06"},
		ObservedAt:   time.Now(), Complete: true,
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
		ObservedAt:   time.Now(), Complete: true,
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

// nova names hosts its own way, and shorter than the inventory in more than one
// way. The third case is why this exists: incheon names its hosts aio01/gpu01
// while the inventory qualifies them by site, and matching only exact and short
// names left all seven local-only — the deployment disowned every machine in it.
func TestMatchHostsPairsAcrossAnInventoryPrefix(t *testing.T) {
	local := []string{"incheon-aio01", "incheon-aio02", "incheon-gpu01"}
	control := []string{"aio01", "aio02", "gpu01"}

	pairs, ambiguous := MatchHosts(local, control)

	for inv, nova := range map[string]string{
		"incheon-aio01": "aio01", "incheon-aio02": "aio02", "incheon-gpu01": "gpu01",
	} {
		if pairs[inv] != nova {
			t.Errorf("%s paired with %q, want %q", inv, pairs[inv], nova)
		}
	}
	if len(ambiguous) != 0 {
		t.Errorf("ambiguous = %v, want none", ambiguous)
	}
}

// A name that fits several inventory hosts is refused, not guessed. Picking one
// would be an inventory claiming a machine on the strength of a resemblance.
func TestMatchHostsRefusesAnAmbiguousName(t *testing.T) {
	local := []string{"incheon-aio01", "seoul-aio01"}
	control := []string{"aio01"}

	pairs, ambiguous := MatchHosts(local, control)

	if len(pairs) != 0 {
		t.Errorf("pairs = %v, want none — the name fits two hosts", pairs)
	}
	if !slices.Contains(ambiguous, "aio01") {
		t.Errorf("ambiguous = %v, want the name reported", ambiguous)
	}
}

// An exact match must win before any looser rule can take the host.
func TestMatchHostsPrefersTheExactName(t *testing.T) {
	local := []string{"aio01", "incheon-aio01"}
	control := []string{"aio01"}

	pairs, _ := MatchHosts(local, control)

	if pairs["aio01"] != "aio01" {
		t.Errorf("pairs = %v, want the exact name to win", pairs)
	}
	if _, taken := pairs["incheon-aio01"]; taken {
		t.Errorf("pairs = %v — the suffix rule stole a host that had an exact match", pairs)
	}
}

// The boundary is required. Without it "u01" would match "sre-gpu01", and a
// name that merely ends in the same letters is not the same machine.
func TestMatchHostsRequiresASeparatorBeforeTheSuffix(t *testing.T) {
	pairs, _ := MatchHosts([]string{"sre-gpu01"}, []string{"u01"})

	if len(pairs) != 0 {
		t.Errorf("pairs = %v — matched on letters rather than on a name", pairs)
	}
}

// The domain-suffix case still works.
func TestMatchHostsStillPairsAcrossADomain(t *testing.T) {
	pairs, _ := MatchHosts([]string{"sre-srv-0059"}, []string{"sre-srv-0059.internal.example"})

	if pairs["sre-srv-0059"] != "sre-srv-0059.internal.example" {
		t.Errorf("pairs = %v, want the qualified nova name paired", pairs)
	}
}

// A farm's name and region are things a person set. The reconciler knows the
// endpoint and nothing else, so writing EXCLUDED unconditionally overwrote them
// with the empty strings it was not carrying — a farm named today was anonymous
// again six hours later, and nothing said so.
// Integration — needs VCTL_TEST_DSN.
func TestReconcileDoesNotEraseTheFarmName(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-name"
	seedFarmHosts(t, st, "10.0.0.7:5000", "recon-host-09")
	cleanupDeployment(t, st, farm)

	if err := st.SetDeploymentName(ctx, farm, "seoul-x", ptr("kr-seoul-9")); err != nil {
		t.Fatalf("SetDeploymentName: %v", err)
	}
	// The reconciler carries neither field, exactly as the CLI calls it.
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts: []string{"recon-host-09"}, ControlHosts: []string{"recon-host-09"},
		ObservedAt: time.Now(), Complete: true,
	}); err != nil {
		t.Fatalf("ReconcileDeployment: %v", err)
	}

	ds, err := st.Deployments(ctx)
	if err != nil {
		t.Fatalf("Deployments: %v", err)
	}
	for _, d := range ds {
		if d.ID != farm {
			continue
		}
		if d.DisplayName != "seoul-x" {
			t.Errorf("display_name = %q after a reconcile, want it preserved", d.DisplayName)
		}
		if d.Region != "kr-seoul-9" {
			t.Errorf("region = %q after a reconcile, want it preserved", d.Region)
		}
		return
	}
	t.Fatalf("%s disappeared from the deployments table", farm)
}

// Naming is still a write. Somebody passing an empty name is asking to clear
// it, and the preservation rule must not turn that into a no-op.
// Integration — needs VCTL_TEST_DSN.
func TestSetDeploymentNameCanStillClearIt(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-clear"
	cleanupDeployment(t, st, farm)

	if err := st.SetDeploymentName(ctx, farm, "temporary", ptr("kr-x")); err != nil {
		t.Fatalf("SetDeploymentName: %v", err)
	}
	if err := st.SetDeploymentName(ctx, farm, "", ptr("")); err != nil {
		t.Fatalf("SetDeploymentName(clear): %v", err)
	}
	ds, _ := st.Deployments(ctx)
	for _, d := range ds {
		if d.ID == farm && d.DisplayName != "" {
			t.Errorf("display_name = %q, want it cleared by an explicit empty name", d.DisplayName)
		}
	}
}

// A partial answer may not demote. os-services being refused hides every
// controller, so a run that trusted it would strip confirmation from the whole
// control plane and report a change in the deployment when what changed was one
// API call.
// Integration — needs VCTL_TEST_DSN.
func TestPartialAnswerDoesNotDemoteAConfirmedHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-partial"
	seedFarmHosts(t, st, "10.0.0.8:5000", "recon-host-10")
	cleanupDeployment(t, st, farm)

	// A complete run confirms it.
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts: []string{"recon-host-10"}, ControlHosts: []string{"recon-host-10"},
		ObservedAt: time.Now().Add(-time.Hour), Complete: true,
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if got := findOpenStackHost(t, st, "recon-host-10"); got.Confidence != ConfidenceConfirmed {
		t.Fatalf("precondition: confidence = %q", got.Confidence)
	}

	// The next run gets half an answer that happens not to name the host.
	got, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts: []string{"recon-host-10"}, ControlHosts: nil,
		ObservedAt: time.Now(), Complete: false,
	})
	if err != nil {
		t.Fatalf("partial reconcile: %v", err)
	}
	if !slices.Contains(got.Held, "recon-host-10") {
		t.Errorf("held = %v, want the host named as not demoted", got.Held)
	}
	if h := findOpenStackHost(t, st, "recon-host-10"); h.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q after a partial answer, want it held at confirmed", h.Confidence)
	}
}

// A complete answer that no longer names the host is real evidence, and must
// still demote — otherwise confirmation could never be withdrawn.
// Integration — needs VCTL_TEST_DSN.
func TestCompleteAnswerStillDemotes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-demote"
	seedFarmHosts(t, st, "10.0.0.11:5000", "recon-host-11")
	cleanupDeployment(t, st, farm)

	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts: []string{"recon-host-11"}, ControlHosts: []string{"recon-host-11"},
		ObservedAt: time.Now().Add(-time.Hour), Complete: true,
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts: []string{"recon-host-11"}, ControlHosts: nil,
		ObservedAt: time.Now(), Complete: true,
	}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	if h := findOpenStackHost(t, st, "recon-host-11"); h.Confidence != ConfidenceLocalOnly {
		t.Errorf("confidence = %q, want %q — a complete answer is evidence", h.Confidence, ConfidenceLocalOnly)
	}
}

// The stale sweep must not run on a partial answer either: a host missing from
// half a listing has not left the deployment.
// Integration — needs VCTL_TEST_DSN.
func TestPartialAnswerDoesNotSweepMemberships(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "recon-farm-sweep"
	seedFarmHosts(t, st, "10.0.0.12:5000", "recon-host-12", "recon-host-13")
	cleanupDeployment(t, st, farm)

	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts:   []string{"recon-host-12", "recon-host-13"},
		ControlHosts: []string{"recon-host-12", "recon-host-13"},
		ObservedAt:   time.Now().Add(-time.Hour), Complete: true,
	}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// A partial run that only saw one of them.
	if _, err := st.ReconcileDeployment(ctx, ReconcileInput{
		DeploymentID: farm, KeystoneURL: farm,
		LocalHosts:   []string{"recon-host-12", "recon-host-13"},
		ControlHosts: []string{"recon-host-12"},
		ObservedAt:   time.Now(), Complete: false,
	}); err != nil {
		t.Fatalf("partial reconcile: %v", err)
	}

	var n int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM openstack_memberships WHERE deployment_id=$1`, farm).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("%d memberships after a partial answer, want both kept", n)
	}
}

// ptr is for the optional region: nil means "leave it", and a pointer to any
// value — "" included — means "set it to this".
func ptr(s string) *string { return &s }

// Renaming a deployment must not drop its region.
//
// The write took a plain string, so an omitted --region arrived as "" and
// overwrote whatever was recorded. The command reads as changing a name, and a
// region disappearing from it is a change nobody asked for and nothing reports.
//
// nil is "leave it"; a pointer — "" included — is "set it to this", so clearing
// stays possible and stays explicit.
// Integration — needs VCTL_TEST_DSN.
func TestRenamingADeploymentKeepsItsRegion(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "region-farm-a"
	cleanupDeployment(t, st, farm)

	if err := st.SetDeploymentName(ctx, farm, "first", ptr("kr-inc-1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	// A rename with nothing said about the region.
	if err := st.SetDeploymentName(ctx, farm, "second", nil); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got := deploymentByID(t, st, farm)
	if got.Region != "kr-inc-1" {
		t.Errorf("region = %q after a rename that never mentioned it, want it kept", got.Region)
	}
	if got.DisplayName != "second" {
		t.Errorf("display name = %q, want the rename applied", got.DisplayName)
	}

	// Clearing is still possible, and still has to be asked for.
	if err := st.SetDeploymentName(ctx, farm, "second", ptr("")); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := deploymentByID(t, st, farm); got.Region != "" {
		t.Errorf("region = %q, want it cleared when asked for explicitly", got.Region)
	}
}

func deploymentByID(t *testing.T, st *Store, id string) Deployment {
	t.Helper()
	ds, err := st.Deployments(context.Background())
	if err != nil {
		t.Fatalf("Deployments: %v", err)
	}
	for _, d := range ds {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("no deployment %s", id)
	return Deployment{}
}
