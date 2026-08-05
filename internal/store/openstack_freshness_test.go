package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A run that could not reach the control plane keeps the counts the last good
// one produced. Blanking them would report a farm as empty on the strength of a
// timeout — the same mistake the probe's error handling exists to avoid.
// Integration — needs VCTL_TEST_DSN.
func TestFailedRunKeepsTheLastGoodCounts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "fresh-farm-a"
	seedInstanceFarm(t, st, farm)
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_reconcile_runs WHERE deployment_id=$1`, farm)
	})

	good := ReconcileResult{Complete: true, Confirmed: []string{"a", "b"}, LocalOnly: []string{"c"}}
	if err := st.RecordReconcileRun(ctx, farm, good, time.Now().Add(-time.Hour), nil); err != nil {
		t.Fatalf("good run: %v", err)
	}
	if err := st.RecordReconcileRun(ctx, farm, ReconcileResult{}, time.Now(), errors.New("keystone unreachable")); err != nil {
		t.Fatalf("failed run: %v", err)
	}

	runs, err := st.ReconcileRuns(ctx)
	if err != nil {
		t.Fatalf("ReconcileRuns: %v", err)
	}
	r := runs[farm]
	if r.Confirmed != 2 || r.LocalOnly != 1 {
		t.Errorf("counts = %d/%d after a failure, want the last good run's", r.Confirmed, r.LocalOnly)
	}
	if r.SucceededAt == nil {
		t.Error("succeeded_at was cleared by a failure")
	}
	if r.LastError == "" {
		t.Error("the failure was not recorded")
	}
	// The pair is the signal: settled an hour ago, failing since.
	if !r.StartedAt.After(*r.SucceededAt) {
		t.Error("started_at does not show the failure came after the success")
	}
}

// A success clears the error, or a farm that recovered would look broken
// forever.
// Integration — needs VCTL_TEST_DSN.
func TestSuccessClearsTheError(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "fresh-farm-b"
	seedInstanceFarm(t, st, farm)
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_reconcile_runs WHERE deployment_id=$1`, farm)
	})

	if err := st.RecordReconcileRun(ctx, farm, ReconcileResult{}, time.Now().Add(-time.Hour), errors.New("boom")); err != nil {
		t.Fatalf("failed run: %v", err)
	}
	if err := st.RecordReconcileRun(ctx, farm, ReconcileResult{Complete: true}, time.Now(), nil); err != nil {
		t.Fatalf("good run: %v", err)
	}

	runs, _ := st.ReconcileRuns(ctx)
	if runs[farm].LastError != "" {
		t.Errorf("last_error = %q after a success", runs[farm].LastError)
	}
}

// first_seen_at survives later runs: "nova has been telling us about this for
// three weeks" is a registration somebody forgot, and "this appeared today" is
// a host being built.
// Integration — needs VCTL_TEST_DSN.
func TestControlHostKeepsWhenItWasFirstSeen(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "fresh-farm-c"
	seedInstanceFarm(t, st, farm)
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_control_hosts WHERE deployment_id=$1`, farm)
	})

	first := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	if err := st.RecordControlHosts(ctx, farm, []string{"ghost-1"}, first); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := st.RecordControlHosts(ctx, farm, []string{"ghost-1"}, time.Now()); err != nil {
		t.Fatalf("second: %v", err)
	}

	got, err := st.ControlHosts(ctx, farm)
	if err != nil || len(got) != 1 {
		t.Fatalf("ControlHosts: %v (%d rows)", err, len(got))
	}
	if !got[0].FirstSeenAt.Equal(first) {
		t.Errorf("first_seen_at = %v, want %v — the age is the whole signal", got[0].FirstSeenAt, first)
	}
}

// A ghost that gets registered stops being one. Keeping the row would leave a
// permanent list of problems already fixed.
// Integration — needs VCTL_TEST_DSN.
func TestControlHostDisappearsOnceItMatches(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "fresh-farm-d"
	seedInstanceFarm(t, st, farm)
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_control_hosts WHERE deployment_id=$1`, farm)
	})

	if err := st.RecordControlHosts(ctx, farm, []string{"ghost-2", "ghost-3"}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("first: %v", err)
	}
	// ghost-3 was registered, so the next run does not name it.
	if err := st.RecordControlHosts(ctx, farm, []string{"ghost-2"}, time.Now()); err != nil {
		t.Fatalf("second: %v", err)
	}

	got, _ := st.ControlHosts(ctx, farm)
	if len(got) != 1 || got[0].NovaHostname != "ghost-2" {
		t.Errorf("control hosts = %+v, want only the one still unmatched", got)
	}
}
