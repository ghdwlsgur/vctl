package store

import (
	"context"
	"testing"
)

// The two agent metrics survive a round trip, and absent stays absent.
//
// The distinction is the point. An agent that predates these columns writes
// nothing, and a host can genuinely have zero of either; a reader that cannot
// tell them apart reports a fleet that stopped measuring as a fleet measuring
// zero.
func TestAgentMetricsRoundTripAndKeepAbsentDistinctFromZero(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "sre-test-agentmetrics"

	if _, err := st.Insert(ctx, Server{Hostname: host, IP: "10.9.9.9", Port: 22, User: "root", DC: "test"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host) })

	read := func() *ServerStatus {
		t.Helper()
		rows, err := st.ListWithStatus(ctx, "test")
		if err != nil {
			t.Fatalf("ListWithStatus: %v", err)
		}
		for _, r := range rows {
			if r.Hostname == host {
				return r.Status
			}
		}
		t.Fatalf("%s not in listing", host)
		return nil
	}

	// An agent that has not measured writes nothing.
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{Hostname: host, AgentVersion: "old"}); err != nil {
		t.Fatalf("upsert without metrics: %v", err)
	}
	if s := read(); s.MountCount != nil || s.CollectMs != nil {
		t.Errorf("absent metrics came back as %v/%v, want nil/nil", s.MountCount, s.CollectMs)
	}

	// Zero is a measurement and must be stored as one.
	zero := 0
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{
		Hostname: host, AgentVersion: "new", MountCount: &zero, CollectMs: &zero,
	}); err != nil {
		t.Fatalf("upsert zero: %v", err)
	}
	s := read()
	if s.MountCount == nil || *s.MountCount != 0 || s.CollectMs == nil || *s.CollectMs != 0 {
		t.Fatalf("zero metrics = %v/%v, want 0/0 present", s.MountCount, s.CollectMs)
	}

	// A real reading replaces it.
	mounts, ms := 16383, 1200
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{
		Hostname: host, AgentVersion: "new", MountCount: &mounts, CollectMs: &ms,
	}); err != nil {
		t.Fatalf("upsert values: %v", err)
	}
	if s := read(); s.MountCount == nil || *s.MountCount != mounts || s.CollectMs == nil || *s.CollectMs != ms {
		t.Fatalf("metrics = %v/%v, want %d/%d", s.MountCount, s.CollectMs, mounts, ms)
	}

	// An older agent reporting alongside a newer one must not erase what was
	// measured. Half-upgraded fleets are the normal state during a rollout.
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{Hostname: host, AgentVersion: "old"}); err != nil {
		t.Fatalf("upsert from old agent: %v", err)
	}
	if s := read(); s.MountCount == nil || *s.MountCount != mounts {
		t.Errorf("an older agent erased the measurement: %v", s.MountCount)
	}
}

// The CHECK constraint from migration 026 rejects a negative, which can only be
// a bug in the writer.
func TestAgentMetricsRejectNegatives(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO server_status (hostname, mount_count) VALUES ('x-neg', -1)`); err == nil {
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_status WHERE hostname='x-neg'`)
		t.Error("a negative mount count was accepted")
	}
}
