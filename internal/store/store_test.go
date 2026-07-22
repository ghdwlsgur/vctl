package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNullIfEmpty(t *testing.T) {
	if got := nullIfEmpty(""); got != nil {
		t.Errorf(`nullIfEmpty("") = %v, want nil`, got)
	}
	if got := nullIfEmpty("x"); got != "x" {
		t.Errorf(`nullIfEmpty("x") = %v, want "x"`, got)
	}
}

func TestMergeAddresses(t *testing.T) {
	got := mergeAddresses("10.0.0.1", []string{"10.0.0.2", "10.0.0.1", ""}, []string{"10.0.0.2", "192.168.1.9"})
	want := []string{"10.0.0.1", "10.0.0.2", "192.168.1.9"}
	if len(got) != len(want) {
		t.Fatalf("mergeAddresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mergeAddresses[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
	// Primary must always come first even when it also appears in a later set.
	if got[0] != "10.0.0.1" {
		t.Fatalf("primary not first: %v", got)
	}
}

// testStore connects to a throwaway Postgres named by VCTL_TEST_DSN and applies
// migrations. Skips when the env var is unset so unit runs need no database.
//
//	VCTL_TEST_DSN=postgres://user:pass@localhost:5432/vctl_test go test ./internal/store/
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("VCTL_TEST_DSN")
	if dsn == "" {
		t.Skip("VCTL_TEST_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	st := &Store{pool: pool}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// TestSessionEventRoundTrip exercises the audit path end to end: record a
// session, ingest events that link by cgroup, and confirm the timeline groups
// them under the right session. Integration — needs VCTL_TEST_DSN.
func TestSessionEventRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "test-host-" + time.Now().Format("150405.000000")
	start := time.Now().UTC().Truncate(time.Second)

	id, err := st.RecordSession(ctx, AuditSession{
		CertSerial: "SER-1", VaultUser: "alice", Hostname: host, LoginUser: "root",
		LeaderPID: 4242, CgroupID: 999, StartedAt: start,
	})
	if err != nil {
		t.Fatalf("RecordSession: %v", err)
	}

	// Idempotent re-record (same host/pid/started) must NOT create a new row —
	// guards against the watch-sessions restart duplication bug.
	id2, err := st.RecordSession(ctx, AuditSession{
		CertSerial: "SER-1", Hostname: host, LoginUser: "root",
		LeaderPID: 4242, CgroupID: 999, StartedAt: start,
	})
	if err != nil || id2 != id {
		t.Fatalf("re-RecordSession = (%d,%v), want (%d,nil)", id2, err, id)
	}

	n, err := st.InsertKernelEvents(ctx, []KernelEvent{
		{Hostname: host, TS: start.Add(time.Second), Kind: "exec", Binary: "/usr/bin/id", CgroupID: 999},
		{Hostname: host, TS: start.Add(2 * time.Second), Kind: "exit", Binary: "/usr/bin/id", CgroupID: 999},
	})
	if err != nil || n != 2 {
		t.Fatalf("InsertKernelEvents = (%d,%v), want (2,nil)", n, err)
	}

	sessions, byID, err := st.SessionTimeline(ctx, "SER-1", 10)
	if err != nil {
		t.Fatalf("SessionTimeline: %v", err)
	}
	if len(sessions) != 1 || sessions[0].VaultUser != "alice" {
		t.Fatalf("sessions = %+v, want 1 (alice)", sessions)
	}
	if got := len(byID[id]); got != 2 {
		t.Fatalf("events linked = %d, want 2", got)
	}

	// prune cleanup
	if _, err := st.PruneKernelEvents(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("PruneKernelEvents: %v", err)
	}
	if _, err := st.PruneSessions(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("PruneSessions: %v", err)
	}
}

// TestListInventoryMergesObservedIPs confirms `vctl list` sees agent-observed
// addresses without pulling the full runtime status: ListInventory folds
// observed_ips into Addresses. Integration — needs VCTL_TEST_DSN.
func TestListInventoryMergesObservedIPs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "inv-host-" + time.Now().Format("150405.000000")
	dc := "inv-dc-" + time.Now().Format("150405.000000")

	if err := st.Upsert(ctx, Server{
		Hostname: host, IP: "192.0.2.50", Port: 22, User: "ubuntu", DC: dc,
		CARole: "sre-core", ExtraIPs: []string{"192.0.2.51"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{
		Hostname: host, AgentVersion: "test", ObservedIPs: []string{"192.0.2.52", "192.0.2.50"},
	}); err != nil {
		t.Fatalf("UpsertServerStatus: %v", err)
	}

	rows, err := st.ListInventory(ctx, dc)
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0].Addresses
	want := []string{"192.0.2.50", "192.0.2.51", "192.0.2.52"} // primary, extra, observed; dedup drops the repeat
	if len(got) != len(want) {
		t.Fatalf("Addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Addresses[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestServerStatusDoesNotCreateInventory(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "status-host-" + time.Now().Format("150405.000000")

	ok, err := st.UpsertServerStatus(ctx, ServerStatus{Hostname: host, AgentVersion: "test"})
	if err != nil {
		t.Fatalf("UpsertServerStatus absent host: %v", err)
	}
	if ok {
		t.Fatal("UpsertServerStatus reported success for absent inventory host")
	}

	if err := st.Upsert(ctx, Server{
		Hostname: host,
		IP:       "192.0.2.10",
		Port:     22,
		User:     "ubuntu",
		DC:       "test",
		CARole:   "sre-core",
	}); err != nil {
		t.Fatalf("Upsert server: %v", err)
	}
	load := 0.25
	ok, err = st.UpsertServerStatus(ctx, ServerStatus{
		Hostname:     host,
		AgentVersion: "test",
		OS:           "linux",
		Load1:        &load,
	})
	if err != nil || !ok {
		t.Fatalf("UpsertServerStatus registered host = (%v,%v), want (true,nil)", ok, err)
	}

	servers, err := st.ListWithStatus(ctx, "test")
	if err != nil {
		t.Fatalf("ListWithStatus: %v", err)
	}
	var found *ServerWithStatus
	for i := range servers {
		if servers[i].Hostname == host {
			found = &servers[i]
			break
		}
	}
	if found == nil || found.Status == nil {
		t.Fatalf("status for %s not found in %+v", host, servers)
	}
	if found.Status.AgentVersion != "test" || found.Status.Load1 == nil || *found.Status.Load1 != load {
		t.Fatalf("status = %+v, want agent version and load", found.Status)
	}
}
