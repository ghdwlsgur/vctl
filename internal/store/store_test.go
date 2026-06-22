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
