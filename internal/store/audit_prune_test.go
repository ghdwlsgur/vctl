package store

import (
	"context"
	"testing"
	"time"
)

// The retention operation removes expired raw events first, then only ended
// sessions that no event still references. Integration — needs VCTL_TEST_DSN.
func TestPruneAuditPreservesRecentAndOpenSessions(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	old := AuditSession{
		CertSerial: "prune-old-session",
		Hostname:   "prune-test-host",
		LeaderPID:  8101,
		StartedAt:  now.AddDate(0, 0, -400),
	}
	oldID, err := st.RecordSession(ctx, old)
	if err != nil {
		t.Fatalf("record old session: %v", err)
	}
	if err := st.EndSession(ctx, oldID, old.StartedAt.Add(time.Hour), "done"); err != nil {
		t.Fatalf("end old session: %v", err)
	}

	recent := AuditSession{
		CertSerial: "prune-recent-session",
		Hostname:   "prune-test-host",
		LeaderPID:  8102,
		StartedAt:  now.Add(-time.Hour),
	}
	recentID, err := st.RecordSession(ctx, recent)
	if err != nil {
		t.Fatalf("record recent session: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM kernel_event WHERE session_id=ANY($1::bigint[])`, []int64{oldID, recentID})
		_, _ = st.pool.Exec(ctx, `DELETE FROM audit_session WHERE id=ANY($1::bigint[])`, []int64{oldID, recentID})
	})

	if _, err := st.InsertKernelEvents(ctx, []KernelEvent{
		{SessionID: &oldID, CertSerial: old.CertSerial, Hostname: old.Hostname, TS: now.AddDate(0, 0, -20), Kind: "exec"},
		{SessionID: &recentID, CertSerial: recent.CertSerial, Hostname: recent.Hostname, TS: now.Add(-time.Minute), Kind: "exec"},
	}); err != nil {
		t.Fatalf("insert events: %v", err)
	}

	sessionCutoff := now.AddDate(0, 0, -365)
	got, err := st.PruneAudit(ctx, AuditCutoff{
		KernelEventsBefore: now.AddDate(0, 0, -14),
		SessionsBefore:     &sessionCutoff,
	}, 1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if got.KernelEvents != 1 || got.Sessions != 1 {
		t.Fatalf("pruned = %+v, want one event and one session", got)
	}

	oldSessions, _, err := st.SessionTimeline(ctx, old.CertSerial, 10)
	if err != nil {
		t.Fatalf("old timeline: %v", err)
	}
	if len(oldSessions) != 0 {
		t.Fatalf("old sessions remain: %v", oldSessions)
	}
	recentSessions, events, err := st.SessionTimeline(ctx, recent.CertSerial, 10)
	if err != nil {
		t.Fatalf("recent timeline: %v", err)
	}
	if len(recentSessions) != 1 || len(events[recentID]) != 1 {
		t.Fatalf("recent timeline was pruned: sessions=%d events=%d", len(recentSessions), len(events[recentID]))
	}
}
