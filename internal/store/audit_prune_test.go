package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPruneAuditRejectsAccessCutoffThatBreaksSessionAttribution(t *testing.T) {
	now := time.Now().UTC()
	sessionCutoff := now.AddDate(0, 0, -365)
	accessCutoff := now.AddDate(0, 0, -30)
	_, err := (&Store{}).PruneAudit(context.Background(), AuditCutoff{
		KernelEventsBefore: now.AddDate(0, 0, -14),
		SessionsBefore:     &sessionCutoff,
		AccessLogsBefore:   &accessCutoff,
	}, 100)
	if err == nil {
		t.Fatal("accepted access retention shorter than session retention")
	}
}

func TestPruneAuditRejectsAccessRetentionWhenSessionsAreKeptForever(t *testing.T) {
	now := time.Now().UTC()
	accessCutoff := now.AddDate(-3, 0, 0)
	_, err := (&Store{}).PruneAudit(context.Background(), AuditCutoff{
		KernelEventsBefore: now.AddDate(0, 0, -14),
		AccessLogsBefore:   &accessCutoff,
	}, 100)
	if err == nil || !strings.Contains(err.Error(), "sessions are retained forever") {
		t.Fatalf("PruneAudit error = %v, want permanent-session attribution guard", err)
	}
}

// The retention operation removes expired raw events first, then only ended
// sessions that no event still references, and finally access attribution after
// its longer legal horizon. Integration — needs VCTL_TEST_DSN.
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
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO access_log (cert_serial, signed_at, ok) VALUES
			($1, $2, true), ($3, $4, true)`,
		"prune-old-access", now.AddDate(-4, 0, 0),
		"prune-recent-access", now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert access logs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM access_log WHERE cert_serial IN ('prune-old-access','prune-recent-access')`)
	})

	sessionCutoff := now.AddDate(0, 0, -365)
	accessCutoff := now.AddDate(-3, 0, 0)
	got, err := st.PruneAudit(ctx, AuditCutoff{
		KernelEventsBefore: now.AddDate(0, 0, -14),
		SessionsBefore:     &sessionCutoff,
		AccessLogsBefore:   &accessCutoff,
	}, 1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if got.KernelEvents != 1 || got.Sessions != 1 || got.AccessLogs != 1 {
		t.Fatalf("pruned = %+v, want one event, one session, and one access log", got)
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
	var remaining int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM access_log WHERE cert_serial IN ('prune-old-access','prune-recent-access')`).Scan(&remaining); err != nil {
		t.Fatalf("count retained access logs: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining access logs = %d, want recent row only", remaining)
	}
}
