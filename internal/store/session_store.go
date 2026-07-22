package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditSession ties a cert serial (a human, via access_log) to one SSH session
// on a host. The host-side login stamper records it; kernel events link to it.
type AuditSession struct {
	ID         int64
	CertSerial string
	VaultUser  string
	Hostname   string
	LoginUser  string
	SourceIP   string
	LeaderPID  int
	CgroupID   int64
	StartedAt  time.Time
	EndedAt    *time.Time
	Summary    string
}

// sessionRow is the shared column list + scan for a full audit_session row.
const sessionCols = `id, coalesce(cert_serial,''), coalesce(vault_user,''), hostname, coalesce(login_user,''),
	coalesce(host(source_ip),''), coalesce(session_leader_pid,0), coalesce(cgroup_id,0),
	started_at, ended_at, coalesce(summary,'')`

func scanSession(row interface {
	Scan(dest ...any) error
}) (AuditSession, error) {
	var a AuditSession
	err := row.Scan(&a.ID, &a.CertSerial, &a.VaultUser, &a.Hostname, &a.LoginUser,
		&a.SourceIP, &a.LeaderPID, &a.CgroupID, &a.StartedAt, &a.EndedAt, &a.Summary)
	return a, err
}

// RecordSession upserts a session row and returns its id. Requires write
// credentials. The conflict key is (hostname, session_leader_pid, started_at),
// so started_at MUST be the stable login time from the marker — not now() — or a
// watch-sessions restart would re-insert the same session as a new row and leave
// the old one un-ended. When StartedAt is zero we fall back to now() (legacy).
//
// On conflict the nullable fields are COALESCEd (EXCLUDED first, existing
// second): a re-record that arrives without the vault_user/cert_serial (e.g. a
// restart that only re-sees the pid) refreshes what it knows without wiping the
// attribution the first record already captured.
func (s *Store) RecordSession(ctx context.Context, a AuditSession) (int64, error) {
	var started any
	if !a.StartedAt.IsZero() {
		started = a.StartedAt
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO audit_session
			(cert_serial, vault_user, hostname, login_user, source_ip, session_leader_pid, cgroup_id, summary, started_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7,$8, COALESCE($9, now()))
		ON CONFLICT (hostname, session_leader_pid, started_at) DO UPDATE SET
			cert_serial=COALESCE(EXCLUDED.cert_serial, audit_session.cert_serial),
			vault_user=COALESCE(EXCLUDED.vault_user, audit_session.vault_user),
			login_user=COALESCE(EXCLUDED.login_user, audit_session.login_user),
			source_ip=COALESCE(EXCLUDED.source_ip, audit_session.source_ip),
			cgroup_id=EXCLUDED.cgroup_id
		RETURNING id`,
		nullIfEmpty(a.CertSerial), nullIfEmpty(a.VaultUser), nullIfEmpty(a.Hostname),
		nullIfEmpty(a.LoginUser), a.SourceIP, a.LeaderPID, a.CgroupID, nullIfEmpty(a.Summary), started).Scan(&id)
	return id, err
}

// EndSession stamps ended_at and an optional summary for a session.
func (s *Store) EndSession(ctx context.Context, id int64, summary string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_session SET ended_at=now(), summary=COALESCE(NULLIF($2,''), summary) WHERE id=$1`,
		id, summary)
	return err
}

// UnendedSessions returns sessions on a host without an ended_at, for restart
// reconciliation (end the ones whose leader process is gone).
func (s *Store) UnendedSessions(ctx context.Context, host string) ([]AuditSession, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, coalesce(session_leader_pid,0)
		FROM audit_session WHERE hostname=$1 AND ended_at IS NULL`, host)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (AuditSession, error) {
		var a AuditSession
		err := r.Scan(&a.ID, &a.LeaderPID)
		return a, err
	})
}

// ListSessions returns recent sessions, optionally filtered by host substring.
func (s *Store) ListSessions(ctx context.Context, hostFilter string, limit int) ([]AuditSession, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+sessionCols+`
		FROM audit_session
		WHERE ($1='' OR hostname ILIKE '%'||$1||'%')
		ORDER BY started_at DESC LIMIT $2`, hostFilter, limit)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (AuditSession, error) { return scanSession(r) })
}
