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
// Qualified with the `s` alias because every query using it also joins
// sessionVaultUser to attribute the session to a person.
const sessionCols = `s.id, coalesce(s.cert_serial,''), coalesce(nullif(s.vault_user,''), al.vault_user, ''),
	s.hostname, coalesce(s.login_user,''),
	coalesce(host(s.source_ip),''), coalesce(s.session_leader_pid,0), coalesce(s.cgroup_id,0),
	s.started_at, s.ended_at, coalesce(s.summary,'')`

// sessionVaultUser resolves "which person was this" from the certificate serial.
//
// The host collector cannot do this itself and should not be able to: the marker
// the PAM stamper drops carries the cert serial but no identity, and the
// vctl-audit-ingest database role has no read access to access_log at all. That
// separation is deliberate — a host may append audit records, not read who
// signed for other hosts. So audit_session.vault_user stays NULL for anything
// recorded by a collector, and the join below fills it in on the read path,
// where vctl-audit-ro does have access_log.
//
// Latest signature wins: a serial is one certificate, but a re-sign for the same
// serial should attribute to the most recent one.
const sessionVaultUser = `
	LEFT JOIN LATERAL (
		SELECT vault_user
		FROM access_log
		WHERE cert_serial = s.cert_serial
		  AND s.cert_serial IS NOT NULL
		  AND vault_user IS NOT NULL
		ORDER BY signed_at DESC
		LIMIT 1
	) al ON true`

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
//
// endedAt comes from the caller, not from now(), because started_at comes from
// the marker and is therefore on the *host's* clock (see RecordSession — it has
// to be, it is part of the conflict key). Stamping the end with the database
// clock mixed two clocks in one interval, so any host running ahead of Postgres
// produced sessions that ended before they began: observed durations of -3m15s,
// -48s and -44s in production on 2026-07-29. The watcher that sees the session
// end is on the same host as the marker, so its clock is the right one.
//
// GREATEST is a floor for the remaining case one clock cannot fix: a step
// correction (NTP) between login and logout can still move the host's clock
// backwards. A zero-length session is wrong but readable; a negative one is
// neither.
func (s *Store) EndSession(ctx context.Context, id int64, endedAt time.Time, summary string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_session
		 SET ended_at=GREATEST($2::timestamptz, started_at),
		     summary=COALESCE(NULLIF($3,''), summary)
		 WHERE id=$1`,
		id, endedAt.UTC(), summary)
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
		FROM audit_session s`+sessionVaultUser+`
		WHERE ($1='' OR s.hostname ILIKE '%'||$1||'%')
		ORDER BY s.started_at DESC LIMIT $2`, hostFilter, limit)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (AuditSession, error) { return scanSession(r) })
}
