package store

import (
	"context"
	"time"
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

// KernelEvent is one process/file/network event observed inside a session.
type KernelEvent struct {
	SessionID  *int64
	CertSerial string
	Hostname   string
	TS         time.Time
	Kind       string // exec | exit | open | connect
	PID        int
	PPID       int
	CgroupID   int64
	Binary     string
	Args       string
	CWD        string
	UID        int
	Filename   string
	DestAddr   string
	ExitCode   *int
}

// RecordSession upserts a session row (keyed by host + leader pid + start) and
// returns its id. Requires write credentials. Used by the login-time stamper.
func (s *Store) RecordSession(ctx context.Context, a AuditSession) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO audit_session
			(cert_serial, vault_user, hostname, login_user, source_ip, session_leader_pid, cgroup_id, summary)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7,$8)
		ON CONFLICT (hostname, session_leader_pid, started_at) DO UPDATE SET
			cert_serial=EXCLUDED.cert_serial, vault_user=EXCLUDED.vault_user,
			login_user=EXCLUDED.login_user, source_ip=EXCLUDED.source_ip,
			cgroup_id=EXCLUDED.cgroup_id
		RETURNING id`,
		nullIfEmpty(a.CertSerial), nullIfEmpty(a.VaultUser), nullIfEmpty(a.Hostname),
		nullIfEmpty(a.LoginUser), a.SourceIP, a.LeaderPID, a.CgroupID, nullIfEmpty(a.Summary)).Scan(&id)
	return id, err
}

// EndSession stamps ended_at and an optional summary for a session.
func (s *Store) EndSession(ctx context.Context, id int64, summary string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_session SET ended_at=now(), summary=COALESCE(NULLIF($2,''), summary) WHERE id=$1`,
		id, summary)
	return err
}

// InsertKernelEvents writes a batch of events. Requires write credentials.
// session_id is linked best-effort by (hostname, cgroup_id) when not set.
func (s *Store) InsertKernelEvents(ctx context.Context, evs []KernelEvent) (int, error) {
	if len(evs) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n := 0
	for _, e := range evs {
		_, err := tx.Exec(ctx, `
			INSERT INTO kernel_event
				(session_id, cert_serial, hostname, ts, kind, pid, ppid, cgroup_id,
				 exe, args, cwd, uid, filename, dest_addr, exit_code)
			VALUES (
				COALESCE($1, (SELECT id FROM audit_session
				              WHERE hostname=$3
				                AND ( ($8<>0 AND cgroup_id=$8)
				                   OR (NULLIF($2,'') IS NOT NULL AND cert_serial=$2) )
				              ORDER BY started_at DESC LIMIT 1)),
				NULLIF($2,''),$3,$4,$5,$6,$7,$8,
				NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),$12,NULLIF($13,''),NULLIF($14,''),$15)`,
			e.SessionID, e.CertSerial, e.Hostname, e.TS, e.Kind, e.PID, e.PPID, e.CgroupID,
			e.Binary, e.Args, e.CWD, e.UID, e.Filename, e.DestAddr, e.ExitCode)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit(ctx)
}

// SessionTimeline returns sessions matching a cert serial with their events,
// newest session first, events in chronological order.
func (s *Store) SessionTimeline(ctx context.Context, certSerial string, limit int) ([]AuditSession, map[int64][]KernelEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	srows, err := s.pool.Query(ctx, `
		SELECT id, coalesce(cert_serial,''), coalesce(vault_user,''), hostname, coalesce(login_user,''),
		       coalesce(host(source_ip),''), coalesce(session_leader_pid,0), coalesce(cgroup_id,0),
		       started_at, ended_at, coalesce(summary,'')
		FROM audit_session
		WHERE ($1='' OR cert_serial=$1)
		ORDER BY started_at DESC LIMIT $2`, certSerial, limit)
	if err != nil {
		return nil, nil, err
	}
	defer srows.Close()
	var sessions []AuditSession
	var ids []int64
	for srows.Next() {
		var a AuditSession
		if err := srows.Scan(&a.ID, &a.CertSerial, &a.VaultUser, &a.Hostname, &a.LoginUser,
			&a.SourceIP, &a.LeaderPID, &a.CgroupID, &a.StartedAt, &a.EndedAt, &a.Summary); err != nil {
			return nil, nil, err
		}
		sessions = append(sessions, a)
		ids = append(ids, a.ID)
	}
	if err := srows.Err(); err != nil {
		return nil, nil, err
	}
	byID := map[int64][]KernelEvent{}
	if len(ids) == 0 {
		return sessions, byID, nil
	}
	erows, err := s.pool.Query(ctx, `
		SELECT coalesce(session_id,0), coalesce(cert_serial,''), hostname, ts, kind,
		       coalesce(pid,0), coalesce(ppid,0), coalesce(cgroup_id,0),
		       coalesce(exe,''), coalesce(args,''), coalesce(cwd,''), coalesce(uid,0),
		       coalesce(filename,''), coalesce(dest_addr,''), exit_code
		FROM kernel_event
		WHERE session_id = ANY($1)
		ORDER BY ts ASC`, ids)
	if err != nil {
		return nil, nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var e KernelEvent
		var sid int64
		if err := erows.Scan(&sid, &e.CertSerial, &e.Hostname, &e.TS, &e.Kind, &e.PID, &e.PPID,
			&e.CgroupID, &e.Binary, &e.Args, &e.CWD, &e.UID, &e.Filename, &e.DestAddr, &e.ExitCode); err != nil {
			return nil, nil, err
		}
		byID[sid] = append(byID[sid], e)
	}
	return sessions, byID, erows.Err()
}

// ListSessions returns recent sessions, optionally filtered by host substring.
func (s *Store) ListSessions(ctx context.Context, hostFilter string, limit int) ([]AuditSession, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, coalesce(cert_serial,''), coalesce(vault_user,''), hostname, coalesce(login_user,''),
		       coalesce(host(source_ip),''), coalesce(session_leader_pid,0), coalesce(cgroup_id,0),
		       started_at, ended_at, coalesce(summary,'')
		FROM audit_session
		WHERE ($1='' OR hostname ILIKE '%'||$1||'%')
		ORDER BY started_at DESC LIMIT $2`, hostFilter, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditSession
	for rows.Next() {
		var a AuditSession
		if err := rows.Scan(&a.ID, &a.CertSerial, &a.VaultUser, &a.Hostname, &a.LoginUser,
			&a.SourceIP, &a.LeaderPID, &a.CgroupID, &a.StartedAt, &a.EndedAt, &a.Summary); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
