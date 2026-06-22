package store

import (
	"context"
	"time"
)

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

// InsertKernelEvents writes a batch of events. Requires write credentials.
// session_id is linked exactly when the event's cgroup matches a session's, or
// by cert serial; otherwise it stays NULL and SessionTimeline links by time.
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

// --- retention (driven by `vctl prune`) ---

// CountKernelEventsBefore returns how many kernel_event rows are older than t.
// Used for prune dry-runs.
func (s *Store) CountKernelEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM kernel_event WHERE ts < $1`, t).Scan(&n)
	return n, err
}

// PruneKernelEvents deletes kernel_event rows older than t and returns the count.
// Requires write credentials.
func (s *Store) PruneKernelEvents(ctx context.Context, t time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM kernel_event WHERE ts < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneSessions deletes audit_session rows started before t. Sessions are the
// dataset index, so prune them with a longer horizon than raw events.
// FK on kernel_event is ON DELETE SET NULL, so orphan events are harmless and
// caught by their own retention.
func (s *Store) PruneSessions(ctx context.Context, t time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_session WHERE started_at < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
