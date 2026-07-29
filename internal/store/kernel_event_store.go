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

// InsertKernelEvents writes a batch of events whether or not they attribute to a
// session. Requires write credentials.
//
// Prefer InsertKernelEventsAttributed for host ingest — storing unattributable
// events is what filled this table with rows nothing could ever join to a person.
func (s *Store) InsertKernelEvents(ctx context.Context, evs []KernelEvent) (int, error) {
	n, _, err := s.insertKernelEvents(ctx, evs, false)
	return n, err
}

// InsertKernelEventsAttributed inserts only the events whose session resolves and
// returns the ones it could not attribute, so the caller can hold them and try
// again once the session row lands.
//
// A kernel event exists to answer "what did this person run inside this SSH
// session". An event with no session_id cannot answer it, and cannot later:
// nothing back-fills the column and SessionTimeline joins on it. So the row is
// storage spent on a question it will never help with.
//
// 2026-07-29 measurement, one Kubernetes node over six days: 4,748,267 exec/exit
// rows, 5,157 MB, 99.7% of the entire database — and session_id was NULL on every
// single one, because what it recorded was the node's own container and kubelet
// churn. At that rate a 43-host rollout at 14-day retention wants roughly 500 GB
// against a 20 GiB volume.
//
// Attribution stays server-side in one statement so it cannot drift from the read
// path, and the caller learns per event whether it landed.
// Misses come back as indices into evs, not copies: the caller is holding those
// events already and needs to match them to what it knows about each one (how long
// it has been waiting), which only the position can tell it.
func (s *Store) InsertKernelEventsAttributed(ctx context.Context, evs []KernelEvent) (int, []int, error) {
	return s.insertKernelEvents(ctx, evs, true)
}

func (s *Store) insertKernelEvents(ctx context.Context, evs []KernelEvent, requireSession bool) (int, []int, error) {
	if len(evs) == 0 {
		return 0, nil, nil
	}
	// The resolved CTE runs the same lookup in both modes; only the guard differs,
	// so the two paths cannot disagree about what "attributed" means.
	const q = `
		WITH resolved AS (
			SELECT COALESCE($1::bigint, (SELECT id FROM audit_session
			                             WHERE hostname=$3
			                               AND ( ($8<>0 AND cgroup_id=$8)
			                                  OR (NULLIF($2,'') IS NOT NULL AND cert_serial=$2) )
			                             ORDER BY started_at DESC LIMIT 1)) AS sid
		)
		INSERT INTO kernel_event
			(session_id, cert_serial, hostname, ts, kind, pid, ppid, cgroup_id,
			 exe, args, cwd, uid, filename, dest_addr, exit_code)
		SELECT sid, NULLIF($2,''),$3,$4,$5,$6,$7,$8,
		       NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),$12,NULLIF($13,''),NULLIF($14,''),$15
		FROM resolved
		WHERE NOT $16::boolean OR sid IS NOT NULL`

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)
	n := 0
	var unattributed []int
	for i, e := range evs {
		tag, err := tx.Exec(ctx, q,
			e.SessionID, e.CertSerial, e.Hostname, e.TS, e.Kind, e.PID, e.PPID, e.CgroupID,
			e.Binary, e.Args, e.CWD, e.UID, e.Filename, e.DestAddr, e.ExitCode, requireSession)
		if err != nil {
			return n, nil, err
		}
		if tag.RowsAffected() == 0 {
			unattributed = append(unattributed, i)
			continue
		}
		n++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return n, unattributed, nil
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
