package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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

// AuditCutoff is the retention horizon for each audit tier. A nil SessionsBefore
// keeps session metadata indefinitely while still pruning raw events.
type AuditCutoff struct {
	KernelEventsBefore time.Time
	SessionsBefore     *time.Time
}

// AuditPruneResult reports what one complete retention pass removed.
type AuditPruneResult struct {
	KernelEvents int64
	Sessions     int64
}

// PruneAudit removes expired audit rows in bounded transactions. Small commits
// keep row locks and WAL bursts bounded; callers get one deep operation rather
// than having to reproduce the loop and its session-safety rule.
func (s *Store) PruneAudit(ctx context.Context, cutoff AuditCutoff, batchSize int) (AuditPruneResult, error) {
	if cutoff.KernelEventsBefore.IsZero() {
		return AuditPruneResult{}, fmt.Errorf("kernel event cutoff is required")
	}
	if batchSize <= 0 {
		batchSize = 10_000
	}
	var out AuditPruneResult
	for {
		tag, err := s.pool.Exec(ctx, `
			WITH doomed AS (
				SELECT id FROM kernel_event
				WHERE ts < $1 ORDER BY ts LIMIT $2
			)
			DELETE FROM kernel_event e USING doomed d WHERE e.id=d.id`,
			cutoff.KernelEventsBefore, batchSize)
		if err != nil {
			return out, err
		}
		n := tag.RowsAffected()
		out.KernelEvents += n
		if n < int64(batchSize) {
			break
		}
	}
	if cutoff.SessionsBefore == nil {
		return out, nil
	}
	for {
		tag, err := s.pool.Exec(ctx, `
			WITH doomed AS (
				SELECT s.id FROM audit_session s
				WHERE s.started_at < $1
				  AND s.ended_at IS NOT NULL
				  AND NOT EXISTS (SELECT 1 FROM kernel_event e WHERE e.session_id=s.id)
				ORDER BY s.started_at LIMIT $2
			)
			DELETE FROM audit_session s USING doomed d WHERE s.id=d.id`,
			*cutoff.SessionsBefore, batchSize)
		if err != nil {
			return out, err
		}
		n := tag.RowsAffected()
		out.Sessions += n
		if n < int64(batchSize) {
			break
		}
	}
	return out, nil
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
	batch := &pgx.Batch{}
	for _, e := range evs {
		batch.Queue(q,
			e.SessionID, e.CertSerial, e.Hostname, e.TS, e.Kind, e.PID, e.PPID, e.CgroupID,
			e.Binary, e.Args, e.CWD, e.UID, e.Filename, e.DestAddr, e.ExitCode, requireSession)
	}
	results := tx.SendBatch(ctx, batch)
	n := 0
	var unattributed []int
	for i := range evs {
		tag, err := results.Exec()
		if err != nil {
			_ = results.Close()
			return n, nil, err
		}
		if tag.RowsAffected() == 0 {
			unattributed = append(unattributed, i)
			continue
		}
		n++
	}
	if err := results.Close(); err != nil {
		return n, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return n, unattributed, nil
}

// --- retention (reported by `vctl retention`; enforced by the prune CronJob) ---
//
// Retention deletion runs only through the hidden in-cluster prune command with
// its delete-only Vault role. Human operator credentials cannot obtain that role;
// vctl retention reads the same numbers without DELETE.

// CountKernelEventsBefore returns how many kernel_event rows are older than t.
func (s *Store) CountKernelEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM kernel_event WHERE ts < $1`, t).Scan(&n)
	return n, err
}

// CountSessionsBefore returns how many ended audit_session rows are eligible for
// pruning before t. Open sessions and sessions with retained events are not
// reported as overdue when the pruner intentionally cannot remove them.
func (s *Store) CountSessionsBefore(ctx context.Context, t time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_session s
		WHERE s.started_at < $1
		  AND s.ended_at IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM kernel_event e WHERE e.session_id=s.id)`, t).Scan(&n)
	return n, err
}

// TableFootprint is what a table costs on disk right now.
type TableFootprint struct {
	Table string
	Bytes int64
	Rows  int64
	Dead  int64
}

// AuditFootprint reports the on-disk size of the audit tables.
//
// This exists because the size was invisible. A delete-only retention job
// returns space to the table's free list, not to the volume, so a burst parks the
// high-water mark permanently and nothing says so — on 2026-07-29 an empty
// kernel_event held 5,157 MB with no signal anywhere. Reading it needs no
// privilege beyond seeing the table, so the auditor role is enough.
func (s *Store) AuditFootprint(ctx context.Context) ([]TableFootprint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.relname,
		       pg_total_relation_size(c.oid),
		       coalesce(st.n_live_tup, 0),
		       coalesce(st.n_dead_tup, 0)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
		WHERE n.nspname = 'public' AND c.relname IN ('kernel_event', 'audit_session', 'access_log')
		ORDER BY pg_total_relation_size(c.oid) DESC`)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (TableFootprint, error) {
		var f TableFootprint
		err := r.Scan(&f.Table, &f.Bytes, &f.Rows, &f.Dead)
		return f, err
	})
}
