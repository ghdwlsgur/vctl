package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// SessionTimeline returns sessions matching a cert serial (newest first) with
// their kernel events in chronological order.
//
// Event→session linking has two tiers: exact session_id first, then an explicit
// cert-serial or cgroup match for rows that were ingested before the session.
// Time-window-only matching is intentionally forbidden because concurrent SSH
// sessions would leak and misattribute one another's commands.
func (s *Store) SessionTimeline(ctx context.Context, certSerial string, limit int) ([]AuditSession, map[int64][]KernelEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	srows, err := s.pool.Query(ctx, `
		SELECT `+sessionCols+`
		FROM audit_session
		WHERE ($1='' OR cert_serial=$1)
		ORDER BY started_at DESC LIMIT $2`, certSerial, limit)
	if err != nil {
		return nil, nil, err
	}
	defer srows.Close()
	var sessions []AuditSession
	for srows.Next() {
		a, err := scanSession(srows)
		if err != nil {
			return nil, nil, err
		}
		sessions = append(sessions, a)
	}
	if err := srows.Err(); err != nil {
		return nil, nil, err
	}

	byID := map[int64][]KernelEvent{}
	for _, sess := range sessions {
		evs, err := s.sessionEvents(ctx, sess)
		if err != nil {
			return nil, nil, err
		}
		byID[sess.ID] = evs
	}
	return sessions, byID, nil
}

// sessionEvents returns the kernel events attributed to one session (see the
// linking tiers documented on SessionTimeline).
func (s *Store) sessionEvents(ctx context.Context, sess AuditSession) ([]KernelEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(cert_serial,''), hostname, ts, kind,
		       coalesce(pid,0), coalesce(ppid,0), coalesce(cgroup_id,0),
		       coalesce(exe,''), coalesce(args,''), coalesce(cwd,''), coalesce(uid,0),
		       coalesce(filename,''), coalesce(dest_addr,''), exit_code
			FROM kernel_event
			WHERE session_id = $1
			   OR (
			       session_id IS NULL
			       AND hostname = $2
			       AND ts >= $3 AND ts <= coalesce($4, now())
			       AND (($5 <> '' AND cert_serial = $5) OR ($6 <> 0 AND cgroup_id = $6))
			   )
			ORDER BY ts ASC`, sess.ID, sess.Hostname, sess.StartedAt, sess.EndedAt, sess.CertSerial, sess.CgroupID)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (KernelEvent, error) {
		var e KernelEvent
		err := r.Scan(&e.CertSerial, &e.Hostname, &e.TS, &e.Kind, &e.PID, &e.PPID,
			&e.CgroupID, &e.Binary, &e.Args, &e.CWD, &e.UID, &e.Filename, &e.DestAddr, &e.ExitCode)
		return e, err
	})
}
