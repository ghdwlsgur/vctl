package store

import "context"

// SessionTimeline returns sessions matching a cert serial (newest first) with
// their kernel events in chronological order.
//
// Event→session linking has two tiers:
//   - Exact: a kernel_event already carries session_id (set at insert when its
//     cgroup matched a session, or by cert serial).
//   - Fallback: when no cgroup/serial was available, events are correlated by
//     hostname + the session's [started, ended] window. To keep concurrent
//     sessions on one host from bleeding together, a cgroup match is still
//     required when BOTH sides have a cgroup id (id 0 on either side = pure
//     time-window).
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
		WHERE hostname = $1
		  AND ts >= $2 AND ts <= coalesce($3, now())
		  AND ($4 = 0 OR coalesce(cgroup_id,0) = 0 OR cgroup_id = $4)
		ORDER BY ts ASC`, sess.Hostname, sess.StartedAt, sess.EndedAt, sess.CgroupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KernelEvent
	for rows.Next() {
		var e KernelEvent
		if err := rows.Scan(&e.CertSerial, &e.Hostname, &e.TS, &e.Kind, &e.PID, &e.PPID,
			&e.CgroupID, &e.Binary, &e.Args, &e.CWD, &e.UID, &e.Filename, &e.DestAddr, &e.ExitCode); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
