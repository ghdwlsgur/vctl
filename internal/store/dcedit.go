package store

import "context"

// Delete removes a server from the inventory. Use when a host is
// decommissioned (e.g. a deleted VM). Audit/access rows keyed by the hostname
// remain as historical records. Returns whether a row matched.
func (s *Store) Delete(ctx context.Context, hostname string) (bool, error) {
	return s.execMatched(ctx, `DELETE FROM servers WHERE hostname=$1`, hostname)
}

// SetDC updates a server's datacenter label. DC is operator-managed and `vctl
// sync` would overwrite it from IP heuristics, so this is the deliberate manual
// edit path (used by cmd/dbedit). Returns whether a row matched.
func (s *Store) SetDC(ctx context.Context, hostname, dc string) (bool, error) {
	return s.execMatched(ctx, `UPDATE servers SET dc=$2 WHERE hostname=$1`, hostname, dc)
}

// SetUser updates a server's SSH login user. Like dc, `vctl sync` derives it
// from ssh config and would overwrite a manual value, so this is the deliberate
// edit path (cmd/dbedit). Returns whether a row matched.
func (s *Store) SetUser(ctx context.Context, hostname, user string) (bool, error) {
	return s.execMatched(ctx, `UPDATE servers SET ssh_user=$2 WHERE hostname=$1`, hostname, user)
}

// SetExtraIPs replaces a server's operator-curated additional addresses (VIPs,
// extra NICs). `vctl sync` preserves extra_ips, so this is the deliberate edit
// path (cmd/dbedit) for hosts whose node-agent can't auto-report (e.g. probe-only
// LBs). Pass bare IPs; an empty slice clears them. Returns whether a row matched.
func (s *Store) SetExtraIPs(ctx context.Context, hostname string, ips []string) (bool, error) {
	return s.execMatched(ctx, `UPDATE servers SET extra_ips=coalesce($2::inet[],'{}'), updated_at=now() WHERE hostname=$1`, hostname, ips)
}

// Rename changes a server's hostname (the inventory key) and, in the same
// transaction, repoints any host that jumped via the old name so jump chains
// stay intact. Audit rows keyed by the old name remain as historical records
// (not FK-linked); new activity uses the new name. Returns whether the host
// itself matched.
func (s *Store) Rename(ctx context.Context, oldHost, newHost string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE servers SET hostname=$2 WHERE hostname=$1`, oldHost, newHost)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE servers SET jump_via=$2 WHERE jump_via=$1`, oldHost, newHost); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// execMatched runs a statement that edits one inventory row and reports whether
// it found one.
//
// Every editor here returns (matched, error) rather than just error, because
// "no such host" is a normal outcome the caller must be able to tell from a
// failed statement — a typo'd hostname is not a database error. That two-value
// contract was written out four times; keeping it in one place is what stops
// the next editor from returning nil for a host that does not exist.
func (s *Store) execMatched(ctx context.Context, sql string, args ...any) (bool, error) {
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Insert registers a new inventory host and reports whether it was created.
//
// It is deliberately not Upsert. Upsert exists for `vctl sync`, which sees the
// same host repeatedly and must not clobber operator-set fields, so on conflict
// it refreshes only probe-derived columns — ssh_user, dc and jump_via survive.
// That is right for a sync and wrong for an explicit add: a caller who typed a
// hostname that already exists wants to hear about it, not to have half their
// input silently dropped.
//
// false with a nil error means the hostname is taken. Editing an existing host
// goes through SetDC/SetUser/SetExtraIPs, which say what they change.
func (s *Store) Insert(ctx context.Context, sv Server) (bool, error) {
	var jump any
	if sv.JumpVia != "" {
		jump = sv.JumpVia
	}
	return s.execMatched(ctx, `
		INSERT INTO servers (hostname, ip, ssh_port, ssh_user, jump_via, dc, ca_role, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now())
		ON CONFLICT (hostname) DO NOTHING`,
		sv.Hostname, sv.IP, sv.Port, sv.User, jump, sv.DC, sv.CARole)
}
