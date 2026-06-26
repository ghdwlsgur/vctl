package store

import "context"

// SetDC updates a server's datacenter label. DC is operator-managed and `vctl
// sync` would overwrite it from IP heuristics, so this is the deliberate manual
// edit path (used by cmd/dbedit). Returns whether a row matched.
func (s *Store) SetDC(ctx context.Context, hostname, dc string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE servers SET dc=$2 WHERE hostname=$1`, hostname, dc)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// SetUser updates a server's SSH login user. Like dc, `vctl sync` derives it
// from ssh config and would overwrite a manual value, so this is the deliberate
// edit path (cmd/dbedit). Returns whether a row matched.
func (s *Store) SetUser(ctx context.Context, hostname, user string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE servers SET ssh_user=$2 WHERE hostname=$1`, hostname, user)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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
