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
