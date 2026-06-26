package store

import (
	"context"
	"sort"
	"strings"
)

// RBACGroup is a named permission group in the app-layer RBAC (layer 2).
type RBACGroup struct {
	Name        string
	Description string
	Members     int
	Commands    int
}

// RBACGroupUpsert creates a group (or updates its description).
func (s *Store) RBACGroupUpsert(ctx context.Context, name, desc string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rbac_groups (name, description) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description`, name, desc)
	return err
}

// RBACGroupDelete removes a group; members/grants cascade. Idempotent.
func (s *Store) RBACGroupDelete(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM rbac_groups WHERE name = $1`, name)
	return err
}

// RBACGroups lists all groups with member/grant counts.
func (s *Store) RBACGroups(ctx context.Context) ([]RBACGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT g.name, g.description,
		       (SELECT count(*) FROM rbac_members m WHERE m.group_name = g.name),
		       (SELECT count(*) FROM rbac_grants  r WHERE r.group_name = g.name)
		FROM rbac_groups g ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RBACGroup
	for rows.Next() {
		var g RBACGroup
		if err := rows.Scan(&g.Name, &g.Description, &g.Members, &g.Commands); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RBACGroupExists reports whether a group is defined.
func (s *Store) RBACGroupExists(ctx context.Context, name string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT exists(SELECT 1 FROM rbac_groups WHERE name = $1)`, name).Scan(&ok)
	return ok, err
}

// RBACMemberAdd adds a user to a group (idempotent). Fails if the group is absent.
func (s *Store) RBACMemberAdd(ctx context.Context, group, user string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rbac_members (group_name, username) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, group, user)
	return err
}

// RBACMemberRemove removes a user from a group.
func (s *Store) RBACMemberRemove(ctx context.Context, group, user string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM rbac_members WHERE group_name = $1 AND username = $2`, group, user)
	return err
}

// RBACGrant grants a command to a group (idempotent). Fails if the group is absent.
func (s *Store) RBACGrant(ctx context.Context, group, command string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rbac_grants (group_name, command) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, group, command)
	return err
}

// RBACRevoke removes a command grant from a group.
func (s *Store) RBACRevoke(ctx context.Context, group, command string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE group_name = $1 AND command = $2`, group, command)
	return err
}

// RBACGroupMembers / RBACGroupCommands return a group's members and granted commands.
func (s *Store) RBACGroupMembers(ctx context.Context, group string) ([]string, error) {
	return s.rbacStrings(ctx, `SELECT username FROM rbac_members WHERE group_name = $1 ORDER BY username`, group)
}

func (s *Store) RBACGroupCommands(ctx context.Context, group string) ([]string, error) {
	return s.rbacStrings(ctx, `SELECT command FROM rbac_grants WHERE group_name = $1 ORDER BY command`, group)
}

// RBACGroupsForUser returns the groups a user belongs to.
func (s *Store) RBACGroupsForUser(ctx context.Context, user string) ([]string, error) {
	return s.rbacStrings(ctx, `SELECT group_name FROM rbac_members WHERE username = $1 ORDER BY group_name`, user)
}

// RBACCommandsForUser returns the set of commands granted to a user via any of
// their groups. '*' in the set means all commands.
func (s *Store) RBACCommandsForUser(ctx context.Context, user string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT r.command FROM rbac_grants r
		JOIN rbac_members m ON m.group_name = r.group_name
		WHERE m.username = $1`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out[c] = true
	}
	return out, rows.Err()
}

// RecordSeenUser upserts a username into seen_users — called on `vctl login` so
// anyone who authenticates becomes a candidate for the interactive assigner,
// without first having to ssh. Best-effort at the call site.
func (s *Store) RecordSeenUser(ctx context.Context, username string) error {
	if username == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO seen_users (username) VALUES ($1)
		ON CONFLICT (username) DO UPDATE SET last_seen = now()`, username)
	return err
}

// RBACCandidateUsers returns known usernames to offer in the interactive
// assigner: everyone who logged in (seen_users), ever ssh'd (access_log), or is
// already a member. Sources are queried independently and a not-yet-migrated
// table (e.g. seen_users before migration 007) is tolerated rather than failing.
func (s *Store) RBACCandidateUsers(ctx context.Context) ([]string, error) {
	set := map[string]bool{}
	sources := []string{
		`SELECT DISTINCT vault_user FROM access_log WHERE vault_user IS NOT NULL AND vault_user <> ''`,
		`SELECT DISTINCT username FROM rbac_members`,
		`SELECT DISTINCT username FROM seen_users`,
	}
	for _, q := range sources {
		rows, err := s.pool.Query(ctx, q)
		if err != nil {
			if strings.Contains(err.Error(), "42P01") { // table not migrated yet
				continue
			}
			return nil, err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return nil, err
			}
			if v != "" {
				set[v] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) rbacStrings(ctx context.Context, q, arg string) ([]string, error) {
	rows, err := s.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
