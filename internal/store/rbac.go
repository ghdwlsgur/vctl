package store

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func scanRBACGroup(r pgx.Rows) (RBACGroup, error) {
	var g RBACGroup
	err := r.Scan(&g.Name, &g.Description, &g.Members, &g.Commands)
	return g, err
}

func scanSeenUser(r pgx.Rows) (SeenUser, error) {
	var u SeenUser
	err := r.Scan(&u.Username, &u.Version, &u.LastSeen)
	return u, err
}

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
	return queryAndCollect(ctx, s.pool, `
		SELECT g.name, g.description,
		       (SELECT count(*) FROM rbac_members m WHERE m.group_name = g.name),
		       (SELECT count(*) FROM rbac_grants  r WHERE r.group_name = g.name)
		FROM rbac_groups g ORDER BY g.name`, nil, scanRBACGroup)
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
	cmds, err := queryAndCollect(ctx, s.pool, `
		SELECT DISTINCT r.command FROM rbac_grants r
		JOIN rbac_members m ON m.group_name = r.group_name
		WHERE m.username = $1`, []any{user}, scanString)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		out[c] = true
	}
	return out, nil
}

// SeenUser is a person who has logged in, with the vctl version they last used.
type SeenUser struct {
	Username string
	Version  string
	LastSeen time.Time
}

// RecordSeenUser upserts a username (+ the vctl version they logged in with) into
// seen_users — called on `vctl login` so anyone who authenticates becomes a
// candidate for the interactive assigner, without first having to ssh, and so an
// admin can track who is on which version. Best-effort at the call site.
func (s *Store) RecordSeenUser(ctx context.Context, username, version string) error {
	if username == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO seen_users (username, vctl_version) VALUES ($1, NULLIF($2, ''))
		ON CONFLICT (username) DO UPDATE SET last_seen = now(), vctl_version = NULLIF($2, '')`,
		username, version)
	return err
}

// SeenUsers lists everyone recorded at login, with version and last-seen time.
func (s *Store) SeenUsers(ctx context.Context) ([]SeenUser, error) {
	return queryAndCollect(ctx, s.pool,
		`SELECT username, coalesce(vctl_version, ''), last_seen FROM seen_users ORDER BY username`,
		nil, scanSeenUser)
}

// RBACCandidateUsers returns known usernames to offer in the interactive
// assigner: everyone who logged in (seen_users) or is already a member. Audit
// data is intentionally not readable through the inventory/RBAC role. Sources
// are queried independently and a not-yet-migrated
// table (e.g. seen_users before migration 007) is tolerated rather than failing.
func (s *Store) RBACCandidateUsers(ctx context.Context) ([]string, error) {
	set := map[string]bool{}
	sources := []string{
		`SELECT DISTINCT username FROM rbac_members`,
		`SELECT DISTINCT username FROM seen_users`,
	}
	for _, q := range sources {
		users, err := queryAndCollect(ctx, s.pool, q, nil, scanString)
		if err != nil {
			if strings.Contains(err.Error(), "42P01") { // table not migrated yet
				continue
			}
			return nil, err
		}
		for _, v := range users {
			if v != "" {
				set[v] = true
			}
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
	return queryAndCollect(ctx, s.pool, q, []any{arg}, scanString)
}
