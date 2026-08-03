package store

import (
	"context"
	"fmt"
	"strings"
)

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

// SetJumpVia sets or clears the host a connection hops through. Like dc and
// ssh_user this is operator-managed: `vctl sync` reads ProxyJump from ssh config
// and would overwrite a value set here, so this is the deliberate edit path.
// An empty jump means a direct connection. Returns whether a row matched.
func (s *Store) SetJumpVia(ctx context.Context, hostname, jump string) (bool, error) {
	var v any
	if jump != "" {
		v = jump
	}
	return s.execMatched(ctx, `UPDATE servers SET jump_via=$2, updated_at=now() WHERE hostname=$1`, hostname, v)
}

// SetExtraIPs replaces a server's operator-curated additional addresses (VIPs,
// extra NICs). `vctl sync` preserves extra_ips, so this is the deliberate edit
// path (cmd/dbedit) for hosts whose node-agent can't auto-report (e.g. probe-only
// LBs). Pass bare IPs; an empty slice clears them. Returns whether a row matched.
func (s *Store) SetExtraIPs(ctx context.Context, hostname string, ips []string) (bool, error) {
	return s.execMatched(ctx, `UPDATE servers SET extra_ips=coalesce($2::inet[],'{}'), updated_at=now() WHERE hostname=$1`, hostname, ips)
}

// renameCarried are the tables that key on a hostname and describe the host as
// it is now. A rename has to carry all of them or the row keeps its old key and
// silently stops joining.
//
// There are no foreign keys anywhere in this schema, so nothing enforces this
// list — Postgres will happily leave every one of these pointing at a name that
// no longer exists, and each failure shows up somewhere different: the host
// reads as no-agent in `vctl list`, its WireGuard interfaces vanish from the
// graph, its IP ledger entry stops resolving. Adding a hostname column without
// adding it here reintroduces exactly that.
//
// Audit tables are deliberately absent — see the comment on Rename.
// keyed marks a column that is part of its table's primary key. Those are the
// only ones where a leftover row under the new name can collide, and the only
// ones it is safe to clear: such a row describes the host itself. Where the
// hostname is an ordinary attribute — wg_endpoint_annotations is keyed by public
// key, ip_allocations by address — a row naming the new host belongs to someone
// else, and deleting it would destroy an unrelated record.
var renameCarried = []struct {
	table, column string
	keyed         bool
}{
	{"server_status", "hostname", true},
	{"wg_interfaces", "host", true},
	{"wg_peers", "host", true},
	{"wg_peer_status", "host", true},
	{"wg_endpoint_annotations", "inventory_host", false},
	{"wg_endpoint_annotations", "parent_hostname", false},
	{"ip_allocations", "hostname", false},
}

// SetState records what an operator declared about a host: active, maintenance,
// broken or retired.
//
// This is the one column here that is not a connection detail. dc, ssh_user and
// jump_via describe how to reach the machine; state describes whether anyone
// should expect to. Observation cannot supply it — a dead NIC, a planned window
// and a host nobody has installed the agent on all read as "down" — so it is
// entered rather than derived, and the listing shows it beside the observed
// value instead of replacing it.
//
// The database constrains the value, so an unknown state is rejected here rather
// than stored and rendered as a blank column. Returns whether a row matched.
func (s *Store) SetState(ctx context.Context, hostname, state string) (bool, error) {
	if !ValidState(state) {
		return false, fmt.Errorf("unknown state %q (want one of %s)", state, strings.Join(HostStates, ", "))
	}
	return s.execMatched(ctx, `UPDATE servers SET state=$2, updated_at=now() WHERE hostname=$1`, hostname, state)
}

// Rename changes a server's hostname — the inventory key — and carries with it
// everything that describes the host as it is now: the node-agent heartbeat, the
// WireGuard topology it appears in, and its entry in the IP ledger. Jump chains
// pointing at the old name are repointed so they stay intact.
//
// Audit rows are left alone on purpose. access_log, audit_session and
// kernel_event record what happened on that machine under the name it had at
// the time, and rewriting them would make the history claim something that was
// never true. This is the same rule Delete follows.
//
// The whole thing is one transaction. A rename that updated servers and then
// failed on server_status would leave the host registered under a name its own
// agent does not report as, which is worse than not renaming at all.
//
// Returns whether the host itself matched.
func (s *Store) Rename(ctx context.Context, oldHost, newHost string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `UPDATE servers SET hostname=$2, updated_at=now() WHERE hostname=$1`, oldHost, newHost)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		// Nothing to rename. Returning early keeps the dependent updates from
		// moving rows that belong to a host this inventory does not have.
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE servers SET jump_via=$2 WHERE jump_via=$1`, oldHost, newHost); err != nil {
		return false, err
	}

	for _, c := range renameCarried {
		if c.keyed {
			// Clear any row already sitting under the new name before moving this
			// host's onto it. Delete only removes from servers, so a host retired
			// under that name can leave its status or WireGuard rows behind, and the
			// update would hit the primary key. Dropping them is right — they
			// describe a machine the inventory no longer has, and keeping them would
			// hand the renamed host another machine's state.
			del := `DELETE FROM ` + c.table + ` WHERE ` + c.column + `=$1`
			if _, err := tx.Exec(ctx, del, newHost); err != nil {
				return false, err
			}
		}
		upd := `UPDATE ` + c.table + ` SET ` + c.column + `=$2 WHERE ` + c.column + `=$1`
		if _, err := tx.Exec(ctx, upd, oldHost, newHost); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
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
		INSERT INTO servers (hostname, ip, ssh_port, ssh_user, jump_via, dc, ca_role, extra_ips, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, coalesce($8::inet[],'{}'), now())
		ON CONFLICT (hostname) DO NOTHING`,
		sv.Hostname, sv.IP, sv.Port, sv.User, jump, sv.DC, sv.CARole, sv.ExtraIPs)
}
