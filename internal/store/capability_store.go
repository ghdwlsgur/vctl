package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Capability is one platform role a host holds — "this machine is an OpenStack
// compute node" — with the versions found and how the probe went.
type Capability struct {
	Hostname string
	Kind     string // openstack | kubernetes | ceph
	Role     string // compute | controller | network | ...
	Detected bool
	// Active says whether a service is actually running behind this role. A
	// role is what the host is built to do; Active is whether it is doing it.
	Active     bool
	Components map[string]CapabilityComponent
	Details    map[string]string
	LastError  string
	ObservedAt time.Time
	UpdatedAt  time.Time
}

// CapabilityComponent is one piece of software the probe found. Versions are
// per component because a rolling upgrade leaves them different for weeks.
type CapabilityComponent struct {
	Version string `json:"version,omitempty"`
	Package string `json:"package,omitempty"`

	// Active is meaningful only when Service is true — see hoststatus.Component.
	Active  bool `json:"active"`
	Service bool `json:"service"`
}

// UpsertCapability records what a probe found, and refuses to create inventory
// the way UpsertServerStatus does: a capability for a host that is not in
// servers is dropped.
//
// A host that can write status for a name it does not own could otherwise
// invent a compute node, and anything reading this to plan maintenance would
// believe it.
func (s *Store) UpsertCapability(ctx context.Context, c Capability) (bool, error) {
	comps, err := json.Marshal(orEmptyComponents(c.Components))
	if err != nil {
		return false, err
	}
	details, err := json.Marshal(orEmptyDetails(c.Details))
	if err != nil {
		return false, err
	}
	at := c.ObservedAt
	if at.IsZero() {
		at = time.Now()
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO server_capabilities
			(hostname, kind, role, detected, active, components, details, last_error, observed_at, updated_at)
		SELECT $1,$2,$3,$4,$9,$5::jsonb,$6::jsonb,$7,$8, now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname, kind, role) DO UPDATE SET
			detected=EXCLUDED.detected, active=EXCLUDED.active,
			components=EXCLUDED.components,
			details=EXCLUDED.details, last_error=EXCLUDED.last_error,
			observed_at=EXCLUDED.observed_at, updated_at=now()`,
		c.Hostname, c.Kind, c.Role, c.Detected, string(comps), string(details), c.LastError, at, c.Active)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RecordCapabilityError notes that a probe could not complete, without touching
// what it last found.
//
// Deleting the rows would be the obvious thing and the wrong one: a probe that
// times out does not mean the host stopped being a compute node, and a listing
// built from that would show an outage as a decommission. The facts stay, the
// error sits beside them, and the age says how much to trust it.
//
// When there is nothing to sit beside, a row is created for the error alone.
// An UPDATE was the whole implementation at first, which meant the very first
// probe on a host — the one most likely to fail, because that is when the
// packaging and permissions are still wrong — updated zero rows and returned
// nil. The failure left no trace anywhere, and the host was indistinguishable
// from one nothing had looked at yet.
func (s *Store) RecordCapabilityError(ctx context.Context, hostname, kind, message string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE server_capabilities SET last_error=$3, updated_at=now()
		WHERE hostname=$1 AND kind=$2`, hostname, kind, message)
	if err != nil || tag.RowsAffected() > 0 {
		return err
	}
	// detected=false here means "we do not know", not "we looked and there is
	// nothing" — last_error is what tells the two apart, and every reader has
	// to check it before believing detected.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO server_capabilities
			(hostname, kind, role, detected, last_error, observed_at, updated_at)
		SELECT $1,$2,$3,false,$4, now(), now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname, kind, role) DO UPDATE SET
			last_error=EXCLUDED.last_error, updated_at=now()`,
		hostname, kind, RoleUnknown, message)
	return err
}

// Capabilities returns capability rows, optionally narrowed to one kind.
func (s *Store) Capabilities(ctx context.Context, kind string) ([]Capability, error) {
	q := `SELECT hostname, kind, role, detected, active, components, details, last_error, observed_at, updated_at
		FROM server_capabilities`
	var args []any
	if kind != "" {
		q += ` WHERE kind=$1`
		args = append(args, kind)
	}
	q += ` ORDER BY kind, role, hostname`
	return queryAndCollect(ctx, s.pool, q, args, scanCapability)
}

func scanCapability(r pgx.Rows) (Capability, error) {
	var c Capability
	var comps, details []byte
	if err := r.Scan(&c.Hostname, &c.Kind, &c.Role, &c.Detected, &c.Active, &comps, &details,
		&c.LastError, &c.ObservedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	// Malformed JSON in one row must not fail the whole listing: the row still
	// says which host holds which role, which is most of its value.
	_ = json.Unmarshal(comps, &c.Components)
	_ = json.Unmarshal(details, &c.Details)
	return c, nil
}

func orEmptyComponents(m map[string]CapabilityComponent) map[string]CapabilityComponent {
	if m == nil {
		return map[string]CapabilityComponent{}
	}
	return m
}

func orEmptyDetails(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
