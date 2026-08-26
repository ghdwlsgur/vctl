package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// FarmMember is one host of a deployment as the MOTD renderer needs it: the
// inventory identity, plus the name the control plane knows the machine by so
// the caller can pair it against the unmatched-name list.
type FarmMember struct {
	Hostname     string
	IP           string
	NovaHostname string // evidence->>'nova_hostname'; empty when nova never confirmed it
	Confidence   string // declared | confirmed | local-only | control-only

	// Controller is whether the newest capability pass found the control
	// plane on this machine. The probe is the only source: ghost rows are the
	// opposite of controllers (names matching no inventory host), and reading
	// them as controllers is the misreading that once shipped a wrong banner.
	Controller bool
}

// FarmTopology is one deployment's membership as the inventory believes it,
// shaped for rendering rather than reconciling: members with addresses, the
// control plane's own host names, and when the reconciler last looked.
type FarmTopology struct {
	DeploymentID string
	DisplayName  string
	State        string // active | maintenance | broken | retired
	StateNote    string
	Team         string // metadata->>'team'; who the farm is run for, empty when unrecorded

	// GhostNames are machines the control plane names that the reconciler
	// could pair with no inventory host (the openstack_ghost_hosts table —
	// see store.GhostHost). One of them today is an inventory host whose
	// nova.conf carries a typo'd name; the caller decides how visible to make
	// each one, because a name nobody claims is worth showing, not dropping.
	GhostNames []string

	// SyncedAt is the newest membership observation — the honest value for a
	// "last synced" line, as opposed to "when this query ran".
	SyncedAt time.Time

	Members []FarmMember
}

// FarmTopologies returns every deployment the given host is a member of, with
// that deployment's full member list. Almost always zero or one; the slice is
// for the schema, which does not forbid a host claiming two farms.
//
// Conflict rows are excluded: a membership the reconciler itself flagged as
// contradictory is a question for an operator, not a fact for a login banner.
func (s *Store) FarmTopologies(ctx context.Context, hostname string) ([]FarmTopology, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.display_name, d.state, d.state_note, coalesce(d.metadata->>'team','')
		FROM openstack_deployments d
		WHERE d.id IN (
			SELECT deployment_id FROM openstack_memberships
			WHERE hostname=$1 AND confidence <> 'conflict')
		ORDER BY d.display_name, d.id`, hostname)
	if err != nil {
		return nil, err
	}
	farms, err := collectRows(rows, func(r pgx.Rows) (FarmTopology, error) {
		var f FarmTopology
		err := r.Scan(&f.DeploymentID, &f.DisplayName, &f.State, &f.StateNote, &f.Team)
		return f, err
	})
	if err != nil || len(farms) == 0 {
		return farms, err
	}

	for i := range farms {
		if err := s.fillFarmTopology(ctx, &farms[i]); err != nil {
			return nil, err
		}
	}
	return farms, nil
}

func (s *Store) fillFarmTopology(ctx context.Context, f *FarmTopology) error {
	// Controller comes from the newest capability pass only: a role the latest
	// pass did not rewrite is a role the machine dropped (see openstack_fold),
	// and a machine that stopped being a controller must not keep the crown on
	// a login banner.
	rows, err := s.pool.Query(ctx, `
		SELECT m.hostname, coalesce(host(s.ip),''), coalesce(m.evidence->>'nova_hostname',''),
		       m.confidence, m.observed_at,
		       EXISTS (
		         SELECT 1 FROM server_capabilities c
		         WHERE c.hostname = m.hostname AND c.kind = 'openstack'
		           AND c.role = 'controller' AND c.detected
		           AND c.pass_id = (SELECT max(c2.pass_id) FROM server_capabilities c2
		                            WHERE c2.hostname = c.hostname AND c2.kind = c.kind)
		       )
		FROM openstack_memberships m
		JOIN servers s USING (hostname)
		WHERE m.deployment_id=$1 AND m.confidence <> 'conflict'
		ORDER BY m.hostname`, f.DeploymentID)
	if err != nil {
		return err
	}
	members, err := collectRows(rows, func(r pgx.Rows) (FarmMember, error) {
		var m FarmMember
		var observed time.Time
		if err := r.Scan(&m.Hostname, &m.IP, &m.NovaHostname, &m.Confidence, &observed, &m.Controller); err != nil {
			return m, err
		}
		if observed.After(f.SyncedAt) {
			f.SyncedAt = observed
		}
		return m, nil
	})
	if err != nil {
		return err
	}
	f.Members = members

	ctrl, err := s.pool.Query(ctx, `
		SELECT nova_hostname FROM openstack_ghost_hosts
		WHERE deployment_id=$1 ORDER BY nova_hostname`, f.DeploymentID)
	if err != nil {
		return err
	}
	f.GhostNames, err = collectRows(ctrl, func(r pgx.Rows) (string, error) {
		var n string
		err := r.Scan(&n)
		return n, err
	})
	return err
}
