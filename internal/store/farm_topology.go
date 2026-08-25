package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// FarmMember is one host of a deployment as the MOTD renderer needs it: the
// inventory identity, plus the name the control plane knows the machine by so
// the caller can pair it against the control-host list.
type FarmMember struct {
	Hostname     string
	IP           string
	NovaHostname string // evidence->>'nova_hostname'; empty when nova never confirmed it
	Confidence   string // declared | confirmed | local-only | control-only
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

	// ControlNames are the control plane hosts as nova reports them. They are
	// nova's names, not inventory names — pairing the two is the caller's
	// problem (membership.MatchHosts), because an unmatchable control name is
	// worth showing rather than dropping.
	ControlNames []string

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
	rows, err := s.pool.Query(ctx, `
		SELECT m.hostname, coalesce(host(s.ip),''), coalesce(m.evidence->>'nova_hostname',''),
		       m.confidence, m.observed_at
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
		if err := r.Scan(&m.Hostname, &m.IP, &m.NovaHostname, &m.Confidence, &observed); err != nil {
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
		SELECT nova_hostname FROM openstack_control_hosts
		WHERE deployment_id=$1 ORDER BY nova_hostname`, f.DeploymentID)
	if err != nil {
		return err
	}
	f.ControlNames, err = collectRows(ctrl, func(r pgx.Rows) (string, error) {
		var n string
		err := r.Scan(&n)
		return n, err
	})
	return err
}
