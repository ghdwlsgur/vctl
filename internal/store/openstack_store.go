package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
)

// OpenStackHost is one host as the openstack listing sees it: the roles the last
// probe found, which deployment claims it, and how old that observation is.
//
// The database keys capabilities per (hostname, role) because a host holds
// several at once. Reading is the other way round — the question is "what is
// this machine", not "who is a controller" — so the rows are folded back into
// one record per host here rather than in every caller.
type OpenStackHost struct {
	Hostname  string `json:"hostname"`
	DC        string `json:"dc,omitempty"`
	HostState string `json:"host_state"` // active | maintenance | broken | retired

	// Detected is whether the probe found OpenStack at all. False with a row
	// present means "looked, found nothing", which is a different answer from
	// having no row.
	Detected bool `json:"detected"`

	// Roles the most recent probe found — what the host is built to do,
	// running or not.
	Roles []string `json:"roles,omitempty"`

	// ActiveRoles are the subset with a running service behind them. The
	// difference between the two lists is the outage, and keeping them apart is
	// what stops a farm's topology from shrinking while something is down.
	ActiveRoles []string `json:"active_roles,omitempty"`

	// Dropped are roles an earlier probe found and the latest one did not.
	//
	// The agent has no DELETE on server_capabilities — deliberately, so a probe
	// cannot erase a fact — which means a role a host stops holding leaves its
	// row behind forever. Every role written by one pass carries that pass's
	// timestamp, so a row that lags the newest one is a role that has gone away.
	// Reporting it as current would keep a decommissioned neutron agent in the
	// listing indefinitely; dropping it silently would hide the change.
	Dropped []DroppedRole `json:"dropped_roles,omitempty"`

	Components map[string]CapabilityComponent `json:"components,omitempty"`
	Details    map[string]string              `json:"details,omitempty"`
	LastError  string                         `json:"last_error,omitempty"`

	// ObservedAt is the newest observation across this host's rows.
	ObservedAt time.Time `json:"observed_at"`

	// Farm is the deployment this host belongs to, and Confidence says on what
	// evidence. Empty Farm means nothing has claimed it.
	Farm        string                `json:"farm,omitempty"`
	FarmName    string                `json:"farm_name,omitempty"`
	FarmRegion  string                `json:"farm_region,omitempty"`
	Confidence  string                `json:"confidence,omitempty"`
	Memberships []OpenStackMembership `json:"memberships,omitempty"`
}

// DroppedRole is a role that has fallen out of the latest probe.
type DroppedRole struct {
	Role     string    `json:"role"`
	LastSeen time.Time `json:"last_seen"`
}

// OpenStackMembership is one deployment claiming one host.
type OpenStackMembership struct {
	DeploymentID string    `json:"deployment_id"`
	DisplayName  string    `json:"display_name,omitempty"`
	Region       string    `json:"region,omitempty"`
	Confidence   string    `json:"confidence"`
	ObservedAt   time.Time `json:"observed_at"`
}

// Membership confidence values, in the order automation should trust them.
//
// Defined where the decision that produces them is — internal/openstack/
// membership — and re-exported here for the readers that compare against a
// stored row. One definition, so a rename cannot leave half the codebase
// writing a word the other half does not recognise.
const (
	ConfidenceDeclared    = membership.Declared
	ConfidenceConfirmed   = membership.Confirmed
	ConfidenceLocalOnly   = membership.LocalOnly
	ConfidenceControlOnly = membership.ControlOnly
	ConfidenceConflict    = membership.Conflict
)

// KindOpenStack is the capability kind this file reads.
const KindOpenStack = "openstack"

// roleNone is what a probe files when it found nothing, so that "probed and
// absent" has a row and can be told from "never probed".
const roleNone = "none"

// RoleUnknown is filed when a probe could not complete and there was nothing
// already recorded for the host. It is not a role — it is a place to hang the
// error so a failed first probe is visible rather than silent.
const RoleUnknown = "unknown"

// OpenStackCoverage says how much of the fleet has been looked at, which is the
// context an empty listing needs: no OpenStack hosts because none were found is
// a different situation from none because nothing has probed yet.
type OpenStackCoverage struct {
	// Hosts is the inventory excluding parked ones — nothing is expected of
	// those, so counting them would make coverage look permanently incomplete.
	Hosts   int `json:"hosts"`
	Probed  int `json:"probed"`
	Running int `json:"running"`

	// Failed is a probe that could not answer. Folding these into Absent would
	// report "this host does not run OpenStack" on the strength of a timeout.
	Failed   int `json:"failed"`
	Absent   int `json:"absent"`
	Unprobed int `json:"unprobed"`
}

// OpenStackHosts returns every host a probe has filed an OpenStack capability
// for, newest observation first within each host, sorted by hostname.
func (s *Store) OpenStackHosts(ctx context.Context) ([]OpenStackHost, error) {
	return openStackHostsOn(ctx, s.pool)
}

func openStackHostsOn(ctx context.Context, db rowQuerier) ([]OpenStackHost, error) {
	rows, err := queryAndCollect(ctx, db, `
		SELECT c.hostname, c.role, c.detected, c.active, c.components, c.details,
		       c.last_error, c.observed_at, c.pass_id,
		       coalesce(s.dc,''), coalesce(s.state,'active')
		FROM server_capabilities c
		LEFT JOIN servers s ON s.hostname = c.hostname
		WHERE c.kind = $1
		ORDER BY c.hostname, c.role`,
		[]any{KindOpenStack}, scanCapabilityRow)
	if err != nil {
		return nil, err
	}
	members, err := openStackMembershipsOn(ctx, db)
	if err != nil {
		return nil, err
	}
	return foldCapabilityRows(rows, members), nil
}

// capabilityRow is one (host, role) row before the fold.
type capabilityRow struct {
	Capability
	DC        string
	HostState string
}

func scanCapabilityRow(r pgx.Rows) (capabilityRow, error) {
	var row capabilityRow
	var comps, details []byte
	if err := r.Scan(&row.Hostname, &row.Role, &row.Detected, &row.Active, &comps, &details,
		&row.LastError, &row.ObservedAt, &row.PassID, &row.DC, &row.HostState); err != nil {
		return row, err
	}
	// A row with malformed JSON still says which host holds which role, which is
	// most of its value — so it stays in the listing without its detail.
	_ = json.Unmarshal(comps, &row.Components)
	_ = json.Unmarshal(details, &row.Details)
	return row, nil
}

func openStackMembershipsOn(ctx context.Context, db rowQuerier) (map[string][]OpenStackMembership, error) {
	rows, err := queryAndCollect(ctx, db, `
		SELECT m.hostname, m.deployment_id, coalesce(d.display_name,''),
		       coalesce(d.region,''), m.confidence, m.observed_at
		FROM openstack_memberships m
		LEFT JOIN openstack_deployments d ON d.id = m.deployment_id
		ORDER BY m.hostname, m.deployment_id`,
		nil, func(r pgx.Rows) (hostMembership, error) {
			var hm hostMembership
			err := r.Scan(&hm.Hostname, &hm.DeploymentID, &hm.DisplayName,
				&hm.Region, &hm.Confidence, &hm.ObservedAt)
			return hm, err
		})
	if err != nil {
		return nil, err
	}
	out := map[string][]OpenStackMembership{}
	for _, hm := range rows {
		out[hm.Hostname] = append(out[hm.Hostname], hm.OpenStackMembership)
	}
	return out, nil
}

type hostMembership struct {
	Hostname string
	OpenStackMembership
}

// FarmSnapshot is everything one farm's screen is built from, read together.
//
// Assembled inside a single read transaction so the screen describes one moment.
// It used to be five independent reads, and a reconcile finishing between the
// second and the third put a host count from before it beside a run result from
// after it — a picture of the deployment that was never true. Nothing on screen
// says which reads came from where, so there is no way to notice from the
// output.
//
// DeploymentKnown separates "this deployment was never named" from "the read
// failed", which the caller used to conflate by ignoring the error.
type FarmSnapshot struct {
	Deployment      Deployment
	DeploymentKnown bool
	Hosts           []OpenStackHost
	Instances       []Instance
	Ghosts          []GhostHost
	Run             *ReconcileRun
}

// FarmSnapshot reads one deployment's whole picture at one instant.
//
// REPEATABLE READ rather than the default: every statement in the transaction
// then sees the same snapshot, which is the entire reason this exists. Read-only
// so it cannot block a writer or be chosen as a deadlock victim.
//
// Missing VMs are included. The assessment counts them, so filtering them out
// here would hide the number it exists to report.
func (s *Store) FarmSnapshot(ctx context.Context, id string) (FarmSnapshot, error) {
	var out FarmSnapshot
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hosts, err := openStackHostsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	for _, h := range hosts {
		if h.Farm == id && h.Detected {
			out.Hosts = append(out.Hosts, h)
		}
	}
	if out.Instances, err = instancesOn(ctx, tx, InstanceFilter{
		DeploymentID: id, IncludeMissing: true,
	}); err != nil {
		return out, err
	}
	if out.Ghosts, err = ghostHostsOn(ctx, tx, id); err != nil {
		return out, err
	}
	runs, err := reconcileRunsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	if r, ok := runs[id]; ok {
		out.Run = &r
	}
	ds, err := deploymentsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	for _, d := range ds {
		if d.ID == id {
			out.Deployment, out.DeploymentKnown = d, true
			break
		}
	}
	return out, nil
}
