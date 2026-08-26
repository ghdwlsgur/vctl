package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
)

// ApplyMembership records what a reconcile decided.
//
// It decides nothing. The rules — which hosts a deployment owns, what a partial
// answer may and may not settle, which control-plane name is which machine —
// are in internal/openstack/membership, and this writes their answer down.
//
// They used to be here, inside this transaction, which meant a caller could
// only ask what a run would do by letting it happen. `--dry-run` was therefore
// a separate implementation that agreed with this one by inspection, and the
// host matching sat in the persistence layer where `vctl openstack vm --host`
// had to reach into it.
//
// One transaction, because a partial write would leave some hosts confirmed
// against a control-plane read that never finished — worse than not having run
// at all.
func (s *Store) ApplyMembership(ctx context.Context, d membership.Decision) error {
	at := d.At
	if at.IsZero() {
		at = time.Now()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Empty means "not carrying this", not "clear it".
	//
	// The reconciler knows a deployment's endpoint and nothing else about it —
	// the name and region are things a person set with `vctl openstack farm
	// name`. Writing EXCLUDED unconditionally meant every run overwrote them
	// with the empty strings it was not carrying, so a farm named today was
	// anonymous again six hours later.
	if _, err := tx.Exec(ctx, `
		INSERT INTO openstack_deployments (id, display_name, region, keystone_url, updated_at)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (id) DO UPDATE SET
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), openstack_deployments.display_name),
			region       = COALESCE(NULLIF(EXCLUDED.region, ''),       openstack_deployments.region),
			keystone_url = COALESCE(NULLIF(EXCLUDED.keystone_url, ''), openstack_deployments.keystone_url),
			updated_at   = now()`,
		d.DeploymentID, d.DisplayName, d.Region, d.KeystoneURL); err != nil {
		return err
	}

	for _, h := range d.Hosts {
		if h.Holds() {
			// Seen this run without being judged: the row keeps what it said,
			// and only its observation time moves so the sweep below cannot
			// take it.
			if err := touchMembership(ctx, tx, h.Hostname, d.DeploymentID, at); err != nil {
				return err
			}
			continue
		}
		if err := upsertMembership(ctx, tx, h.Hostname, d.DeploymentID, h.Confidence, h.Evidence, at); err != nil {
			return err
		}
	}

	if d.SweepStale {
		if _, err := tx.Exec(ctx, `
			DELETE FROM openstack_memberships
			WHERE deployment_id=$1 AND observed_at < $2`, d.DeploymentID, at); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func upsertMembership(ctx context.Context, tx pgx.Tx, host, deployment, confidence string, evidence map[string]any, at time.Time) error {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO openstack_memberships (hostname, deployment_id, confidence, evidence, observed_at)
		SELECT $1,$2,$3,$4::jsonb,$5
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname, deployment_id) DO UPDATE SET
			confidence=EXCLUDED.confidence, evidence=EXCLUDED.evidence,
			observed_at=EXCLUDED.observed_at`,
		host, deployment, confidence, string(raw), at)
	return err
}

// touchMembership marks a row as seen this run without changing what it says.
//
// A held host must not fall behind the stale sweep just because an incomplete
// answer could not speak for it.
func touchMembership(ctx context.Context, tx pgx.Tx, host, deployment string, at time.Time) error {
	_, err := tx.Exec(ctx, `
		UPDATE openstack_memberships SET observed_at=$3
		WHERE hostname=$1 AND deployment_id=$2`, host, deployment, at)
	return err
}

// LocalOnlyFarms returns the deployments the probe has inferred but nothing has
// confirmed — the work list for a reconciler.
func (s *Store) LocalOnlyFarms(ctx context.Context) (map[string][]string, error) {
	hosts, err := s.OpenStackHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, h := range hosts {
		if h.Farm == "" || !h.Detected {
			continue
		}
		out[h.Farm] = append(out[h.Farm], h.Hostname)
	}
	return out, nil
}

// Deployment is one OpenStack farm as the inventory records it.
type Deployment struct {
	ID          string
	DisplayName string
	Region      string
	KeystoneURL string

	// State is what an operator declared about it, in the same words hosts use.
	// Observation cannot tell a farm that is broken from one being rebuilt.
	State          string
	StateNote      string
	StateChangedAt *time.Time
}

// SetDeploymentState records what an operator declares about a deployment.
//
// The row is created if the reconciler has not seen this deployment yet, so a
// farm can be marked broken before anything has successfully collected from it
// — which is exactly when somebody wants to.
func (s *Store) SetDeploymentState(ctx context.Context, id, state, note string) error {
	if !ValidState(state) {
		return fmt.Errorf("%q is not a state; use one of %s", state, strings.Join(HostStates, ", "))
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO openstack_deployments (id, state, state_note, state_changed_at, updated_at)
		VALUES ($1,$2,$3, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			state=EXCLUDED.state, state_note=EXCLUDED.state_note,
			-- Only when it actually changes: re-declaring the same state should
			-- not reset the age somebody is reading to decide how stale a fault is.
			state_changed_at = CASE
				WHEN openstack_deployments.state IS DISTINCT FROM EXCLUDED.state
				THEN now() ELSE openstack_deployments.state_changed_at END,
			updated_at=now()`,
		id, state, note)
	return err
}

// SetDeploymentName gives a farm a name people can read.
//
// This is the one writer that may clear a name — somebody passing an empty one
// is asking for that. The reconciler cannot, because it never carries the field
// at all; see the COALESCE in ReconcileDeployment.
//
// The farm's id is its Keystone endpoint — 172.16.0.245:5000 — which is stable
// and says nothing. A name is the only part of this a person chooses, so it is
// stored rather than derived: deriving it from the hosts (a common prefix, the
// datacenter) would rename the farm whenever its membership changed.
//
// The row is created if the reconciler has not yet seen this deployment, so a
// name can be given before the first reconcile rather than only after.
// region is nil for "leave whatever is there" and non-nil for "set it to this",
// empty string included.
//
// A plain string could not tell the two apart, and the command that calls this
// reads as renaming a deployment: `farm name <id> <new-name>` with no --region
// wrote an empty one and dropped a region nobody mentioned. Deciding it in the
// caller would mean reading the row first and writing it back, which is the
// same read-then-write gap this file has been closing elsewhere.
func (s *Store) SetDeploymentName(ctx context.Context, id, name string, region *string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO openstack_deployments (id, display_name, region, updated_at)
		VALUES ($1,$2, coalesce($3,''), now())
		ON CONFLICT (id) DO UPDATE SET
			display_name=EXCLUDED.display_name,
			region=coalesce($3, openstack_deployments.region),
			updated_at=now()`,
		id, name, region)
	return err
}

// Deployments lists the farms the inventory knows by name.
func (s *Store) Deployments(ctx context.Context) ([]Deployment, error) {
	return deploymentsOn(ctx, s.pool)
}

func deploymentsOn(ctx context.Context, db rowQuerier) ([]Deployment, error) {
	return queryAndCollect(ctx, db, `
		SELECT id, display_name, region, keystone_url,
		       coalesce(state,'active'), state_note, state_changed_at
		FROM openstack_deployments ORDER BY id`, nil,
		func(r pgx.Rows) (Deployment, error) {
			var d Deployment
			err := r.Scan(&d.ID, &d.DisplayName, &d.Region, &d.KeystoneURL,
				&d.State, &d.StateNote, &d.StateChangedAt)
			return d, err
		})
}

// ReconcileRun is the state of one deployment's last reconcile.
type ReconcileRun struct {
	DeploymentID string     `json:"deployment_id"`
	StartedAt    time.Time  `json:"started_at"`
	SucceededAt  *time.Time `json:"succeeded_at,omitempty"`
	Complete     bool       `json:"complete"`
	LastError    string     `json:"last_error,omitempty"`

	Confirmed   int `json:"confirmed"`
	LocalOnly   int `json:"local_only"`
	ControlOnly int `json:"control_only"`
	Held        int `json:"held"`
	Ambiguous   int `json:"ambiguous"`
}

// RecordReconcileRun stores what a run did, so a later reader can tell a
// membership decided an hour ago from one decided three weeks ago.
//
// A failure keeps the previous counts and succeeded_at. The counts describe the
// last run that produced any, and blanking them because a later attempt could
// not reach the control plane would report a farm as empty on the strength of a
// timeout — the same mistake the probe's error handling exists to avoid.
func (s *Store) RecordReconcileRun(ctx context.Context, deployment string, res membership.Outcome, at time.Time, runErr error) error {
	if at.IsZero() {
		at = time.Now()
	}
	msg := ""
	if runErr != nil {
		msg = runErr.Error()
	}
	if runErr != nil {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO openstack_reconcile_runs (deployment_id, started_at, complete, last_error)
			VALUES ($1,$2,false,$3)
			ON CONFLICT (deployment_id) DO UPDATE SET
				started_at=EXCLUDED.started_at, complete=false, last_error=EXCLUDED.last_error`,
			deployment, at, msg)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO openstack_reconcile_runs
			(deployment_id, started_at, succeeded_at, complete, last_error,
			 confirmed, local_only, control_only, held, ambiguous)
		VALUES ($1,$2,$2,$3,'',$4,$5,$6,$7,$8)
		ON CONFLICT (deployment_id) DO UPDATE SET
			started_at=EXCLUDED.started_at, succeeded_at=EXCLUDED.succeeded_at,
			complete=EXCLUDED.complete, last_error='',
			confirmed=EXCLUDED.confirmed, local_only=EXCLUDED.local_only,
			control_only=EXCLUDED.control_only, held=EXCLUDED.held,
			ambiguous=EXCLUDED.ambiguous`,
		deployment, at, res.Complete,
		len(res.Confirmed), len(res.LocalOnly), len(res.ControlOnly), len(res.Held), len(res.Ambiguous))
	return err
}

// ReconcileRuns returns the last run per deployment.
func (s *Store) ReconcileRuns(ctx context.Context) (map[string]ReconcileRun, error) {
	return reconcileRunsOn(ctx, s.pool)
}

func reconcileRunsOn(ctx context.Context, db rowQuerier) (map[string]ReconcileRun, error) {
	rows, err := queryAndCollect(ctx, db, `
		SELECT deployment_id, started_at, succeeded_at, complete, last_error,
		       confirmed, local_only, control_only, held, ambiguous
		FROM openstack_reconcile_runs`, nil,
		func(r pgx.Rows) (ReconcileRun, error) {
			var v ReconcileRun
			err := r.Scan(&v.DeploymentID, &v.StartedAt, &v.SucceededAt, &v.Complete, &v.LastError,
				&v.Confirmed, &v.LocalOnly, &v.ControlOnly, &v.Held, &v.Ambiguous)
			return v, err
		})
	if err != nil {
		return nil, err
	}
	out := make(map[string]ReconcileRun, len(rows))
	for _, r := range rows {
		out[r.DeploymentID] = r
	}
	return out, nil
}

// GhostHost is a machine the control plane knows and the inventory does not.
type GhostHost struct {
	DeploymentID string    `json:"deployment_id"`
	NovaHostname string    `json:"nova_hostname"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// RecordGhostHosts keeps the hosts nova named that no inventory entry matched.
//
// first_seen_at is preserved across runs: "nova has been telling us about this
// machine for three weeks" is a different statement from "this appeared today",
// and only the first is a registration somebody forgot.
//
// Rows are removed once they match an inventory host again — the caller passes
// only the still-unmatched names, and anything else for this deployment is
// deleted. Keeping them would leave a permanent list of problems already fixed.
func (s *Store) RecordGhostHosts(ctx context.Context, deployment string, names []string, at time.Time) error {
	if at.IsZero() {
		at = time.Now()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, n := range names {
		if n == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO openstack_ghost_hosts (deployment_id, nova_hostname, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,$3)
			ON CONFLICT (deployment_id, nova_hostname) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at`,
			deployment, n, at); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM openstack_ghost_hosts WHERE deployment_id=$1 AND last_seen_at < $2`,
		deployment, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GhostHosts lists the machines nova knows that the inventory does not.
func (s *Store) GhostHosts(ctx context.Context, deployment string) ([]GhostHost, error) {
	return ghostHostsOn(ctx, s.pool, deployment)
}

func ghostHostsOn(ctx context.Context, db rowQuerier, deployment string) ([]GhostHost, error) {
	q := `SELECT deployment_id, nova_hostname, first_seen_at, last_seen_at
		FROM openstack_ghost_hosts`
	var args []any
	if deployment != "" {
		q += ` WHERE deployment_id=$1`
		args = append(args, deployment)
	}
	return queryAndCollect(ctx, db, q+` ORDER BY deployment_id, nova_hostname`, args,
		func(r pgx.Rows) (GhostHost, error) {
			var c GhostHost
			err := r.Scan(&c.DeploymentID, &c.NovaHostname, &c.FirstSeenAt, &c.LastSeenAt)
			return c, err
		})
}
