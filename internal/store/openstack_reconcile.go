package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Reconcile turns two observations of one deployment into recorded membership.
//
// The probe says "this host runs OpenStack and points at this Keystone". The
// control plane says "these are my compute hosts". Neither alone is enough:
// pointing at a Keystone does not prove membership, because two deployments
// behind one proxy look identical from a host — and being registered centrally
// does not prove the host is still there.
//
// Agreement is the only thing that promotes to confirmed. Everything else keeps
// its weaker label, and the disagreements are recorded rather than resolved.

// ReconcileInput is one deployment's two sides.
type ReconcileInput struct {
	// DeploymentID is the farm's identity — the normalized Keystone endpoint.
	DeploymentID string
	DisplayName  string
	Region       string
	KeystoneURL  string

	// LocalHosts are inventory hostnames whose probe named this Keystone.
	LocalHosts []string

	// ControlHosts are the hypervisor names the control plane returned. These
	// are nova's names, which are not always the inventory's.
	ControlHosts []string

	// Complete says whether the control plane answered fully. A partial answer
	// may confirm, because a host both sides name is confirmed either way — but
	// it may not demote, because absence from a partial list is not evidence of
	// absence from the deployment.
	Complete bool

	ObservedAt time.Time
}

// ReconcileResult reports what changed, for the operator running it.
type ReconcileResult struct {
	DeploymentID string
	Confirmed    []string
	LocalOnly    []string
	ControlOnly  []string

	// Ambiguous are control-plane names that could belong to more than one
	// inventory host. They are reported rather than resolved: guessing which
	// machine a name means is how an inventory starts claiming the wrong one.
	Ambiguous []string

	// Held are hosts an incomplete answer would have demoted and did not. They
	// keep whatever confidence they had; this names them so the run does not
	// look like it confirmed them.
	Held []string

	// Complete mirrors the input, so a caller rendering this can say whether
	// the run was allowed to settle anything.
	Complete bool
}

// ReconcileDeployment records one deployment and the membership of its hosts.
//
// Runs in a transaction: a partial write would leave some hosts confirmed
// against a control-plane read that never finished, which is worse than not
// having run at all.
func (s *Store) ReconcileDeployment(ctx context.Context, in ReconcileInput) (ReconcileResult, error) {
	res := ReconcileResult{DeploymentID: in.DeploymentID, Complete: in.Complete}
	at := in.ObservedAt
	if at.IsZero() {
		at = time.Now()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Empty means "not carrying this", not "clear it".
	//
	// The reconciler knows a deployment's endpoint and nothing else about it —
	// the name and region are things a person set with `vctl openstack farm
	// name`. Writing EXCLUDED unconditionally meant every run overwrote them
	// with the empty strings it was not carrying, so a farm named today was
	// anonymous again six hours later. Only a caller that actually has a value
	// changes one.
	if _, err := tx.Exec(ctx, `
		INSERT INTO openstack_deployments (id, display_name, region, keystone_url, updated_at)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (id) DO UPDATE SET
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), openstack_deployments.display_name),
			region       = COALESCE(NULLIF(EXCLUDED.region, ''),       openstack_deployments.region),
			keystone_url = COALESCE(NULLIF(EXCLUDED.keystone_url, ''), openstack_deployments.keystone_url),
			updated_at   = now()`,
		in.DeploymentID, in.DisplayName, in.Region, in.KeystoneURL); err != nil {
		return res, err
	}

	pairs, ambiguous := MatchHosts(in.LocalHosts, in.ControlHosts)
	seen := map[string]bool{}

	for _, host := range in.LocalHosts {
		novaName, agreed := pairs[host]
		if agreed {
			evidence := map[string]any{"local": true, "control": true, "nova_hostname": novaName}
			seen[novaName] = true
			res.Confirmed = append(res.Confirmed, host)
			if err := upsertMembership(ctx, tx, host, in.DeploymentID, ConfidenceConfirmed, evidence, at); err != nil {
				return res, err
			}
			continue
		}
		res.LocalOnly = append(res.LocalOnly, host)
		// A partial answer may not demote. os-services being refused hides every
		// controller, and os-hypervisors being refused hides compute nodes whose
		// nova-compute is down — writing local-only from either would report a
		// change in the deployment when what changed was one API call.
		if !in.Complete {
			res.Held = append(res.Held, host)
			if err := touchMembership(ctx, tx, host, in.DeploymentID, at); err != nil {
				return res, err
			}
			continue
		}
		evidence := map[string]any{"local": true, "control": false}
		if err := upsertMembership(ctx, tx, host, in.DeploymentID, ConfidenceLocalOnly, evidence, at); err != nil {
			return res, err
		}
	}
	res.Ambiguous = ambiguous

	// Registered centrally with nothing found on the host. Not an error and not
	// something to delete: a compute node that is down still belongs to the
	// deployment, and a nova record for a machine that is gone is exactly what
	// somebody would want to see.
	//
	// No row is written for these — a membership needs a host in the inventory,
	// and by definition these are not matched to one. They are reported instead.
	for _, h := range in.ControlHosts {
		if !seen[h] {
			res.ControlOnly = append(res.ControlOnly, h)
		}
	}

	// Anything this deployment claimed on an earlier run and does not now is
	// stale. Dropping it beats leaving a host confirmed against evidence that
	// no longer exists.
	//
	// Skipped on a partial answer for the same reason demotion is: a host
	// missing from half a listing has not left the deployment. touchMembership
	// above keeps held rows current so this cannot sweep them either.
	if in.Complete {
		if _, err := tx.Exec(ctx, `
			DELETE FROM openstack_memberships
			WHERE deployment_id=$1 AND observed_at < $2`, in.DeploymentID, at); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
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

// MatchHosts pairs inventory hostnames with the names the control plane uses.
//
// nova writes its own names and they are shorter than the inventory's in more
// than one way. Measured across this fleet:
//
//	sre-srv-0059        ↔ sre-srv-0059                exact
//	sre-srv-0059        ↔ sre-srv-0059.internal       a domain suffix
//	incheon-aio01       ↔ aio01                       an inventory prefix
//
// The third is why this is not two lines. The incheon deployment names its
// hosts aio01/gpu01 while the inventory qualifies them by site, and matching
// only on exact and short names left all seven local-only — the deployment
// disowned every machine in it.
//
// # Why ambiguity is refused rather than resolved
//
// A short name can fit several inventory hosts, and picking one would be an
// inventory claiming a machine on the strength of a resemblance. Those are
// returned separately and confirmed for nobody. The rule is applied inside a
// single deployment's host list, which is what keeps it narrow enough to be
// safe at all.
func MatchHosts(local, control []string) (pairs map[string]string, ambiguous []string) {
	pairs = make(map[string]string, len(local))
	claimed := map[string]bool{}

	// Exact and domain-suffix first. These are unambiguous by construction, and
	// taking them before anything looser stops a weaker rule from stealing a
	// host that already has an exact match.
	byShort := map[string][]string{}
	for _, h := range local {
		byShort[shortName(h)] = append(byShort[shortName(h)], h)
	}
	remaining := make([]string, 0, len(control))
	for _, c := range control {
		cs := shortName(c)
		if hosts := byShort[cs]; len(hosts) == 1 {
			pairs[hosts[0]] = c
			claimed[hosts[0]] = true
			continue
		}
		remaining = append(remaining, c)
	}

	for _, c := range remaining {
		var hits []string
		for _, h := range local {
			if !claimed[h] && suffixMatch(h, shortName(c)) {
				hits = append(hits, h)
			}
		}
		switch len(hits) {
		case 0:
			// Not this deployment's, or a host nothing has probed. The caller
			// reports it as control-only.
		case 1:
			pairs[hits[0]] = c
			claimed[hits[0]] = true
		default:
			ambiguous = append(ambiguous, c)
		}
	}
	sort.Strings(ambiguous)
	return pairs, ambiguous
}

// shortName drops a domain suffix. sre-srv-0059.internal and sre-srv-0059 are
// one machine.
func shortName(h string) string {
	if s, _, ok := strings.Cut(h, "."); ok {
		return s
	}
	return h
}

// suffixMatch reports whether an inventory name is the control plane's name
// with a site prefix on it — incheon-aio01 against aio01.
//
// The boundary is required. Without it "u01" would match "sre-gpu01", and a
// name that merely ends in the same letters is not the same machine.
func suffixMatch(inventory, control string) bool {
	if control == "" || len(inventory) <= len(control) {
		return false
	}
	if !strings.EqualFold(inventory[len(inventory)-len(control):], control) {
		return false
	}
	switch inventory[len(inventory)-len(control)-1] {
	case '-', '_', '.':
		return true
	default:
		return false
	}
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
func (s *Store) SetDeploymentName(ctx context.Context, id, name, region string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO openstack_deployments (id, display_name, region, updated_at)
		VALUES ($1,$2,$3, now())
		ON CONFLICT (id) DO UPDATE SET
			display_name=EXCLUDED.display_name, region=EXCLUDED.region, updated_at=now()`,
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
func (s *Store) RecordReconcileRun(ctx context.Context, deployment string, res ReconcileResult, at time.Time, runErr error) error {
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

// ControlHost is a machine the control plane knows and the inventory does not.
type ControlHost struct {
	DeploymentID string    `json:"deployment_id"`
	NovaHostname string    `json:"nova_hostname"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// RecordControlHosts keeps the hosts nova named that no inventory entry matched.
//
// first_seen_at is preserved across runs: "nova has been telling us about this
// machine for three weeks" is a different statement from "this appeared today",
// and only the first is a registration somebody forgot.
//
// Rows are removed once they match an inventory host again — the caller passes
// only the still-unmatched names, and anything else for this deployment is
// deleted. Keeping them would leave a permanent list of problems already fixed.
func (s *Store) RecordControlHosts(ctx context.Context, deployment string, names []string, at time.Time) error {
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
			INSERT INTO openstack_control_hosts (deployment_id, nova_hostname, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,$3)
			ON CONFLICT (deployment_id, nova_hostname) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at`,
			deployment, n, at); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM openstack_control_hosts WHERE deployment_id=$1 AND last_seen_at < $2`,
		deployment, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ControlHosts lists the machines nova knows that the inventory does not.
func (s *Store) ControlHosts(ctx context.Context, deployment string) ([]ControlHost, error) {
	return controlHostsOn(ctx, s.pool, deployment)
}

func controlHostsOn(ctx context.Context, db rowQuerier, deployment string) ([]ControlHost, error) {
	q := `SELECT deployment_id, nova_hostname, first_seen_at, last_seen_at
		FROM openstack_control_hosts`
	var args []any
	if deployment != "" {
		q += ` WHERE deployment_id=$1`
		args = append(args, deployment)
	}
	return queryAndCollect(ctx, db, q+` ORDER BY deployment_id, nova_hostname`, args,
		func(r pgx.Rows) (ControlHost, error) {
			var c ControlHost
			err := r.Scan(&c.DeploymentID, &c.NovaHostname, &c.FirstSeenAt, &c.LastSeenAt)
			return c, err
		})
}
