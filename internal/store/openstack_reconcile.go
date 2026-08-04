package store

import (
	"context"
	"encoding/json"
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
}

// ReconcileDeployment records one deployment and the membership of its hosts.
//
// Runs in a transaction: a partial write would leave some hosts confirmed
// against a control-plane read that never finished, which is worse than not
// having run at all.
func (s *Store) ReconcileDeployment(ctx context.Context, in ReconcileInput) (ReconcileResult, error) {
	res := ReconcileResult{DeploymentID: in.DeploymentID}
	at := in.ObservedAt
	if at.IsZero() {
		at = time.Now()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO openstack_deployments (id, display_name, region, keystone_url, updated_at)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (id) DO UPDATE SET
			display_name=EXCLUDED.display_name, region=EXCLUDED.region,
			keystone_url=EXCLUDED.keystone_url, updated_at=now()`,
		in.DeploymentID, in.DisplayName, in.Region, in.KeystoneURL); err != nil {
		return res, err
	}

	pairs, ambiguous := MatchHosts(in.LocalHosts, in.ControlHosts)
	seen := map[string]bool{}

	for _, host := range in.LocalHosts {
		novaName, agreed := pairs[host]
		confidence := ConfidenceLocalOnly
		evidence := map[string]any{"local": true, "control": false}
		if agreed {
			confidence = ConfidenceConfirmed
			evidence = map[string]any{"local": true, "control": true, "nova_hostname": novaName}
			seen[novaName] = true
			res.Confirmed = append(res.Confirmed, host)
		} else {
			res.LocalOnly = append(res.LocalOnly, host)
		}
		if err := upsertMembership(ctx, tx, host, in.DeploymentID, confidence, evidence, at); err != nil {
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
	if _, err := tx.Exec(ctx, `
		DELETE FROM openstack_memberships
		WHERE deployment_id=$1 AND observed_at < $2`, in.DeploymentID, at); err != nil {
		return res, err
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
}

// SetDeploymentName gives a farm a name people can read.
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
	return queryAndCollect(ctx, s.pool, `
		SELECT id, display_name, region, keystone_url
		FROM openstack_deployments ORDER BY id`, nil,
		func(r pgx.Rows) (Deployment, error) {
			var d Deployment
			err := r.Scan(&d.ID, &d.DisplayName, &d.Region, &d.KeystoneURL)
			return d, err
		})
}
