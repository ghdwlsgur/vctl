package store

import (
	"context"
	"encoding/json"
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

	// The control plane names hosts its own way. Matching on the short name as
	// well as the full one is what lets a nova host of "sre-srv-0059" meet an
	// inventory entry of "sre-srv-0059.internal" — and matching no further than
	// that is deliberate, because a looser rule would start pairing hosts by
	// resemblance.
	control := map[string]string{}
	for _, h := range in.ControlHosts {
		control[h] = h
		if short, _, ok := strings.Cut(h, "."); ok {
			control[short] = h
		}
	}
	seen := map[string]bool{}

	for _, host := range in.LocalHosts {
		short := host
		if s, _, ok := strings.Cut(host, "."); ok {
			short = s
		}
		novaName, agreed := control[host]
		if !agreed {
			novaName, agreed = control[short]
		}
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
