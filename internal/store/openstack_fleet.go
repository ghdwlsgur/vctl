package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Fleet is every OpenStack fact, read at one instant.
//
// FarmSnapshot does this for one deployment and for the same reason. The
// fleet-wide readers had no equivalent, so each of them opened its own reads:
// the listing read hosts and deployments, `farm list` read those plus runs and
// instances, the browser read all four and then read hosts and deployments a
// second time through the picker's own assembly. Nothing serialised them, so a
// screen could show a farm's host count from before a reconcile beside its VM
// count from after — a picture of a moment that never existed.
//
// It is also four round trips instead of one transaction, on every command that
// names a farm.
type Fleet struct {
	Deployments []Deployment
	// Hosts are folded per host — current roles separated from dropped ones,
	// membership attached — exactly as OpenStackHosts returns them.
	Hosts []OpenStackHost
	// Instances are the VM rows, and only the full reading has them. A screen
	// that lists VMs needs them; one that counts them does not, and fetching
	// every instance with its addresses to print a number is most of what a
	// listing costs.
	Instances []Instance
	// VMs and Gone are the counts, present in both readings.
	VMs  map[string]int
	Gone map[string]int
	Runs map[string]ReconcileRun

	// InventoryHosts counts the whole inventory minus parked machines, which is
	// what coverage is a fraction of. It is not derivable from Hosts: a host
	// nothing has probed has no capability row and so appears nowhere above.
	InventoryHosts int

	// ReadAt is when the transaction took its snapshot. A reader showing this
	// is telling the truth about how old every number in it is.
	ReadAt time.Time
}

// FleetFarms reads what identifies a deployment: the declared rows, the probed
// hosts, and the size of the fleet they are a fraction of.
//
// No transaction and no instances, because this is what resolving a typed word
// and drawing a picker need, and both are on paths where latency is the point.
// Shell completion reads through here on every Tab.
//
// Each statement is a round trip, and round trips are what these commands cost:
// measured against this database, wrapping the same reads in a repeatable-read
// transaction and adding two statements for a timestamp and an aggregate made
// every listing 90–120ms slower. Consistency across statements buys nothing
// here — nothing below is compared against anything else — so it is not bought.
func (s *Store) FleetFarms(ctx context.Context) (Fleet, error) {
	out := Fleet{ReadAt: time.Now()}
	var err error
	if out.Hosts, err = openStackHostsOn(ctx, s.pool); err != nil {
		return out, err
	}
	if out.Deployments, err = deploymentsOn(ctx, s.pool); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM servers WHERE coalesce(state,'active') <> ALL($1)`,
		[]string{StateMaintenance, StateRetired}).Scan(&out.InventoryHosts); err != nil {
		return out, err
	}
	return out, nil
}

// FleetSnapshot reads the whole OpenStack picture in one repeatable-read
// transaction.
//
// Read-only so it cannot block a writer or be chosen as a deadlock victim, and
// REPEATABLE READ so every statement below sees the same snapshot — which is
// the entire reason this exists rather than four calls in a row.
//
// Missing VMs are included, as they are in FarmSnapshot: a caller counting what
// went away needs them, and one listing what is running filters them. Deciding
// that here would take the choice from both.
func (s *Store) FleetSnapshot(ctx context.Context) (Fleet, error) {
	return s.fleet(ctx, false)
}

// FleetSnapshotWithVMs is the same reading with the instance rows in it, for
// the one screen that lists them.
//
// Separate because the rows are what the reading costs: fetching every instance
// with its addresses to print "34 VMs" measured 116ms on this fleet, for a
// number the aggregate below already had.
func (s *Store) FleetSnapshotWithVMs(ctx context.Context) (Fleet, error) {
	return s.fleet(ctx, true)
}

func (s *Store) fleet(ctx context.Context, withVMs bool) (Fleet, error) {
	var out Fleet
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&out.ReadAt); err != nil {
		return out, err
	}
	if out.Hosts, err = openStackHostsOn(ctx, tx); err != nil {
		return out, err
	}
	if out.Deployments, err = deploymentsOn(ctx, tx); err != nil {
		return out, err
	}
	if withVMs {
		if out.Instances, err = instancesOn(ctx, tx, InstanceFilter{IncludeMissing: true}); err != nil {
			return out, err
		}
	}
	// The counts either way. An aggregate is cheap where the rows are not, and
	// a caller that only ever prints "34 VMs" should not pay for the rows to
	// arrive.
	if out.VMs, out.Gone, err = instanceCountsOn(ctx, tx); err != nil {
		return out, err
	}
	if out.Runs, err = reconcileRunsOn(ctx, tx); err != nil {
		return out, err
	}
	// The same set OpenStackCoverageOf counts, so the denominator and the
	// listing agree — they disagreed once already, and a summary that
	// contradicts the table above it is worse than no summary.
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM servers WHERE coalesce(state,'active') <> ALL($1)`,
		[]string{StateMaintenance, StateRetired}).Scan(&out.InventoryHosts); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// instanceCountsOn counts the VMs per deployment, split by whether the control
// plane still lists them.
//
// Two counts rather than one, because "gone" is a different fact from a smaller
// number of the same one: a farm that lost nine VMs and one that never had them
// read identically through a single total.
func instanceCountsOn(ctx context.Context, db rowQuerier) (live, gone map[string]int, err error) {
	type row struct {
		Deployment    string
		Live, Missing int
	}
	rows, err := queryAndCollect(ctx, db, `
		SELECT deployment_id,
		       count(*) FILTER (WHERE missing_since IS NULL),
		       count(*) FILTER (WHERE missing_since IS NOT NULL)
		FROM openstack_instances GROUP BY deployment_id`, nil,
		func(r pgx.Rows) (row, error) {
			var v row
			err := r.Scan(&v.Deployment, &v.Live, &v.Missing)
			return v, err
		})
	if err != nil {
		return nil, nil, err
	}
	live, gone = map[string]int{}, map[string]int{}
	for _, v := range rows {
		live[v.Deployment] = v.Live
		gone[v.Deployment] = v.Missing
	}
	return live, gone, nil
}
