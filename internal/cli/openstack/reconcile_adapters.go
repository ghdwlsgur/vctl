package openstack

import (
	"context"
	"fmt"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/openstack/reconcile"
	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// The adapters between this CLI and the reconcile service.
//
// Each one is the thinnest possible translation — the OpenStack client to two
// questions, the store to four writes (credentials moved to their own home,
// internal/openstack/farmcreds, when the doctor became their second consumer).
// Nothing here decides anything; the decisions are in
// internal/openstack/reconcile, where
// they can be tested without a terminal, a Vault and a live control plane.

// novaCloud asks one control plane. Each call gets its own deadline because the
// two questions take very different amounts of time.
type novaCloud struct{}

func (novaCloud) Hosts(ctx context.Context, c openstackapi.Credentials, insecure bool) (openstackapi.HostList, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	client, err := openstackapi.New(ctx, c, insecure, reconcileTimeout)
	if err != nil {
		return openstackapi.HostList{}, err
	}
	// Hosts, not Hypervisors: a controller runs nova-api and nova-conductor,
	// not a hypervisor, so asking only for hypervisors left every controller
	// permanently local-only — the farm confirmed its compute nodes and
	// disowned the machine running its own Keystone.
	return client.Hosts(ctx)
}

func (novaCloud) Instances(ctx context.Context, c openstackapi.Credentials, insecure bool) (reconcile.Listing, error) {
	ctx, cancel := context.WithTimeout(ctx, instanceTimeout)
	defer cancel()
	var out reconcile.Listing
	client, err := openstackapi.New(ctx, c, insecure, instanceTimeout)
	if err != nil {
		return out, err
	}
	list, err := client.Instances(ctx)
	out.Complete = err == nil
	if err != nil {
		// A partial page is still worth storing — a listing that stopped at the
		// cap has told us about everything it did reach — but it is a prefix,
		// and Complete=false is what stops the store reading the rest as gone.
		if len(list) == 0 {
			return out, err
		}
		out.Warnings = append(out.Warnings, fmt.Errorf("instances: %w", err))
	}
	out.Instances = list
	// Best effort. A listing of uuids is much better than no listing, so a
	// failure here is a warning and the names are simply absent.
	names, err := client.ProjectNames(ctx)
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Errorf("project names: %w", err))
	}
	out.ProjectNames = names
	return out, nil
}

// storeRepo is the store, narrowed to what a reconcile writes.
type storeRepo struct{ st *store.Store }

func (r storeRepo) Apply(ctx context.Context, d membership.Decision) error {
	return r.st.ApplyMembership(ctx, d)
}

func (r storeRepo) RecordRun(ctx context.Context, id string, res membership.Outcome, at time.Time, runErr error) error {
	return r.st.RecordReconcileRun(ctx, id, res, at, runErr)
}

func (r storeRepo) RecordGhostHosts(ctx context.Context, id string, hosts []string, at time.Time) error {
	return r.st.RecordGhostHosts(ctx, id, hosts, at)
}

func (r storeRepo) ReplaceInstances(ctx context.Context, id string, rows []store.Instance, at time.Time, complete bool) (int, error) {
	return r.st.ReplaceInstances(ctx, id, rows, at, complete)
}
