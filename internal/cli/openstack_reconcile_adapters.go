package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/reconcile"
	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The adapters between this CLI and the reconcile service.
//
// Each one is the thinnest possible translation — Vault to credentials, the
// OpenStack client to two questions, the store to four writes. Nothing here
// decides anything; the decisions are in internal/openstack/reconcile, where
// they can be tested without a terminal, a Vault and a live control plane.

// vaultCredentials reads a deployment's admin credentials at use time.
type vaultCredentials struct{ app *app.App }

func (v vaultCredentials) ForFarm(ctx context.Context, id string) (openstackapi.Credentials, error) {
	path := vaultFarmPrefix + "/" + vaultFarmKey(id)
	secret, err := v.app.Vault.ReadKV(ctx, path)
	if err != nil {
		return openstackapi.Credentials{}, fmt.Errorf("no credentials at %s (%w)", path, err)
	}
	c := openstackapi.Credentials{
		AuthURL:     secret["auth_url"],
		Username:    secret["username"],
		Password:    secret["password"],
		ProjectName: secret["project_name"],
		UserDomain:  secret["user_domain"],
		ProjectDom:  secret["project_domain"],
	}
	if c.AuthURL == "" {
		// The deployment id is the endpoint's host; the scheme is not part of
		// it, so a stored auth_url is what says which one to use.
		return c, fmt.Errorf("credentials at %s carry no auth_url", path)
	}
	return c, nil
}

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
	if err != nil {
		// A partial page is still worth storing — a listing that stopped at the
		// cap has told us about everything it did reach — but say so.
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

func (r storeRepo) Reconcile(ctx context.Context, in store.ReconcileInput) (store.ReconcileResult, error) {
	return r.st.ReconcileDeployment(ctx, in)
}

func (r storeRepo) RecordRun(ctx context.Context, id string, res store.ReconcileResult, at time.Time, runErr error) error {
	return r.st.RecordReconcileRun(ctx, id, res, at, runErr)
}

func (r storeRepo) RecordControlHosts(ctx context.Context, id string, hosts []string, at time.Time) error {
	return r.st.RecordControlHosts(ctx, id, hosts, at)
}

func (r storeRepo) ReplaceInstances(ctx context.Context, id string, rows []store.Instance, at time.Time) (int, error) {
	return r.st.ReplaceInstances(ctx, id, rows, at)
}

// renderReconcile prints one run's report.
//
// Ordering matters and is the reason this is not a loop over fields: the
// partial-answer warning is said *before* the result because it changes what
// the result means — nothing below it was allowed to demote.
func renderReconcile(rep reconcile.Report, dry bool) {
	for _, o := range rep.Outcomes {
		switch {
		case o.NoCredentials != nil:
			ui.Warnf(os.Stderr, "%s: %v", o.ID, o.NoCredentials)
		case o.Unreachable != nil:
			ui.Errorf(os.Stderr, "%s: %v", o.ID, o.Unreachable)
		}
		// Before the warnings and before the result, where it was: a partial
		// answer changes what everything under it means, because nothing was
		// allowed to demote.
		if o.Partial != "" {
			ui.Warnf(os.Stderr, "%s: the control plane answered partially — %s", o.ID, o.Partial)
		}
		for _, w := range o.Warnings {
			ui.Warnf(os.Stderr, "%s: %v", o.ID, w)
		}
		if !o.Reconciled() {
			continue
		}
		if !dry && o.Instances > 0 {
			ui.Infof(os.Stdout, "%s: %d VMs", o.ID, o.Instances)
		}
		reportReconcile(o.ID, o.Result, dry)
	}
}
