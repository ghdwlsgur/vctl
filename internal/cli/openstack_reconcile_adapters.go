package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
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

func (r storeRepo) RecordControlHosts(ctx context.Context, id string, hosts []string, at time.Time) error {
	return r.st.RecordControlHosts(ctx, id, hosts, at)
}

func (r storeRepo) ReplaceInstances(ctx context.Context, id string, rows []store.Instance, at time.Time, complete bool) (int, error) {
	return r.st.ReplaceInstances(ctx, id, rows, at, complete)
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

// reconcileJSON is the machine-readable shape of one run.
//
// Its own type rather than tags on the domain's Report: the Report carries
// errors, which do not marshal, and a wire shape that changes whenever an
// internal field does is not a contract anybody can automate against. What is
// here is what a timer or a dashboard needs — how much was asked, how much
// answered, and what each deployment did.
type reconcileJSON struct {
	StartedAt  time.Time           `json:"started_at"`
	DurationMS int64               `json:"duration_ms"`
	DryRun     bool                `json:"dry_run"`
	Farms      int                 `json:"farms"`
	Reached    int                 `json:"reached"`
	Failed     int                 `json:"unreachable"`
	NoCreds    int                 `json:"no_credentials"`
	Partial    int                 `json:"partial"`
	Warned     int                 `json:"warned"`
	Farms_     []reconcileFarmJSON `json:"deployments"`
}

type reconcileFarmJSON struct {
	ID            string   `json:"id"`
	Reached       bool     `json:"reached"`
	NoCredentials string   `json:"no_credentials,omitempty"`
	Unreachable   string   `json:"unreachable,omitempty"`
	Partial       string   `json:"partial,omitempty"`
	Confirmed     []string `json:"confirmed,omitempty"`
	LocalOnly     []string `json:"local_only,omitempty"`
	ControlOnly   []string `json:"control_only,omitempty"`
	Held          []string `json:"held,omitempty"`
	Ambiguous     []string `json:"ambiguous,omitempty"`
	Instances     int      `json:"instances"`
	Warnings      []string `json:"warnings,omitempty"`
}

func reconcileReportJSON(rep reconcile.Report, startedAt time.Time, took time.Duration, dry bool) reconcileJSON {
	out := reconcileJSON{
		StartedAt: startedAt, DurationMS: took.Milliseconds(), DryRun: dry,
		Farms: len(rep.Outcomes), Reached: rep.Reached,
		Failed: rep.Unreachable(), NoCreds: rep.NoCredentials(),
		Partial: rep.Partial(), Warned: rep.Warned(),
	}
	for _, o := range rep.Outcomes {
		f := reconcileFarmJSON{
			ID: o.ID, Reached: o.Reconciled(), Partial: o.Partial,
			Confirmed: o.Result.Confirmed, LocalOnly: o.Result.LocalOnly,
			ControlOnly: o.Result.ControlOnly, Held: o.Result.Held,
			Ambiguous: o.Result.Ambiguous, Instances: o.Instances,
		}
		if o.NoCredentials != nil {
			f.NoCredentials = o.NoCredentials.Error()
		}
		if o.Unreachable != nil {
			f.Unreachable = o.Unreachable.Error()
		}
		for _, w := range o.Warnings {
			f.Warnings = append(f.Warnings, w.Error())
		}
		out.Farms_ = append(out.Farms_, f)
	}
	return out
}

// parseFailOn turns the flag into the problems a run should exit non-zero for.
//
// Nothing by default, which keeps the existing contract: the run already fails
// when it reached nothing at all, and a timer that started exiting non-zero for
// a farm nobody has filed credentials for would be reporting the normal state
// of a new deployment as an incident.
func parseFailOn(v string) ([]reconcile.Problem, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	known := map[string]reconcile.Problem{
		string(reconcile.ProblemUnreachable):   reconcile.ProblemUnreachable,
		string(reconcile.ProblemNoCredentials): reconcile.ProblemNoCredentials,
		string(reconcile.ProblemPartial):       reconcile.ProblemPartial,
		string(reconcile.ProblemWarning):       reconcile.ProblemWarning,
	}
	var out []reconcile.Problem
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, ok := known[part]
		if !ok {
			return nil, fmt.Errorf("unknown --fail-on %q; pick from unreachable, no-credentials, partial, warning", part)
		}
		out = append(out, p)
	}
	return out, nil
}
