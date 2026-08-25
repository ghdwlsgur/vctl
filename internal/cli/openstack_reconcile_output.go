package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack/reconcile"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// How a reconcile run reaches a person or a machine: the terminal rendering,
// the JSON wire shape, and the --fail-on vocabulary. Split from the port
// adapters, which are about reaching Nova and the store — one file was
// carrying four concerns under a name that promised one.

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
