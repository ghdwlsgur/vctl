// Package reconcile settles which hosts a deployment owns.
//
// The probe on a host can only say which Keystone it points at. Two unrelated
// deployments behind one proxy look identical from there, so that inference is
// recorded as local-only and this asks the control plane which hosts it
// actually owns.
//
// # Why this is not in the CLI
//
// It used to be one Cobra RunE and a 70-line loop underneath it, holding flag
// parsing, Vault paths, HTTP clients, the database, the policy for what a
// failure means, and the printing. Most of that is not about reconciling.
//
// The policy is the part worth protecting: what happens when a farm has no
// credentials filed, when the control plane cannot be reached, when it answers
// half a question, when the bookkeeping write fails but the reconcile did not.
// Every one of those decisions has a reason, several were learned the hard way,
// and none of them could be tested without a terminal, a Vault and a live
// OpenStack. Now they can.
//
// It also means one implementation. A systemd timer, this CLI, and whatever
// asks next all reconcile the same way — rather than each growing its own idea
// of what a partial answer is worth.
package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// Farm is one deployment to reconcile, with the hosts the probes put in it.
type Farm struct {
	ID string
	// LocalHosts are inventory hostnames whose probe pointed at this
	// deployment. Sorted by the caller so a report reads the same twice.
	LocalHosts []string
}

type Request struct {
	Farms []Farm
	// Insecure skips TLS verification against the control plane, for the
	// deployments still on self-signed certificates.
	Insecure bool
	// DryRun computes what would change and writes nothing — not the
	// membership, not the run record, not the VM listing.
	DryRun bool
}

// Outcome is what happened to one deployment. Every field is something a
// reader may need to act on, and none of them is an exception in flight: a farm
// failing is a fact about that farm, not a reason to abandon the others.
type Outcome struct {
	ID string

	// NoCredentials is set when nobody has filed this farm's credentials yet.
	// The normal state of a new deployment, and not a failure of the run.
	NoCredentials error

	// Unreachable is set when the control plane could not be asked at all.
	// Nothing was written except the record of this failure.
	Unreachable error

	// Partial names which half of the answer is missing, and is empty when the
	// control plane answered fully. It changes what the result means, because
	// nothing may be demoted on a partial answer.
	Partial string

	Result membership.Outcome

	// Instances is how many VMs were recorded, and Warnings holds everything
	// that went wrong without being worth failing over.
	Instances int
	Warnings  []error
}

// Reconciled reports whether this farm's membership was settled.
func (o Outcome) Reconciled() bool { return o.NoCredentials == nil && o.Unreachable == nil }

type Report struct {
	Outcomes []Outcome
	// Reached counts the deployments whose control plane answered. Zero means
	// the run established nothing, which is worth failing on: a silent success
	// there reads as "everything agrees".
	Reached int
}

// Credentials hands out one deployment's admin credentials at use time.
type Credentials interface {
	ForFarm(ctx context.Context, id string) (openstackapi.Credentials, error)
}

// Listing is what one conversation with a control plane produced.
//
// Warnings are carried rather than returned as errors because a partial answer
// is still an answer: a listing that stopped at its cap has told us about
// everything it did reach, and dropping it would lose more than it protects.
type Listing struct {
	Instances    []openstackapi.Instance
	ProjectNames map[string]string
	Warnings     []error

	// Complete says the listing is the whole deployment rather than a prefix of
	// it. A pass that stopped early must not let the store mark everything it
	// did not reach as gone — an API answering half a question would render as
	// a deployment that lost half its VMs.
	Complete bool
}

// Cloud is the control plane, reduced to the two questions asked of it.
type Cloud interface {
	Hosts(ctx context.Context, c openstackapi.Credentials, insecure bool) (openstackapi.HostList, error)
	Instances(ctx context.Context, c openstackapi.Credentials, insecure bool) (Listing, error)
}

// Repository is the writing half. Narrow on purpose: the reconciler has no
// business with the rest of the store, and an interface that mirrored the table
// would grow every time something unrelated did.
type Repository interface {
	// Apply records a decision. It does not make one — see
	// internal/openstack/membership, and Preview, which is the same decision
	// with nothing written.
	Apply(ctx context.Context, d membership.Decision) error
	RecordRun(ctx context.Context, id string, r membership.Outcome, at time.Time, runErr error) error
	RecordGhostHosts(ctx context.Context, id string, hosts []string, at time.Time) error
	ReplaceInstances(ctx context.Context, id string, rows []store.Instance, at time.Time, complete bool) (int, error)
}

type Service struct {
	Creds Credentials
	Cloud Cloud
	Repo  Repository
	// Now is injected so a test can assert on what was recorded rather than on
	// what time it happens to be.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ErrNothingReached is returned when no deployment's control plane answered.
//
// A run that reached nothing has confirmed nothing, and reporting that as
// success is how a broken credential or a closed route becomes invisible: the
// listing keeps showing whatever the last working run left behind.
var ErrNothingReached = fmt.Errorf("no deployment could be reached; nothing was confirmed")

// Run reconciles each deployment in turn.
//
// One farm's failure does not stop the others — the deployments are unrelated,
// and a run that abandons five because the first has no credentials filed is a
// run nobody can use. The one exception is a database failure while writing
// membership: that is not about this farm, and continuing would keep writing
// into something that is not answering.
func (s *Service) Run(ctx context.Context, req Request) (Report, error) {
	var rep Report
	for _, f := range req.Farms {
		out := Outcome{ID: f.ID}

		creds, err := s.Creds.ForFarm(ctx, f.ID)
		if err != nil {
			// Not a failure of the run. A deployment with no credentials filed
			// is the normal state until somebody files them.
			out.NoCredentials = err
			rep.Outcomes = append(rep.Outcomes, out)
			continue
		}

		list, err := s.Cloud.Hosts(ctx, creds, req.Insecure)
		if err != nil {
			out.Unreachable = err
			// Recorded so the listing can say this farm has not settled since,
			// and why. Without it a farm failing every six hours is
			// indistinguishable from one nobody has configured.
			if !req.DryRun {
				if e := s.Repo.RecordRun(ctx, f.ID, membership.Outcome{}, s.now(), err); e != nil {
					out.Warnings = append(out.Warnings, fmt.Errorf("recording the failure: %w", e))
				}
			}
			rep.Outcomes = append(rep.Outcomes, out)
			continue
		}
		rep.Reached++
		if !list.Complete {
			out.Partial = PartialReason(list)
		}

		if req.DryRun {
			out.Result = Preview(f.LocalHosts, list.Hosts)
			out.Result.Complete = list.Complete
			rep.Outcomes = append(rep.Outcomes, out)
			continue
		}

		out.Instances, out.Warnings = s.collectInstances(ctx, f.ID, creds, req.Insecure, out.Warnings)

		// Decided here, written below. The decision is the same function
		// --dry-run calls, so what a preview showed is what a run does.
		decision := membership.Decide(membership.Observation{
			DeploymentID: f.ID, KeystoneURL: f.ID,
			LocalHosts: f.LocalHosts, ControlHosts: list.Hosts,
			Complete: list.Complete,
			At:       s.now(),
		})
		if err := s.Repo.Apply(ctx, decision); err != nil {
			return rep, fmt.Errorf("%s: %w", f.ID, err)
		}
		out.Result = decision.Outcome
		if e := s.Repo.RecordRun(ctx, f.ID, decision.Outcome, s.now(), nil); e != nil {
			out.Warnings = append(out.Warnings, fmt.Errorf("recording the run: %w", e))
		}
		// The hosts nova named that no inventory entry matched. Printing them
		// and moving on lost the most interesting rows the reconciler produces:
		// a nova service on a machine nobody has registered is either a
		// forgotten host, a name that drifted, or something that should not be
		// running — and none of those survives being said once.
		if e := s.Repo.RecordGhostHosts(ctx, f.ID, decision.Outcome.ControlOnly, s.now()); e != nil {
			out.Warnings = append(out.Warnings, fmt.Errorf("recording control-only hosts: %w", e))
		}
		rep.Outcomes = append(rep.Outcomes, out)
	}
	if rep.Reached == 0 {
		return rep, ErrNothingReached
	}
	return rep, nil
}

// collectInstances records the deployment's VMs alongside its membership.
//
// Same pass as the reconcile because it is the same conversation with the same
// control plane, and a separate schedule would mean two credentials, two
// timers, and two chances for one of them to be the stale one.
//
// A failure here never fails the reconcile. Membership and the VM listing
// answer different questions, and a deployment that cannot list servers can
// still say which hosts are its own.
func (s *Service) collectInstances(ctx context.Context, id string,
	c openstackapi.Credentials, insecure bool, warnings []error) (int, []error) {
	list, err := s.Cloud.Instances(ctx, c, insecure)
	warnings = append(warnings, list.Warnings...)
	if err != nil {
		return 0, append(warnings, fmt.Errorf("instances: %w", err))
	}
	rows := make([]store.Instance, 0, len(list.Instances))
	for _, i := range list.Instances {
		row := ToStoreInstance(id, i)
		// Nova reports an owner as a bare uuid and Keystone is the only place
		// the name exists. A run that could not resolve them leaves the column
		// alone rather than blanking what an earlier run found.
		row.ProjectName = list.ProjectNames[row.ProjectID]
		rows = append(rows, row)
	}
	n, err := s.Repo.ReplaceInstances(ctx, id, rows, s.now(), list.Complete)
	if err != nil {
		return 0, append(warnings, fmt.Errorf("instances: %w", err))
	}
	return n, warnings
}

// PartialReason names which half of the answer is missing, because the two have
// different consequences: no os-services hides controllers, no os-hypervisors
// hides compute nodes whose nova-compute is down.
func PartialReason(l openstackapi.HostList) string {
	switch {
	case l.HypervisorError != "" && l.ServiceError != "":
		return "neither endpoint answered"
	case l.ServiceError != "":
		return "os-services: " + l.ServiceError + " (controllers are not listed)"
	case l.HypervisorError != "":
		return "os-hypervisors: " + l.HypervisorError + " (stopped compute nodes are not listed)"
	default:
		return "incomplete"
	}
}

// Preview computes what a run would decide, without writing.
//
// The same function the run itself calls, so a dry run cannot decide
// differently from the real one. It used to restate the rule — the matcher was
// shared but the loop around it was written twice — and a preview that
// disagrees with what follows is worse than having none: it invites approving a
// change that then does something else.
func Preview(local, control []string) membership.Outcome {
	return membership.Decide(membership.Observation{
		LocalHosts: local, ControlHosts: control, Complete: true,
	}).Outcome
}

// ToStoreInstance converts one Nova server into the row that is stored.
func ToStoreInstance(deployment string, i openstackapi.Instance) store.Instance {
	out := store.Instance{
		DeploymentID: deployment, InstanceID: i.ID, ProjectID: i.ProjectID, Name: i.Name,
		Status: i.Status, PowerState: i.PowerState, TaskState: i.TaskState,
		AvailabilityZone: i.AvailabilityZone, HypervisorHostname: i.HypervisorHostname,
		FlavorID: i.FlavorID, ImageID: i.ImageID,
	}
	if !i.Created.IsZero() {
		t := i.Created
		out.CreatedAt = &t
	}
	if !i.Updated.IsZero() {
		t := i.Updated
		out.UpdatedAt = &t
	}
	for _, a := range i.Addresses {
		out.Addresses = append(out.Addresses, store.InstanceAddress{
			NetworkName: a.NetworkName, Address: a.Address, Type: a.Type, IPVersion: a.IPVersion,
		})
	}
	return out
}

// What a run went wrong at, counted. A caller decides which of these is worth
// failing over; this package only says what happened.
func (r Report) Unreachable() int {
	return r.count(func(o Outcome) bool { return o.Unreachable != nil })
}
func (r Report) NoCredentials() int {
	return r.count(func(o Outcome) bool { return o.NoCredentials != nil })
}
func (r Report) Partial() int { return r.count(func(o Outcome) bool { return o.Partial != "" }) }
func (r Report) Warned() int  { return r.count(func(o Outcome) bool { return len(o.Warnings) > 0 }) }

func (r Report) count(pred func(Outcome) bool) int {
	var n int
	for _, o := range r.Outcomes {
		if pred(o) {
			n++
		}
	}
	return n
}

// Problem is something a run can be asked to fail over.
type Problem string

const (
	// ProblemUnreachable — a control plane could not be asked at all.
	ProblemUnreachable Problem = "unreachable"
	// ProblemNoCredentials — a deployment has none filed. The normal state of a
	// new farm, which is why it is not a failure by default.
	ProblemNoCredentials Problem = "no-credentials"
	// ProblemPartial — a control plane answered half a question, so nothing was
	// demoted and the picture is incomplete.
	ProblemPartial Problem = "partial"
	// ProblemWarning — anything the run carried but did not stop for.
	ProblemWarning Problem = "warning"
)

// FailOn reports whether any of the named problems occurred.
//
// Separate from Run because it is a policy question, and the answer differs by
// caller: a person running this by hand wants to see the farms that failed and
// carry on, while a timer wants a non-zero exit so somebody is told. Run's own
// error covers only the case where nothing was reached at all — that one is not
// a policy, because a run that established nothing has no result to report.
func (r Report) FailOn(problems []Problem) []Problem {
	var hit []Problem
	for _, p := range problems {
		var n int
		switch p {
		case ProblemUnreachable:
			n = r.Unreachable()
		case ProblemNoCredentials:
			n = r.NoCredentials()
		case ProblemPartial:
			n = r.Partial()
		case ProblemWarning:
			n = r.Warned()
		}
		if n > 0 {
			hit = append(hit, p)
		}
	}
	return hit
}
