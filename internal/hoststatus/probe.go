package hoststatus

import (
	"context"
	"fmt"
	"time"
)

// Probe reports one kind of platform a host may be part of — an OpenStack
// deployment, a Kubernetes cluster, a Ceph cluster.
//
// It is deliberately separate from Collect. Runtime status is load, memory and
// disk: cheap, always present, and meaningful on every host. A capability is
// neither — detecting OpenStack means reading unit files and running version
// commands, on the small fraction of hosts that have them. Folding that into
// Collect would make the heartbeat as slow and as fragile as its least reliable
// question.
//
// The rule that keeps that separation honest: a probe must never fail the
// heartbeat. A host with no OpenStack reports Detected=false and nothing else
// changes; a probe that errors reports the error and the rest of the status
// still lands.
type Probe interface {
	// Kind is the platform this probe knows about, e.g. "openstack". Stable —
	// it is a primary key column.
	Kind() string

	// Collect looks for the platform on this host. It must not modify the host.
	//
	// It must also honour ctx, and that is a requirement rather than a courtesy.
	// The runner's deadline is cooperative: it is passed in, not enforced, so a
	// Collect that ignores cancellation holds its caller for as long as it
	// likes and no timeout placed around it helps. Every external call inside a
	// probe — exec, HTTP, unix socket — takes the context for this reason.
	Collect(ctx context.Context) ProbeResult
}

// ProbeResult is what one probe found.
//
// Detected and Err are separate on purpose. "OpenStack is not installed here"
// and "we could not tell" are different facts, and a reader who cannot tell
// them apart will read an outage as an empty fleet. The store keeps the last
// good answer when a probe errors rather than deleting it.
type ProbeResult struct {
	Kind string

	// Detected is false when the platform is simply absent. Probes should be
	// conservative: a stray client package is not a deployment.
	Detected bool

	// Roles are what this host is built to do in that platform, e.g. compute,
	// controller. A host can hold several — a small deployment often runs
	// controller and network on one box.
	//
	// A service being deployed is what puts a role here, running or not. Only
	// counting running ones made the topology shrink during an outage: a
	// compute node whose nova-compute is down is still a compute node, and a
	// farm view that drops it reports the deployment as smaller at exactly the
	// moment somebody is looking because something broke.
	Roles []string

	// ActiveRoles are the subset with a running service behind them. The
	// difference between the two lists is the outage.
	ActiveRoles []string

	// Components are the parts that were found, keyed by name (nova-compute,
	// libvirt, qemu). Versions are per component because a rolling upgrade
	// leaves them different, and a single "OpenStack 2025.1" would be a guess
	// that reads as a fact.
	Components map[string]Component

	// Details carries anything role-specific that does not deserve a column.
	Details map[string]string

	// Err is set when the probe could not complete. Detected is meaningless
	// then, and the caller must not treat it as absence.
	Err error

	ObservedAt time.Time
}

// Component is one piece of software the probe found.
type Component struct {
	Version string `json:"version,omitempty"`
	Package string `json:"package,omitempty"`

	// Active is meaningful only when Service is true.
	Active bool `json:"active"`

	// Service says whether this component is something that runs, as opposed to
	// something that is only installed.
	//
	// Active alone could not carry the difference, and a listing built on it
	// rendered qemu — a binary the probe reads a version out of, with no daemon
	// and no unit — as a stopped service. On a healthy compute node that reads
	// as a fault and sends somebody to restart a package.
	Service bool `json:"service"`
}

// RunProbes collects from every probe, isolating each one.
//
// A panic in one probe is contained here: it becomes that probe's error and the
// others still run. A hang is not, and the difference matters. Each probe gets
// a deadline, but the deadline is handed to it — a probe that ignores
// cancellation runs as long as it wants and holds this loop with it. That is
// the contract on Probe.Collect, and it is the reason every external call in
// the OpenStack probe takes a context.
//
// Enforcing it here would mean running each Collect on its own goroutine and
// abandoning the ones that overrun. That trades a stuck loop for a leaked
// goroutine — and a leak parked in a syscall costs a thread, inside a unit
// capped at TasksMax=24. The cooperative deadline is the cheaper half of that
// trade as long as the contract holds, so the contract is written down and
// tested rather than assumed.
func RunProbes(ctx context.Context, probes []Probe, timeout time.Duration) []ProbeResult {
	out := make([]ProbeResult, 0, len(probes))
	for _, p := range probes {
		out = append(out, runOne(ctx, p, timeout))
	}
	return out
}

func runOne(ctx context.Context, p Probe, timeout time.Duration) (res ProbeResult) {
	// A probe shells out to commands this code does not own. A panic in one is
	// a bug, but it is not a reason for the host to stop reporting at all.
	defer func() {
		if r := recover(); r != nil {
			res = ProbeResult{Kind: p.Kind(), Err: errPanic(r), ObservedAt: time.Now()}
		}
	}()
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res = p.Collect(c)
	if res.Kind == "" {
		res.Kind = p.Kind()
	}
	if res.ObservedAt.IsZero() {
		res.ObservedAt = time.Now()
	}
	return res
}

type probePanic struct{ v any }

func (e probePanic) Error() string { return fmt.Sprintf("probe panicked: %v", e.v) }

func errPanic(v any) error { return probePanic{v} }
