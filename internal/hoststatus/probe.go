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

	// Collect looks for the platform on this host. It must return promptly and
	// must not modify the host.
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

	// Roles are what this host does in that platform, e.g. compute, controller.
	// A host can hold several — a small deployment often runs controller and
	// network on one box.
	Roles []string

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
	Active  bool   `json:"active"`
}

// RunProbes collects from every probe, isolating each one.
//
// A probe that panics or hangs must not take the others with it, and must not
// take the heartbeat with it either — this returns whatever completed and lets
// the caller report the rest.
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
