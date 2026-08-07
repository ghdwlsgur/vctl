// Package membership decides which hosts a deployment owns.
//
// Two observations arrive and neither is enough on its own. A probe on a host
// says "this machine runs OpenStack and points at this Keystone", which does
// not prove membership: two unrelated deployments behind one proxy look
// identical from a host. The control plane says "these are my hypervisors",
// which does not prove the host is still there, and returns nova's names rather
// than the inventory's. Agreement between the two is the only thing that
// confirms anything.
//
// Everything here is a decision and nothing here is a write. That split is the
// point: the rules used to live inside the transaction that applied them, so
// the only way to ask "what would this run do" was to do it, and `--dry-run`
// had to be a second implementation that agreed with the first by inspection.
// Decide answers that question, and applying its answer is somebody else's job.
//
// It also means the host-name matching is reachable without a database. `vctl
// openstack vm --host` resolves an inventory name to nova's name for the same
// machine, and it was calling into the persistence layer to do it.
package membership

import (
	"sort"
	"strings"
	"time"
)

// Confidence says what a membership row rests on, in the order automation
// should trust it. Only the first two are statements; the rest are
// observations.
//
// The values are what goes in the column, and store re-exports them for the
// readers that compare against it — one definition, so a rename cannot leave
// half the codebase writing a word the other half does not recognise.
const (
	// Declared: an identifier somebody placed on the host on purpose.
	Declared = "declared"
	// Confirmed: local evidence and the control plane agree.
	Confirmed = "confirmed"
	// LocalOnly: the host runs the services, nothing has confirmed which
	// deployment they belong to.
	LocalOnly = "local-only"
	// ControlOnly: registered centrally, nothing found on the host.
	ControlOnly = "control-only"
	// Conflict: the evidence disagrees.
	Conflict = "conflict"
)

// Observation is one deployment's two sides, as collected.
type Observation struct {
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

	// Complete says whether the control plane answered fully. A partial answer
	// may confirm, because a host both sides name is confirmed either way — but
	// it may not demote, because absence from a partial list is not evidence of
	// absence from the deployment.
	Complete bool

	At time.Time
}

// Decision is everything a run wants written, and what it will report.
//
// It carries no SQL and no order of operations — just what should be true
// afterwards. A caller that applies it must do so atomically: a partial write
// would leave some hosts confirmed against a control-plane read that never
// finished, which is worse than not having run at all.
type Decision struct {
	DeploymentID string

	// Facts are the deployment's own fields. Empty means "not carrying this",
	// never "clear it" — the reconciler knows a farm's endpoint and nothing
	// else about it, and a name somebody set with `farm name` must survive it.
	DisplayName string
	Region      string
	KeystoneURL string

	// Hosts is one entry per inventory host this deployment claims.
	Hosts []HostDecision

	// SweepStale drops membership rows this deployment claimed on an earlier
	// run and does not now. False on an incomplete answer: a host missing from
	// half a listing has not left the deployment.
	SweepStale bool

	At time.Time

	// Outcome is the same decision as something to report.
	Outcome Outcome
}

// HostDecision is what to record for one host.
type HostDecision struct {
	Hostname string

	// Confidence is empty for a host the run may not speak for — see Held. The
	// row is left saying whatever it said, and only its observation time moves,
	// so the stale sweep cannot take it.
	Confidence string
	Evidence   map[string]any
}

// Holds reports whether this host is being kept rather than judged.
func (h HostDecision) Holds() bool { return h.Confidence == "" }

// Outcome reports what a run settled, for whoever is watching it.
type Outcome struct {
	DeploymentID string
	Confirmed    []string
	LocalOnly    []string
	ControlOnly  []string

	// Ambiguous are control-plane names that could belong to more than one
	// inventory host. They are reported rather than resolved: guessing which
	// machine a name means is how an inventory starts claiming the wrong one.
	Ambiguous []string

	// Held are hosts an incomplete answer would have demoted and did not. They
	// keep whatever confidence they had; this names them so the run does not
	// look like it confirmed them.
	Held []string

	// Complete mirrors the observation, so a caller rendering this can say
	// whether the run was allowed to settle anything.
	Complete bool
}

// Decide turns one observation into what should be recorded.
//
// Pure, and that is what makes `--dry-run` the same code as the real run rather
// than a second implementation of it.
func Decide(obs Observation) Decision {
	at := obs.At
	if at.IsZero() {
		at = time.Now()
	}
	d := Decision{
		DeploymentID: obs.DeploymentID,
		DisplayName:  obs.DisplayName,
		Region:       obs.Region,
		KeystoneURL:  obs.KeystoneURL,
		SweepStale:   obs.Complete,
		At:           at,
		Outcome:      Outcome{DeploymentID: obs.DeploymentID, Complete: obs.Complete},
	}

	pairs, ambiguous := MatchHosts(obs.LocalHosts, obs.ControlHosts)
	matched := map[string]bool{}

	for _, host := range obs.LocalHosts {
		novaName, agreed := pairs[host]
		if agreed {
			matched[novaName] = true
			d.Outcome.Confirmed = append(d.Outcome.Confirmed, host)
			d.Hosts = append(d.Hosts, HostDecision{
				Hostname:   host,
				Confidence: Confirmed,
				Evidence:   map[string]any{"local": true, "control": true, "nova_hostname": novaName},
			})
			continue
		}
		d.Outcome.LocalOnly = append(d.Outcome.LocalOnly, host)
		// A partial answer may not demote. os-services being refused hides
		// every controller, and os-hypervisors being refused hides compute
		// nodes whose nova-compute is down — writing local-only from either
		// would report a change in the deployment when what changed was one API
		// call.
		if !obs.Complete {
			d.Outcome.Held = append(d.Outcome.Held, host)
			d.Hosts = append(d.Hosts, HostDecision{Hostname: host})
			continue
		}
		d.Hosts = append(d.Hosts, HostDecision{
			Hostname:   host,
			Confidence: LocalOnly,
			Evidence:   map[string]any{"local": true, "control": false},
		})
	}
	d.Outcome.Ambiguous = ambiguous

	// Registered centrally with nothing found on the host. Not an error and not
	// something to delete: a compute node that is down still belongs to the
	// deployment, and a nova record for a machine that is gone is exactly what
	// somebody would want to see.
	//
	// No row is decided for these — a membership needs a host in the inventory,
	// and by definition these are not matched to one. They are reported.
	for _, h := range obs.ControlHosts {
		if !matched[h] {
			d.Outcome.ControlOnly = append(d.Outcome.ControlOnly, h)
		}
	}
	return d
}

// MatchHosts pairs inventory hostnames with the control plane's names for the
// same machines.
//
// They are not the same strings. Nova reports what the host called itself when
// nova-compute registered — aio01 — while the inventory calls it
// incheon-aio01, and either may carry a domain suffix the other does not.
//
// Ambiguity is returned rather than resolved. A control-plane name that could
// be two inventory hosts is a question about which machine somebody means, and
// answering it by picking one is how an inventory starts claiming the wrong
// machine.
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
