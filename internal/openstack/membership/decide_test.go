package membership

import (
	"slices"
	"testing"
	"time"
)

// held reports whether the decision is keeping this host rather than judging it.
func held(d Decision, host string) bool {
	for _, h := range d.Hosts {
		if h.Hostname == host {
			return h.Holds()
		}
	}
	return false
}

func confidenceOf(d Decision, host string) string {
	for _, h := range d.Hosts {
		if h.Hostname == host {
			return h.Confidence
		}
	}
	return "<no decision>"
}

// Agreement is the only thing that confirms. A probe pointing at a Keystone
// does not prove membership — two deployments behind one proxy look identical
// from a host — and a nova record does not prove the machine is still there.
func TestAgreementConfirmsAndDisagreementDoesNot(t *testing.T) {
	d := Decide(Observation{
		DeploymentID: "farm-a",
		LocalHosts:   []string{"sre-srv-0001", "sre-srv-0002"},
		ControlHosts: []string{"sre-srv-0001", "ghost-01"},
		Complete:     true,
	})

	if got := confidenceOf(d, "sre-srv-0001"); got != Confirmed {
		t.Errorf("a host both sides name is %q, want confirmed", got)
	}
	if got := confidenceOf(d, "sre-srv-0002"); got != LocalOnly {
		t.Errorf("a host only the probe found is %q, want local-only", got)
	}
	if !slices.Contains(d.Outcome.ControlOnly, "ghost-01") {
		t.Errorf("control-only = %v, want the name only nova knows", d.Outcome.ControlOnly)
	}
	// Registered centrally with nothing found on the host is reported, never
	// written: a membership needs an inventory host, and by definition this is
	// not matched to one.
	for _, h := range d.Hosts {
		if h.Hostname == "ghost-01" {
			t.Error("a row was decided for a host no inventory entry matches")
		}
	}
}

// A partial answer may confirm and may not demote. os-services being refused
// hides every controller; os-hypervisors being refused hides compute nodes
// whose nova-compute is down. Writing local-only from either would report a
// change in the deployment when what changed was one API call.
func TestAPartialAnswerConfirmsButNeverDemotes(t *testing.T) {
	obs := Observation{
		DeploymentID: "farm-a",
		LocalHosts:   []string{"sre-srv-0001", "sre-srv-0002"},
		ControlHosts: []string{"sre-srv-0001"},
	}
	partial := Decide(obs)
	if got := confidenceOf(partial, "sre-srv-0001"); got != Confirmed {
		t.Errorf("agreement is agreement even in half an answer: %q", got)
	}
	if !held(partial, "sre-srv-0002") {
		t.Errorf("an unmatched host was judged on a partial answer: %q",
			confidenceOf(partial, "sre-srv-0002"))
	}
	if !slices.Contains(partial.Outcome.Held, "sre-srv-0002") {
		t.Errorf("held = %v, want the host that was not spoken for", partial.Outcome.Held)
	}
	// A host missing from half a listing has not left the deployment.
	if partial.SweepStale {
		t.Error("a partial answer would sweep rows it could not speak for")
	}

	obs.Complete = true
	full := Decide(obs)
	if got := confidenceOf(full, "sre-srv-0002"); got != LocalOnly {
		t.Errorf("a complete answer left the host at %q, want local-only", got)
	}
	if len(full.Outcome.Held) != 0 {
		t.Errorf("a complete answer held %v", full.Outcome.Held)
	}
	if !full.SweepStale {
		t.Error("a complete answer must drop what this deployment no longer claims")
	}
}

// The evidence is what makes a row re-readable later: which side saw the host,
// and what nova called it.
func TestAConfirmedRowCarriesWhatConfirmedIt(t *testing.T) {
	d := Decide(Observation{
		DeploymentID: "farm-a",
		LocalHosts:   []string{"incheon-aio01"},
		ControlHosts: []string{"aio01"},
		Complete:     true,
	})
	for _, h := range d.Hosts {
		if h.Hostname != "incheon-aio01" {
			continue
		}
		if h.Evidence["local"] != true || h.Evidence["control"] != true {
			t.Errorf("evidence = %v, want both sides recorded", h.Evidence)
		}
		if h.Evidence["nova_hostname"] != "aio01" {
			t.Errorf("evidence lost the control plane's name for it: %v", h.Evidence)
		}
		return
	}
	t.Fatal("no decision for the host")
}

// An ambiguous control-plane name is a question about which machine somebody
// means, and answering it by picking one is how an inventory starts claiming
// the wrong machine.
func TestAnAmbiguousNameIsReportedAndClaimsNothing(t *testing.T) {
	d := Decide(Observation{
		DeploymentID: "farm-a",
		LocalHosts:   []string{"seoul-aio01", "incheon-aio01"},
		ControlHosts: []string{"aio01"},
		Complete:     true,
	})
	if !slices.Contains(d.Outcome.Ambiguous, "aio01") {
		t.Errorf("ambiguous = %v, want the name that fits two hosts", d.Outcome.Ambiguous)
	}
	for _, h := range d.Hosts {
		if h.Confidence == Confirmed {
			t.Errorf("%s was confirmed on an ambiguous name", h.Hostname)
		}
	}
}

// Empty means "not carrying this", never "clear it". Every run used to write
// what it was not carrying, so a farm named today was anonymous six hours
// later.
func TestADecisionCarriesOnlyTheFactsItHas(t *testing.T) {
	d := Decide(Observation{DeploymentID: "farm-a", KeystoneURL: "farm-a", Complete: true})
	if d.DisplayName != "" || d.Region != "" {
		t.Errorf("the reconciler invented a name or region: %+v", d)
	}
	if d.KeystoneURL != "farm-a" {
		t.Errorf("keystone url = %q", d.KeystoneURL)
	}
}

// A decision with no time of its own still has one: everything it writes is
// compared against it, including the sweep that drops what this run did not
// see.
func TestADecisionAlwaysHasAnInstant(t *testing.T) {
	before := time.Now()
	d := Decide(Observation{DeploymentID: "farm-a"})
	if d.At.Before(before) {
		t.Errorf("At = %v, want the moment it was decided", d.At)
	}

	at := time.Now().Add(-time.Hour)
	if got := Decide(Observation{DeploymentID: "farm-a", At: at}); !got.At.Equal(at) {
		t.Errorf("At = %v, want the caller's %v", got.At, at)
	}
}

// The whole reason the decision is a value: asking what a run would do costs
// nothing and cannot differ from doing it.
func TestDecidingTwiceGivesTheSameAnswer(t *testing.T) {
	obs := Observation{
		DeploymentID: "farm-a",
		LocalHosts:   []string{"h1", "h2", "h3"},
		ControlHosts: []string{"h1", "h3", "ghost"},
		Complete:     true,
		At:           time.Now(),
	}
	a, b := Decide(obs), Decide(obs)
	if !slices.Equal(a.Outcome.Confirmed, b.Outcome.Confirmed) ||
		!slices.Equal(a.Outcome.LocalOnly, b.Outcome.LocalOnly) ||
		!slices.Equal(a.Outcome.ControlOnly, b.Outcome.ControlOnly) {
		t.Errorf("two decisions over one observation differ:\n%+v\n%+v", a.Outcome, b.Outcome)
	}
}
