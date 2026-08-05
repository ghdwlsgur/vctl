package openstack

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func host(name string, roles []string, active []string, release, conf string) store.OpenStackHost {
	h := store.OpenStackHost{
		Hostname: name, Detected: true, Roles: roles, ActiveRoles: active, Confidence: conf,
	}
	if release != "" {
		h.Components = map[string]store.CapabilityComponent{
			"nova-compute": {Version: release, Active: true, Service: true},
		}
	}
	return h
}

func kinds(a Assessment) []string {
	out := make([]string, 0, len(a.Anomalies))
	for _, x := range a.Anomalies {
		out = append(out, x.Kind)
	}
	return out
}

// The control plane leads, because that is the order somebody reasons about a
// deployment in: how many controllers, then how many compute.
func TestSectionsLeadWithTheControlPlane(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("c1", []string{"compute", "controller"}, []string{"compute", "controller"}, "2025.1", store.ConfidenceConfirmed),
	}})

	if len(got.Architecture.Sections) < 2 || got.Architecture.Sections[0].Role != "controller" {
		t.Errorf("sections = %+v, want controller first", got.Architecture.Sections)
	}
}

// A deployed role with nothing running is an outage, not a smaller deployment.
// The section keeps its size and the anomaly says what is wrong.
func TestARoleWithNothingRunningIsAnAnomalyNotAShrunkFarm(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("n1", []string{"compute"}, nil, "2025.1", store.ConfidenceConfirmed),
	}})

	if got.Architecture.Sections[0].Down != 1 || len(got.Architecture.Sections[0].Hosts) != 1 {
		t.Errorf("compute section = %+v, want one host marked down", got.Architecture.Sections[0])
	}
	if got.Health.RolesDown != 1 || got.Health.HostsDown != 1 {
		t.Errorf("health = %+v", got.Health)
	}
	if !slices.Contains(kinds(got), AnomalyRoleDown) {
		t.Errorf("anomalies = %v, want the outage named", kinds(got))
	}
}

// Two releases in one deployment is the question a farm view usually exists to
// answer, so it is a judgement here rather than something each renderer works
// out for itself.
func TestDriftIsJudgedOnce(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("a", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
		host("b", []string{"compute"}, []string{"compute"}, "2024.2", store.ConfidenceConfirmed),
	}})

	if !got.Versions.Drifting {
		t.Error("two releases were not reported as drift")
	}
	if !slices.Contains(kinds(got), AnomalyDrift) {
		t.Errorf("anomalies = %v", kinds(got))
	}
}

// One release is the good news and must not be reported as a problem.
func TestOneReleaseIsNotAnAnomaly(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("a", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
		host("b", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
	}})

	if got.Versions.Drifting || slices.Contains(kinds(got), AnomalyDrift) {
		t.Errorf("a single-release farm was reported as drifting: %v", kinds(got))
	}
}

// A failure only counts as current if it came after the last success. A farm
// that failed once last week and has worked since is not failing.
func TestAnOldFailureIsNotCurrent(t *testing.T) {
	success := time.Now().Add(-time.Hour)
	run := store.ReconcileRun{
		StartedAt: time.Now().Add(-2 * time.Hour), SucceededAt: &success,
		LastError: "keystone unreachable", Complete: true,
	}
	got := Assess(Input{Run: &run, StaleAfter: 13 * time.Hour})

	if got.Freshness.Error != "" {
		t.Errorf("error = %q, but the success came after it", got.Freshness.Error)
	}
	if slices.Contains(kinds(got), AnomalyReconcileNG) {
		t.Errorf("anomalies = %v, want no current failure", kinds(got))
	}
}

// A failure after the last success is the case the two timestamps exist to
// separate: the farm looks settled and has been failing since.
func TestAFailureAfterTheLastSuccessIsCurrent(t *testing.T) {
	success := time.Now().Add(-2 * time.Hour)
	run := store.ReconcileRun{
		StartedAt: time.Now(), SucceededAt: &success, LastError: "keystone unreachable",
	}
	got := Assess(Input{Run: &run, StaleAfter: 13 * time.Hour})

	if got.Freshness.Error == "" {
		t.Error("a failure after the last success was not reported")
	}
	if !slices.Contains(kinds(got), AnomalyReconcileNG) {
		t.Errorf("anomalies = %v", kinds(got))
	}
}

// Never reconciled is not the same as stale, and the two call for different
// responses — configure it, versus find out why it stopped.
func TestNeverReconciledIsItsOwnAnomaly(t *testing.T) {
	got := Assess(Input{StaleAfter: time.Hour})

	if !slices.Contains(kinds(got), AnomalyNeverRun) {
		t.Errorf("anomalies = %v, want never-reconciled", kinds(got))
	}
	if slices.Contains(kinds(got), AnomalyStale) {
		t.Errorf("anomalies = %v — nothing can be stale that never ran", kinds(got))
	}
}

// A zero window disables the judgement rather than marking everything stale,
// which is the safer direction for a caller that forgot to set it.
func TestZeroStaleWindowMarksNothingStale(t *testing.T) {
	old := time.Now().Add(-30 * 24 * time.Hour)
	run := store.ReconcileRun{StartedAt: old, SucceededAt: &old, Complete: true}

	if Assess(Input{Run: &run}).Freshness.Stale {
		t.Error("a zero window marked a month-old success stale")
	}
	if !Assess(Input{Run: &run, StaleAfter: time.Hour}).Freshness.Stale {
		t.Error("a set window did not mark a month-old success stale")
	}
}

// Ghost hosts and missing VMs are the rows that only exist because something is
// wrong, and they belong with the other anomalies rather than in a footnote.
func TestGhostsAndMissingVMsBecomeAnomalies(t *testing.T) {
	gone := time.Now().Add(-time.Hour)
	got := Assess(Input{
		Ghosts:    []store.ControlHost{{NovaHostname: "sre-svr-0032", FirstSeenAt: gone}},
		Instances: []store.Instance{{InstanceID: "u1", MissingSince: &gone}, {InstanceID: "u2"}},
	})

	k := kinds(got)
	if !slices.Contains(k, AnomalyGhost) || !slices.Contains(k, AnomalyVMMissing) {
		t.Errorf("anomalies = %v, want both", k)
	}
	if got.Health.VMsMissing != 1 || got.Architecture.VMs != 1 {
		t.Errorf("vms = %d live / %d missing", got.Architecture.VMs, got.Health.VMsMissing)
	}
}

// The worst thing is the first thing, and the order is the same every run.
func TestAnomaliesPutErrorsFirst(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("n1", []string{"compute"}, nil, "2025.1", store.ConfidenceLocalOnly),
		host("n2", []string{"compute"}, []string{"compute"}, "2024.2", store.ConfidenceConflict),
	}})

	if len(got.Anomalies) < 2 {
		t.Fatalf("anomalies = %v", kinds(got))
	}
	if got.Anomalies[0].Severity != SeverityError {
		t.Errorf("first anomaly is %q severity, want the error first", got.Anomalies[0].Severity)
	}
}

// A host repeated across sections must not repeat its facts, or an all-in-one
// deployment reads as several times its size.
func TestARepeatedHostIsMarkedNotRestated(t *testing.T) {
	got := Assess(Input{Hosts: []store.OpenStackHost{
		host("aio", []string{"controller", "compute", "network"},
			[]string{"controller", "compute", "network"}, "2025.1", store.ConfidenceConfirmed),
	}})

	var seen int
	for _, sec := range got.Architecture.Sections {
		for _, m := range sec.Hosts {
			if m.AlsoIn == "" {
				seen++
			}
		}
	}
	if seen != 1 {
		t.Errorf("the host was stated in full %d times, want once", seen)
	}
}

// VMs attach to the host they run on, which is the join the whole chain rests
// on.
func TestVMsAttachToTheirHypervisor(t *testing.T) {
	got := Assess(Input{
		Hosts: []store.OpenStackHost{
			host("gpu01", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
		},
		Instances: []store.Instance{
			{InstanceID: "u1", HypervisorHostname: "gpu01"},
			{InstanceID: "u2", HypervisorHostname: "gpu01"},
		},
	})

	if got.Architecture.Sections[0].Hosts[0].VMs != 2 {
		t.Errorf("vms on gpu01 = %d, want 2", got.Architecture.Sections[0].Hosts[0].VMs)
	}
}

// The release summary prefers a running component: taking the first name
// alphabetically summarised a healthy controller by the only service that was
// down.
func TestReleasePrefersARunningComponent(t *testing.T) {
	h := store.OpenStackHost{Components: map[string]store.CapabilityComponent{
		"glance-api":     {Version: "30.0.0", Service: true},
		"nova-conductor": {Version: "31.2.0", Active: true, Service: true},
	}}
	if got := ReleaseOf(h); got != "31.2.0" {
		t.Errorf("ReleaseOf = %q, want the running component's", got)
	}
}

// An assessment built from less says less rather than refusing — a farm with no
// hosts collected yet still renders.
func TestAnEmptyDeploymentAssessesCleanly(t *testing.T) {
	got := Assess(Input{ID: "10.0.0.1:5000", Name: "new"})

	if got.Membership.Total != 0 || len(got.Architecture.Sections) != 0 {
		t.Errorf("empty assessment = %+v", got)
	}
	if !strings.Contains(strings.Join(kinds(got), ","), AnomalyNeverRun) {
		t.Errorf("anomalies = %v, want never-reconciled", kinds(got))
	}
}

// A declared state accounts for what follows from it. The anomalies stay —
// somebody marking a farm broken still needs to see what is broken about it —
// but they stop being news, which is what separates an unattended fault from a
// known one.
func TestDeclaredBrokenMarksTheFaultExpectedWithoutHidingIt(t *testing.T) {
	run := store.ReconcileRun{StartedAt: time.Now(), LastError: "nova 500"}
	got := Assess(Input{State: store.StateBroken, Run: &run, StaleAfter: time.Hour})

	var found bool
	for _, a := range got.Anomalies {
		if a.Kind == AnomalyReconcileNG {
			found = true
			if !a.Expected {
				t.Error("a declared-broken farm's reconcile failure was reported as news")
			}
		}
	}
	if !found {
		t.Errorf("the failure disappeared once the farm was declared broken: %v", kinds(got))
	}
}

// An active farm's failure is news, which is the whole point of the
// distinction.
func TestAnActiveFarmsFailureIsNews(t *testing.T) {
	run := store.ReconcileRun{StartedAt: time.Now(), LastError: "nova 500"}
	got := Assess(Input{Run: &run, StaleAfter: time.Hour})

	for _, a := range got.Anomalies {
		if a.Kind == AnomalyReconcileNG && a.Expected {
			t.Error("an active farm's failure was marked expected")
		}
	}
}

// A declared state explains what follows from it and nothing else. Marking
// unrelated problems expected would let a farm declared broken hide things that
// have nothing to do with the fault.
func TestDeclaredBrokenDoesNotExcuseUnrelatedProblems(t *testing.T) {
	got := Assess(Input{
		State: store.StateBroken,
		Hosts: []store.OpenStackHost{
			host("a", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
			host("b", []string{"compute"}, []string{"compute"}, "2024.2", store.ConfidenceConfirmed),
		},
	})

	for _, a := range got.Anomalies {
		if a.Kind == AnomalyDrift && a.Expected {
			t.Error("release drift was excused by a broken declaration; it has nothing to do with the fault")
		}
	}
}

// Empty means active, so a caller that has not declared anything gets the
// default rather than a farm with no state at all.
func TestEmptyStateReadsAsActive(t *testing.T) {
	if got := Assess(Input{}).State; got != store.StateActive {
		t.Errorf("state = %q, want %q", got, store.StateActive)
	}
}
