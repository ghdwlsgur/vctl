package cli

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func osHost(name, farm string, roles ...string) store.OpenStackHost {
	return store.OpenStackHost{
		Hostname: name, DC: "test-dc", HostState: store.StateActive,
		Detected: true, Roles: roles, Farm: farm,
		Confidence: store.ConfidenceConfirmed,
		ObservedAt: time.Now(),
		Components: map[string]store.CapabilityComponent{},
		Details:    map[string]string{},
	}
}

// Hosts arrive sorted by name because that is how the rest of vctl lists a
// fleet. Rendering that order directly printed a group header every time the
// farm changed between two adjacent names, so one deployment appeared as
// several blocks, each with its own count.
func TestGroupByFarmMakesEachDeploymentContiguous(t *testing.T) {
	got := groupByFarm([]store.OpenStackHost{
		osHost("srv-01", "farm-a"),
		osHost("srv-02", "farm-b"),
		osHost("srv-03", "farm-a"),
	})

	var order []string
	for _, h := range got {
		order = append(order, h.Farm)
	}
	if order[0] != order[1] {
		t.Errorf("farm order = %v, want each deployment contiguous", order)
	}
	// Stable within the group, so the listing does not reshuffle between runs.
	if got[0].Hostname != "srv-01" || got[1].Hostname != "srv-03" {
		t.Errorf("hosts = %s,%s — the group lost its name order", got[0].Hostname, got[1].Hostname)
	}
}

// Unassigned is the leftover bucket. The deployments are what someone opened
// the listing to read, so they come first.
func TestGroupByFarmPutsUnassignedLast(t *testing.T) {
	got := groupByFarm([]store.OpenStackHost{
		osHost("srv-01", ""),
		osHost("srv-02", "farm-a"),
	})

	if got[len(got)-1].Farm != "" {
		t.Errorf("last group is %q, want the unassigned one", got[len(got)-1].Farm)
	}
}

// A host that stopped being a compute node still carries the old row. Matching
// on it would answer "which are my compute nodes" with a machine that has not
// run nova in weeks.
func TestRoleFilterIgnoresARoleTheHostNoLongerHolds(t *testing.T) {
	h := osHost("srv-01", "farm-a")
	h.Roles = []string{"network"}
	h.Dropped = []store.DroppedRole{{Role: "compute", LastSeen: time.Now().Add(-30 * 24 * time.Hour)}}

	if got := filterOpenStack([]store.OpenStackHost{h}, "", "compute", false); len(got) != 0 {
		t.Errorf("--role compute matched a host whose compute row is stale: %+v", got[0].Roles)
	}
	if got := filterOpenStack([]store.OpenStackHost{h}, "", "network", false); len(got) != 1 {
		t.Error("--role network did not match the role the host actually holds")
	}
}

// Probed-and-absent rows exist so the listing can tell them from never-probed,
// but a fleet where most machines run no OpenStack would bury the ones that do.
func TestAbsentHostsAreHiddenUntilAsked(t *testing.T) {
	absent := osHost("srv-01", "")
	absent.Detected, absent.Roles = false, nil

	if got := filterOpenStack([]store.OpenStackHost{absent}, "", "", false); len(got) != 0 {
		t.Error("a host with no OpenStack on it appeared in the default listing")
	}
	if got := filterOpenStack([]store.OpenStackHost{absent}, "", "", true); len(got) != 1 {
		t.Error("--all did not bring back the probed-and-absent host")
	}
}

// A host claimed by two deployments belongs to both. If each --farm disowned
// it, the conflict would be visible only in the unfiltered listing — exactly
// where nobody investigating one farm would look.
func TestFarmFilterMatchesEverySideOfAConflict(t *testing.T) {
	h := osHost("srv-01", "farm-a")
	h.Confidence = store.ConfidenceConflict
	h.Memberships = []store.OpenStackMembership{
		{DeploymentID: "farm-a"}, {DeploymentID: "farm-b"},
	}

	for _, farm := range []string{"farm-a", "farm-b"} {
		if got := filterOpenStack([]store.OpenStackHost{h}, farm, "", false); len(got) != 1 {
			t.Errorf("--farm %s did not match a host claimed by both", farm)
		}
	}
}

func TestFarmFilterSelectsTheUnclaimed(t *testing.T) {
	hosts := []store.OpenStackHost{osHost("srv-01", "farm-a"), osHost("srv-02", "")}

	got := filterOpenStack(hosts, "unassigned", "", false)
	if len(got) != 1 || got[0].Hostname != "srv-02" {
		t.Errorf("--farm unassigned returned %+v, want only the unclaimed host", got)
	}
}

// Nothing found and nothing looked produce the same blank table and call for
// opposite responses — redeploy the agent, or accept the answer.
func TestEmptyListingSaysWhetherAnythingHasLooked(t *testing.T) {
	var buf bytes.Buffer
	renderOpenStack(&buf, nil, store.OpenStackCoverage{Hosts: 50, Probed: 0, Unprobed: 50}, false, time.Now())

	out := buf.String()
	if !strings.Contains(out, "0/50") || !strings.Contains(out, "never probed") {
		t.Errorf("an empty listing did not say the fleet is unprobed:\n%s", out)
	}
}

// A probe result older than a few passes is a question about whether anything
// is reporting, not a current reading — and the age has to be on the row that
// carries it.
func TestStaleProbeIsMarkedOnTheRow(t *testing.T) {
	h := osHost("srv-01", "farm-a", "compute")
	h.ObservedAt = time.Now().Add(-capabilityFreshWindow - time.Hour)

	var buf bytes.Buffer
	renderOpenStack(&buf, []store.OpenStackHost{h}, store.OpenStackCoverage{Hosts: 1, Probed: 1, Running: 1}, false, time.Now())

	if fresh := ageCell(osHost("srv-02", "farm-a"), time.Now()); fresh == ageCell(h, time.Now()) {
		t.Error("a four-hour-old probe renders the same as a fresh one")
	}
	if !strings.Contains(buf.String(), "srv-01") {
		t.Error("the stale host was dropped from the listing instead of being marked")
	}
}

// The roles column has to distinguish current from lost without relying on
// colour, which does not survive a pipe.
func TestRolesCellMarksWhatTheHostNoLongerRuns(t *testing.T) {
	h := osHost("srv-01", "farm-a", "compute")
	h.Dropped = []store.DroppedRole{{Role: "network"}}

	got := rolesCell(h)
	if !strings.Contains(got, "compute") || !strings.Contains(got, "-network") {
		t.Errorf("roles cell = %q, want compute and a marked -network", got)
	}
}

// --wide exists for the rolling upgrade case, where the components genuinely
// disagree for weeks and one number cannot say which one lags.
func TestWideShowsEveryComponentAndFlagsStoppedOnes(t *testing.T) {
	h := osHost("srv-01", "farm-a", "compute")
	h.Components = map[string]store.CapabilityComponent{
		"nova-compute":  {Version: "31.2.0", Active: true, Service: true},
		"libvirt":       {Version: "10.0.0", Active: true, Service: true},
		"cinder-volume": {Version: "25.0.0", Service: true},
	}

	narrow, wide := versionCell(h, false), versionCell(h, true)
	if narrow != "31.2.0" {
		t.Errorf("summary column = %q, want the nova version", narrow)
	}
	for _, want := range []string{"nova-compute=31.2.0", "libvirt=10.0.0"} {
		if !strings.Contains(wide, want) {
			t.Errorf("--wide = %q, missing %s", wide, want)
		}
	}
	if !strings.Contains(wide, "cinder-volume=25.0.0(down)") {
		t.Errorf("--wide = %q, a stopped service was not flagged", wide)
	}
}

// qemu has a version and no daemon. Reading Active=false as "stopped" put a
// fault on every healthy compute node and would send somebody to restart a
// package that is not meant to be running.
func TestANonServiceComponentIsNotReportedAsDown(t *testing.T) {
	h := osHost("srv-01", "farm-a", "compute")
	h.Components = map[string]store.CapabilityComponent{
		"nova-compute": {Version: "31.2.0", Active: true, Service: true},
		"qemu":         {Version: "8.2.0"}, // a binary, exec'd per instance
	}

	if got := versionCell(h, true); strings.Contains(got, "qemu=8.2.0(down)") {
		t.Errorf("--wide = %q, qemu was flagged as a stopped service", got)
	}
	var buf bytes.Buffer
	renderOpenStackHost(&buf, h, time.Now())
	if strings.Contains(buf.String(), "stopped") {
		t.Errorf("the detail view called a non-service stopped:\n%s", buf.String())
	}
}

// The one number on the row has to describe the host, not its worst component.
// Taking the first name alphabetically summarised a healthy controller by the
// only service on it that was down.
func TestSummaryVersionPrefersARunningService(t *testing.T) {
	h := osHost("srv-01", "farm-a", "controller")
	h.Components = map[string]store.CapabilityComponent{
		"glance-api":     {Version: "30.0.0", Service: true}, // stopped
		"nova-conductor": {Version: "31.2.0", Active: true, Service: true},
	}

	if got := versionCell(h, false); strings.Contains(got, "glance-api") {
		t.Errorf("summary column = %q, want a component that is actually running", got)
	}
}

// A farm resting on anything weaker than a statement has to say so in the
// heading. Rendering "local-only" the same as "confirmed" is how an inference
// gets acted on as a fact.
func TestFarmHeadingCarriesTheEvidence(t *testing.T) {
	confirmed := osHost("srv-01", "farm-a")
	guessed := osHost("srv-02", "farm-b")
	guessed.Confidence = store.ConfidenceLocalOnly

	if s := farmSuffix(guessed, 1); !strings.Contains(s, store.ConfidenceLocalOnly) {
		t.Errorf("heading = %q, want the weak evidence named", s)
	}
	if s := farmSuffix(confirmed, 1); strings.Contains(s, store.ConfidenceConfirmed) {
		t.Errorf("heading = %q — a confirmed farm needs no annotation", s)
	}
	if s := farmSuffix(osHost("srv-03", ""), 2); !strings.Contains(s, "nothing has claimed") {
		t.Errorf("unassigned heading = %q, want it said plainly", s)
	}
}

// The detail view must not print the probe's raw deployment field beside the
// farm row: it invites reading a refusal to guess as a second opinion.
func TestHostDetailDoesNotRepeatTheRawDeploymentField(t *testing.T) {
	h := osHost("srv-01", "", "compute")
	h.Details = map[string]string{"deployment": "unknown", "hypervisor": "kvm"}

	var buf bytes.Buffer
	renderOpenStackHost(&buf, h, time.Now())

	out := buf.String()
	if strings.Contains(out, "unknown") {
		t.Errorf("the raw deployment field was rendered:\n%s", out)
	}
	if !strings.Contains(out, "kvm") {
		t.Errorf("a real detail was dropped:\n%s", out)
	}
	if !strings.Contains(out, "unassigned") {
		t.Errorf("the detail view did not say the host is unclaimed:\n%s", out)
	}
}

// A probe that could not answer must not be rendered as an answer.
// detected=false with an error beside it means "we could not tell", and calling
// that "none found" states as fact the one thing the probe failed to establish.
func TestAFailedProbeIsNotReportedAsAbsence(t *testing.T) {
	h := osHost("srv-01", "")
	h.Detected, h.Roles = false, nil
	h.LastError = "probe timed out"

	var buf bytes.Buffer
	renderOpenStackHost(&buf, h, time.Now())

	out := buf.String()
	if strings.Contains(out, "none found") {
		t.Errorf("a failed probe was rendered as an absence:\n%s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("the detail view did not say the answer is unknown:\n%s", out)
	}
}

// Folding failures into "do not run OpenStack" reports an absence on the
// strength of a timeout.
func TestCoverageKeepsFailuresApartFromAbsences(t *testing.T) {
	var buf bytes.Buffer
	renderOpenStack(&buf, nil, store.OpenStackCoverage{
		Hosts: 50, Probed: 10, Running: 4, Failed: 2, Absent: 4, Unprobed: 40,
	}, false, time.Now())

	out := buf.String()
	if !strings.Contains(out, "2 could not be probed") {
		t.Errorf("failures were not reported separately:\n%s", out)
	}
	if !strings.Contains(out, "4 do not") {
		t.Errorf("absences lost their own count:\n%s", out)
	}
}

// The per-host rows say what each machine does; the shape says what the
// deployment is. Counting "3 controllers, 5 compute" off nine rows each
// carrying up to nine comma-separated roles is not a reader's job.
func TestFarmShapeCountsTheRoles(t *testing.T) {
	hosts := []store.OpenStackHost{
		osHost("c1", "f", "controller", "identity", "network"),
		osHost("c2", "f", "controller", "identity"),
		osHost("n1", "f", "compute"),
		osHost("n2", "f", "compute"),
		osHost("n3", "f", "compute"),
	}

	got := farmShape(hosts)
	for _, want := range []string{"compute 3", "controller 2", "identity 2", "network 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("shape = %q, missing %s", got, want)
		}
	}
	// Ordered by how many hosts hold the role, so the shape leads with what the
	// deployment is mostly made of.
	if !strings.HasPrefix(got, "compute 3") {
		t.Errorf("shape = %q, want the largest role first", got)
	}
}

// A deployment nothing runs in has no shape to print, and an empty line under
// the heading reads as a rendering fault.
func TestFarmShapeIsEmptyWithNoRoles(t *testing.T) {
	h := osHost("h1", "f")
	h.Roles = nil
	if got := farmShape([]store.OpenStackHost{h}); got != "" {
		t.Errorf("shape = %q, want nothing", got)
	}
}

// Groups are ordered by what is printed, not by the id behind it. Sorting on
// the endpoint while showing the name put "incheon, seoul-b, 172.16.0.21,
// seoul-a" on screen — an order that is correct and looks like none at all.
func TestGroupByFarmOrdersByTheVisibleLabel(t *testing.T) {
	mk := func(id, name string) store.OpenStackHost {
		h := osHost("h-"+id, id)
		h.FarmName = name
		return h
	}
	got := groupByFarm([]store.OpenStackHost{
		mk("172.16.0.10:5000", "incheon"),
		mk("172.16.0.245:5000", "seoul-a"),
		mk("172.16.0.21:5000", ""),
	})

	var labels []string
	for _, h := range got {
		labels = append(labels, farmLabel(h))
	}
	if !sort.StringsAreSorted(labels) {
		t.Errorf("group order = %v, want it sorted by what the reader sees", labels)
	}
}
