package openstack

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
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
	h.ObservedAt = time.Now().Add(-StaleProbeWindow - time.Hour)

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

	got := rolesCell(h, false)
	if !strings.Contains(got, "compute") || !strings.Contains(got, "-network") {
		t.Errorf("roles cell = %q, want compute and a marked -network", got)
	}
}

// A controller's nine roles are ~90 characters of near-identical text on every
// controller in the farm, and because the widths are shared they pushed release
// and age to the right on every other farm's rows too. The summary has to name
// what the host is for and admit how much it is leaving out.
func TestRolesCellSummarisesAControllerAndKeepsTheCount(t *testing.T) {
	h := osHost("srv-01", "farm-a", "block-storage", "compute", "controller",
		"dashboard", "identity", "image", "load-balancer", "network", "orchestration")

	got := rolesCell(h, false)
	if !strings.Contains(got, "controller") {
		t.Errorf("roles cell = %q, want the role that says what the host is for", got)
	}
	if !strings.Contains(got, "9") {
		t.Errorf("roles cell = %q — dropping the count reads as the whole answer", got)
	}
	if strings.Contains(got, "orchestration") {
		t.Errorf("roles cell = %q, want the long list collapsed", got)
	}
	// --wide is the escape hatch, so nothing is unreachable.
	if wide := rolesCell(h, true); !strings.Contains(wide, "orchestration") {
		t.Errorf("--wide roles = %q, want every role", wide)
	}
}

// A compute node running the L3 agent is not a controller, and calling it one
// would be a worse answer than the list it replaced. Short lists stay lists.
func TestRolesCellLeavesShortListsAlone(t *testing.T) {
	if got := rolesCell(osHost("srv-01", "f", "compute", "network"), false); got != "compute,network" {
		t.Errorf("roles cell = %q, want the two roles listed", got)
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

	if s := farmSuffix(guessed, 1, sharedCols{}); !strings.Contains(s, store.ConfidenceLocalOnly) {
		t.Errorf("heading = %q, want the weak evidence named", s)
	}
	if s := farmSuffix(confirmed, 1, sharedCols{}); strings.Contains(s, store.ConfidenceConfirmed) {
		t.Errorf("heading = %q — a confirmed farm needs no annotation", s)
	}
	if s := farmSuffix(osHost("srv-03", ""), 2, sharedCols{}); !strings.Contains(s, "nothing has claimed") {
		t.Errorf("unassigned heading = %q, want it said plainly", s)
	}
	if s := farmSuffix(confirmed, 1, sharedCols{}); !strings.Contains(s, "1 host") || strings.Contains(s, "1 hosts") {
		t.Errorf("heading = %q, want \"1 host\"", s)
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

	got := farmShape(hosts, true)
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

// Nine roles with their counts is the wall of text this line exists to spare the
// reader. It stops, and says how much it stopped short by.
func TestFarmShapeStopsSummarisingBeforeItBecomesTheList(t *testing.T) {
	got := farmShape([]store.OpenStackHost{
		osHost("c1", "f", "controller", "identity", "network", "image",
			"dashboard", "orchestration", "load-balancer", "block-storage"),
	}, false)

	if strings.Count(got, "·") != shapeRoles {
		t.Errorf("shape = %q, want %d roles then a remainder", got, shapeRoles)
	}
	if !strings.Contains(got, "+5 more") {
		t.Errorf("shape = %q — a silent cut reads as the whole census", got)
	}
}

// A deployment nothing runs in has no shape to print, and an empty line under
// the heading reads as a rendering fault.
func TestFarmShapeIsEmptyWithNoRoles(t *testing.T) {
	h := osHost("h1", "f")
	h.Roles = nil
	if got := farmShape([]store.OpenStackHost{h}, false); got != "" {
		t.Errorf("shape = %q, want nothing", got)
	}
}

// osFarm builds a farm whose hosts carry a release and a probe age, which is
// what the heading either absorbs or leaves on the rows.
func osFarm(farm string, specs ...struct {
	name, release string
	age           time.Duration
}) []store.OpenStackHost {
	hosts := make([]store.OpenStackHost, 0, len(specs))
	for _, s := range specs {
		h := osHost(s.name, farm, "compute")
		h.Components = map[string]store.CapabilityComponent{
			"nova-compute": {Version: s.release, Active: true, Service: true},
		}
		h.ObservedAt = time.Now().Add(-s.age)
		hosts = append(hosts, h)
	}
	return hosts
}

type farmSpec = struct {
	name, release string
	age           time.Duration
}

// A column reading the same on every row describes the farm, not the row. Seven
// hosts on 2025.1 printed the release seven times and pushed everything after it
// to the right.
func TestAValueEveryHostAgreesOnIsSaidOnceInTheHeading(t *testing.T) {
	var buf bytes.Buffer
	renderOpenStack(&buf, osFarm("f",
		farmSpec{"srv-01", "2025.1", 17 * time.Minute},
		farmSpec{"srv-02", "2025.1", 18 * time.Minute},
		farmSpec{"srv-03", "2025.1", 18 * time.Minute},
	), store.OpenStackCoverage{Hosts: 3, Probed: 3, Running: 3}, false, time.Now())

	out := buf.String()
	if n := strings.Count(out, "2025.1"); n != 1 {
		t.Errorf("the release appears %d times, want once in the heading:\n%s", n, out)
	}
	// The oldest, never the newest: folding must not make a farm look fresher
	// than its slowest reporter.
	head, _, _ := strings.Cut(out, "\n")
	if !strings.Contains(head, "18m") {
		t.Errorf("heading = %q, want the oldest probe age", head)
	}
	if strings.Contains(out, "17m") {
		t.Errorf("a per-host age survived the fold:\n%s", out)
	}
}

// The age column earns its place by showing the one host that stopped
// reporting. Folding it away on a farm that has one is how a dead agent goes
// unnoticed, so a single stale host keeps the column for everybody.
func TestAStaleHostKeepsTheAgeColumnOnEveryRow(t *testing.T) {
	var buf bytes.Buffer
	renderOpenStack(&buf, osFarm("f",
		farmSpec{"srv-01", "2025.1", 10 * time.Minute},
		farmSpec{"srv-02", "2025.1", 10 * time.Minute},
		farmSpec{"srv-03", "2025.1", StaleProbeWindow + time.Hour},
	), store.OpenStackCoverage{Hosts: 3, Probed: 3, Running: 3}, false, time.Now())

	out := buf.String()
	if n := strings.Count(out, "10m"); n != 2 {
		t.Errorf("the age column was folded away with a stale host present:\n%s", out)
	}
	if !strings.Contains(out, "4h") {
		t.Errorf("the stale host's age is missing:\n%s", out)
	}
}

// Disagreement is the thing worth seeing, so the column comes back the moment
// two hosts differ.
func TestAColumnComesBackWhenTheHostsDisagree(t *testing.T) {
	var buf bytes.Buffer
	renderOpenStack(&buf, osFarm("f",
		farmSpec{"srv-01", "2025.1", 10 * time.Minute},
		farmSpec{"srv-02", "2024.2", 10 * time.Minute},
	), store.OpenStackCoverage{Hosts: 2, Probed: 2, Running: 2}, false, time.Now())

	out := buf.String()
	for _, want := range []string{"2025.1", "2024.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("release %s went missing:\n%s", want, out)
		}
	}
}

// --wide is for the reader who wants every value on every row. Folding rows
// away is the opposite of what they asked for.
func TestWideFoldsNothingIntoTheHeading(t *testing.T) {
	hosts := osFarm("f",
		farmSpec{"srv-01", "2025.1", 10 * time.Minute},
		farmSpec{"srv-02", "2025.1", 10 * time.Minute},
	)
	var buf bytes.Buffer
	renderOpenStack(&buf, hosts, store.OpenStackCoverage{Hosts: 2, Probed: 2, Running: 2}, true, time.Now())

	if n := strings.Count(buf.String(), "2025.1"); n < 2 {
		t.Errorf("--wide folded a column into the heading:\n%s", buf.String())
	}
}

// Dropping the component name off a stand-in release makes the column readable
// and the value ambiguous. The mark and its legend keep the caveat.
func TestAStandInReleaseIsMarkedAndExplained(t *testing.T) {
	h := osHost("srv-01", "f", "controller")
	h.Components = map[string]store.CapabilityComponent{
		"cinder-api": {Version: "2025.1", Active: true, Service: true},
	}

	var buf bytes.Buffer
	renderOpenStack(&buf, []store.OpenStackHost{h},
		store.OpenStackCoverage{Hosts: 1, Probed: 1, Running: 1}, false, time.Now())

	out := buf.String()
	if !strings.Contains(out, "2025.1"+standInMark) {
		t.Errorf("a non-nova release was not marked:\n%s", out)
	}
	if !strings.Contains(out, "--wide names it") {
		t.Errorf("the mark has no legend, so it reads as noise:\n%s", out)
	}
	// A nova release is the norm and must not pick up a footnote.
	n := osHost("srv-02", "f", "compute")
	n.Components = map[string]store.CapabilityComponent{
		"nova-compute": {Version: "2025.1", Active: true, Service: true},
	}
	buf.Reset()
	renderOpenStack(&buf, []store.OpenStackHost{n},
		store.OpenStackCoverage{Hosts: 1, Probed: 1, Running: 1}, false, time.Now())
	if strings.Contains(buf.String(), standInMark) {
		t.Errorf("a nova release was marked as a stand-in:\n%s", buf.String())
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

// Coverage is counted from the rows on screen, so it cannot contradict them.
//
// It used to be a query of its own, and the two disagreed: the query judged
// every capability row on its own while the table judges the newest pass, so a
// controller whose earlier probes had failed showed nine roles in the table and
// "1 could not be probed" in the line underneath it.
func TestCoverageIsCountedFromTheRowsItSummarises(t *testing.T) {
	cat := fleet.From(store.Fleet{InventoryHosts: 10})
	hosts := []store.OpenStackHost{
		{Hostname: "a", Detected: true},
		{Hostname: "b", Detected: true},
		{Hostname: "c", LastError: "probe timed out"},
		{Hostname: "d"}, // probed, found nothing
	}
	got := coverageOf(cat, hosts)

	if got.Probed != 4 {
		t.Errorf("probed = %d, want the rows it was given", got.Probed)
	}
	// Every probed host falls in exactly one bucket, or a host is reported
	// twice in one line.
	if got.Running+got.Failed+got.Absent != got.Probed {
		t.Errorf("counts do not add up: running=%d failed=%d absent=%d probed=%d",
			got.Running, got.Failed, got.Absent, got.Probed)
	}
	if got.Running != 2 || got.Failed != 1 || got.Absent != 1 {
		t.Errorf("buckets = %+v", got)
	}
	if got.Unprobed != 6 {
		t.Errorf("unprobed = %d, want the inventory minus what was probed", got.Unprobed)
	}
}

// A capability row for a host since retired would make the remainder negative,
// and "-3 never probed" is not a thing to print.
func TestCoverageDoesNotGoNegativeWhenMoreWasProbedThanTheInventoryHolds(t *testing.T) {
	cat := fleet.From(store.Fleet{InventoryHosts: 1})
	got := coverageOf(cat, []store.OpenStackHost{{Hostname: "a"}, {Hostname: "b"}})
	if got.Unprobed != 0 {
		t.Errorf("unprobed = %d, want it clamped at zero", got.Unprobed)
	}
}

// A node-agent capability report is inventory-controlled and its keys are not
// validated on the way in. An empty key must not panic the host detail view: a
// compromised or buggy agent cannot be allowed to crash the operator's CLI.
func TestDetailLabelDoesNotPanicOnAnEmptyKey(t *testing.T) {
	if got := detailLabel(""); got != "" {
		t.Errorf("detailLabel(\"\") = %q, want empty", got)
	}
	if got := detailLabel("nova_compute"); got != "Nova compute" {
		t.Errorf("detailLabel(nova_compute) = %q", got)
	}
}
