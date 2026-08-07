package store

import (
	"slices"
	"testing"
	"time"
)

// capRow is one row of a single pass — the shape of most fixtures here, where
// the pass number is not what is being tested.
func capRow(host, role string, at time.Time, detected bool) capabilityRow {
	return capRowIn(1, host, role, at, detected)
}

// capRowIn states which pass wrote the row. The fold compares that number and
// not the timestamp, so a fixture with more than one pass in it has to say so.
func capRowIn(pass int64, host, role string, at time.Time, detected bool) capabilityRow {
	r := capabilityRow{DC: "test-dc", HostState: StateActive}
	r.Hostname, r.Role, r.Detected, r.ObservedAt, r.PassID = host, role, detected, at, pass
	r.Components = map[string]CapabilityComponent{}
	r.Details = map[string]string{}
	return r
}

// Every role one probe pass finds carries that pass's timestamp, so the whole
// pass folds into one host record.
func TestFoldCollectsEveryRoleFromTheLatestPass(t *testing.T) {
	at := time.Now()
	rows := []capabilityRow{
		capRow("h1", "compute", at, true),
		capRow("h1", "network", at, true),
	}
	got := foldCapabilityRows(rows, nil)

	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1", len(got))
	}
	if !slices.Equal(got[0].Roles, []string{"compute", "network"}) {
		t.Errorf("roles = %v, want both roles of the same pass", got[0].Roles)
	}
	if len(got[0].Dropped) != 0 {
		t.Errorf("dropped = %v, want none — nothing has gone away", got[0].Dropped)
	}
}

// The agent has no DELETE on server_capabilities, so a role a host stops
// holding leaves its row behind forever. Reading it as current would keep a
// removed neutron agent in the listing indefinitely, and `--role network` would
// send someone to a host that has not run one in weeks.
func TestFoldSeparatesRolesTheLatestPassNoLongerFinds(t *testing.T) {
	now := time.Now()
	rows := []capabilityRow{
		capRowIn(2, "h1", "compute", now, true),
		capRowIn(1, "h1", "network", now.Add(-72*time.Hour), true),
	}
	got := foldCapabilityRows(rows, nil)

	if !slices.Equal(got[0].Roles, []string{"compute"}) {
		t.Errorf("roles = %v, want only what the latest pass found", got[0].Roles)
	}
	if len(got[0].Dropped) != 1 || got[0].Dropped[0].Role != "network" {
		t.Fatalf("dropped = %+v, want network", got[0].Dropped)
	}
	if !got[0].Dropped[0].LastSeen.Equal(now.Add(-72 * time.Hour)) {
		t.Error("the dropped role lost the time it was last seen, so its age cannot be judged")
	}
}

// A lagging row describes software the host no longer runs. Merging its
// components would resurrect versions of a package that has been removed, and
// the listing would report a release nothing on the machine is running.
func TestFoldIgnoresComponentsFromADroppedRole(t *testing.T) {
	now := time.Now()
	fresh := capRowIn(2, "h1", "compute", now, true)
	fresh.Components["nova-compute"] = CapabilityComponent{Version: "31.2.0", Active: true}
	stale := capRowIn(1, "h1", "network", now.Add(-30*24*time.Hour), true)
	stale.Components["neutron-l3-agent"] = CapabilityComponent{Version: "24.0.0", Active: true}

	got := foldCapabilityRows([]capabilityRow{fresh, stale}, nil)

	if _, ok := got[0].Components["neutron-l3-agent"]; ok {
		t.Errorf("a component from a role the host no longer holds survived: %+v", got[0].Components)
	}
	if got[0].Components["nova-compute"].Version != "31.2.0" {
		t.Errorf("components = %+v, want the latest pass's", got[0].Components)
	}
}

// The pass number decides, even when the clock disagrees with it.
//
// This is the case the column split exists for. A host whose clock ran a day
// fast stamped rows nothing could beat, so the write had to force each pass
// past the last one — greatest(now(), max + 1 microsecond) — and freshness
// inherited that future forever. Ordering by a counter lets the timestamp be
// wrong without the fold being wrong, so the skew stays one host's problem
// instead of pinning the listing.
//
// The newer pass here is stamped a day *earlier* than the one it replaces,
// which is exactly what a corrected clock produces.
func TestFoldFollowsThePassAndNotTheClock(t *testing.T) {
	now := time.Now()
	rows := []capabilityRow{
		capRowIn(1, "h1", "network", now.Add(24*time.Hour), true), // written while the clock ran fast
		capRowIn(2, "h1", "compute", now, true),                   // after somebody fixed it
	}
	got := foldCapabilityRows(rows, nil)

	if !slices.Equal(got[0].Roles, []string{"compute"}) {
		t.Errorf("roles = %v, want only the newest pass — the older row's clock is not evidence", got[0].Roles)
	}
	if len(got[0].Dropped) != 1 || got[0].Dropped[0].Role != "network" {
		t.Errorf("dropped = %+v, want network", got[0].Dropped)
	}
	if !got[0].ObservedAt.Equal(now) {
		t.Errorf("observed_at = %v, want the newest pass's own time (%v) — a listing that "+
			"reports the future has no way to say it is wrong", got[0].ObservedAt, now)
	}
}

// A host whose every pass predates the migration has only negative numbers, and
// the fold has to order them like any others.
//
// The comparison started from a map's missing entry, which is 0 — above every
// backfilled pass — so a host nothing had probed since the migration came out
// with no roles at all and its entire history in the dropped list. The listing
// would have shown the fleet as having abandoned OpenStack.
func TestFoldHandlesAHostWhoseHistoryIsAllBackfilled(t *testing.T) {
	now := time.Now()
	got := foldCapabilityRows([]capabilityRow{
		capRowIn(-1, "h1", "compute", now, true),
		capRowIn(-2, "h1", "network", now.Add(-72*time.Hour), true),
	}, nil)

	if !slices.Equal(got[0].Roles, []string{"compute"}) {
		t.Errorf("roles = %v, want the newest backfilled pass", got[0].Roles)
	}
	if len(got[0].Dropped) != 1 || got[0].Dropped[0].Role != "network" {
		t.Errorf("dropped = %+v, want network", got[0].Dropped)
	}
}

// "none" is how a probe files "I looked and found nothing". It is a real answer
// and needs a row, but it is not a role and must not be rendered as one.
func TestFoldDoesNotTreatTheAbsenceMarkerAsARole(t *testing.T) {
	got := foldCapabilityRows([]capabilityRow{capRow("h1", roleNone, time.Now(), false)}, nil)

	if len(got[0].Roles) != 0 {
		t.Errorf("roles = %v, want none", got[0].Roles)
	}
	if got[0].Detected {
		t.Error("a host with nothing on it was reported as detected")
	}
}

// A host that used to run nothing and now runs nova must not carry "none" into
// its dropped list, where it would read as a lost capability.
func TestFoldDropsTheAbsenceMarkerWhenSomethingIsFound(t *testing.T) {
	now := time.Now()
	got := foldCapabilityRows([]capabilityRow{
		capRowIn(1, "h1", roleNone, now.Add(-24*time.Hour), false),
		capRowIn(2, "h1", "compute", now, true),
	}, nil)

	if len(got[0].Dropped) != 0 {
		t.Errorf("dropped = %+v, want none — 'none' is not a role that was lost", got[0].Dropped)
	}
	if !got[0].Detected {
		t.Error("the newest pass found OpenStack and the host still reads as absent")
	}
}

// The probe writes deployment=unknown on purpose: local evidence cannot tell
// two farms behind one endpoint apart. Grouping on it would turn that refusal
// into a farm named "unknown" holding the whole fleet.
func TestFoldLeavesAHostUnassignedWithoutADeclaration(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "unknown"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "" {
		t.Errorf("farm = %q, want unassigned — the host cannot know this", got[0].Farm)
	}
}

// An identifier somebody placed on the host is a statement, not an inference,
// and is the one local fact allowed to decide membership.
func TestFoldAcceptsADeclaredDeployment(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "incheon-aio01"
	row.Details["deployment_source"] = "declared"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "incheon-aio01" {
		t.Errorf("farm = %q, want the declared id", got[0].Farm)
	}
	if got[0].Confidence != ConfidenceDeclared {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, ConfidenceDeclared)
	}
}

// A deployment id with no source did not come from a declaration. Treating it
// as one would let any value that reached the details map become a farm.
func TestFoldRejectsADeploymentIDWithNoDeclaredSource(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "guessed-from-keystone"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "" {
		t.Errorf("farm = %q, want unassigned — nothing declared this", got[0].Farm)
	}
}

// A membership row is written by whatever can see the control plane, so it
// outranks anything the host says about itself.
func TestFoldPrefersAMembershipOverTheHostsOwnClaim(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "stale-label"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "incheon-aio01", Confidence: ConfidenceConfirmed}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Farm != "incheon-aio01" || got[0].Confidence != ConfidenceConfirmed {
		t.Errorf("farm = %q/%q, want the confirmed membership", got[0].Farm, got[0].Confidence)
	}
}

// Two deployments claiming one host is a real state, not something to resolve
// by picking one. Silently choosing would hide a split-brain inventory.
func TestFoldFlagsAHostClaimedByTwoDeployments(t *testing.T) {
	members := map[string][]OpenStackMembership{
		"h1": {
			{DeploymentID: "farm-a", Confidence: ConfidenceConfirmed},
			{DeploymentID: "farm-b", Confidence: ConfidenceLocalOnly},
		},
	}
	got := foldCapabilityRows([]capabilityRow{capRow("h1", "compute", time.Now(), true)}, members)

	if got[0].Confidence != ConfidenceConflict {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, ConfidenceConflict)
	}
	if len(got[0].Memberships) != 2 {
		t.Errorf("memberships = %d, want both kept so the conflict can be read", len(got[0].Memberships))
	}
}

// "unknown" is where a failed first probe hangs its error. It is bookkeeping,
// not something the host does, and listing it as a role would put "unknown" in
// the list of what a machine runs.
func TestFoldDoesNotTreatTheErrorPlaceholderAsARole(t *testing.T) {
	row := capRow("h1", RoleUnknown, time.Now(), false)
	row.LastError = "probe timed out"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if len(got[0].Roles) != 0 {
		t.Errorf("roles = %v, want none", got[0].Roles)
	}
	if got[0].LastError != "probe timed out" {
		t.Errorf("last_error = %q, want the failure to survive the fold", got[0].LastError)
	}
}

// The Keystone every service authenticates against is the one local fact that
// groups a deployment. A controller and its compute nodes name the same one.
func TestFoldGroupsByKeystoneWhenNothingHasClaimedTheHost(t *testing.T) {
	mk := func(host string) capabilityRow {
		r := capRow(host, "compute", time.Now(), true)
		r.Details["deployment"] = "unknown"
		r.Details["keystone_url"] = "172.16.0.245:5000"
		return r
	}
	got := foldCapabilityRows([]capabilityRow{mk("h1"), mk("h2")}, nil)

	for _, h := range got {
		if h.Farm != "172.16.0.245:5000" {
			t.Errorf("%s farm = %q, want the shared Keystone", h.Hostname, h.Farm)
		}
		// Never confirmed: two deployments behind one proxy look identical from
		// a host, and only the control plane can tell them apart.
		if h.Confidence != ConfidenceLocalOnly {
			t.Errorf("%s confidence = %q, want %q", h.Hostname, h.Confidence, ConfidenceLocalOnly)
		}
	}
}

// A declaration outranks the observation. Somebody placing an id on the host is
// a statement; reading a config file is an inference.
func TestFoldPrefersADeclarationOverTheKeystoneObservation(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "incheon-aio01"
	row.Details["deployment_source"] = "declared"
	row.Details["keystone_url"] = "172.16.0.245:5000"

	got := foldCapabilityRows([]capabilityRow{row}, nil)

	if got[0].Farm != "incheon-aio01" || got[0].Confidence != ConfidenceDeclared {
		t.Errorf("farm = %q/%q, want the declaration", got[0].Farm, got[0].Confidence)
	}
}

// Different endpoints are different deployments and must not merge.
func TestFoldKeepsDifferentKeystonesApart(t *testing.T) {
	mk := func(host, ks string) capabilityRow {
		r := capRow(host, "compute", time.Now(), true)
		r.Details["keystone_url"] = ks
		return r
	}
	got := foldCapabilityRows([]capabilityRow{
		mk("h1", "192.168.201.130:5000"),
		mk("h2", "192.168.201.90:5000"),
	}, nil)

	if got[0].Farm == got[1].Farm {
		t.Errorf("two deployments collapsed into %q", got[0].Farm)
	}
}

// A membership row used to win outright, which inverted the scale it is ranked
// on. A dedicated Neutron or Cinder node — one nova never lists — has a
// declared identifier and gets a local-only membership from the reconciler, and
// came out of that reconcile weaker than it went in:
//
//	declared → reconcile → local-only
func TestFoldDoesNotLetAWeakerMembershipBeatADeclaration(t *testing.T) {
	row := capRow("h1", "network", time.Now(), true)
	row.Details["deployment"] = "incheon"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "incheon", Confidence: ConfidenceLocalOnly}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Confidence != ConfidenceDeclared {
		t.Errorf("confidence = %q, want %q — the declaration is the stronger claim",
			got[0].Confidence, ConfidenceDeclared)
	}
	if got[0].Farm != "incheon" {
		t.Errorf("farm = %q", got[0].Farm)
	}
}

// The ranking still runs the other way: a confirmed membership beats a
// declaration, because the control plane saw what the label only asserts.
func TestFoldLetsAConfirmedMembershipBeatADeclaration(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "incheon"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "incheon", Confidence: ConfidenceConfirmed}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", got[0].Confidence, ConfidenceConfirmed)
	}
}

// A ranking that resolves cleanly is not a conflict. A stale label beside a
// confirmed membership is something to fix, not a reason to mark the host
// unusable — and marking it would bury the conflicts that are real.
func TestFoldDoesNotCallAResolvedRankingAConflict(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "stale-label"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "incheon", Confidence: ConfidenceConfirmed}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Confidence == ConfidenceConflict {
		t.Error("a confirmed membership over a stale label was reported as a conflict")
	}
	if got[0].Farm != "incheon" {
		t.Errorf("farm = %q, want the confirmed one", got[0].Farm)
	}
}

// Equal rank naming different deployments is where the scale has no answer, so
// there is nothing to report but the disagreement.
func TestFoldFlagsEqualRankClaimsThatDisagree(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["deployment"] = "farm-a"
	row.Details["deployment_source"] = "declared"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "farm-b", Confidence: ConfidenceDeclared}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Confidence != ConfidenceConflict {
		t.Errorf("confidence = %q, want %q — two declarations disagree", got[0].Confidence, ConfidenceConflict)
	}
}

// A membership and the host's own Keystone name the same deployment by
// different labels — the endpoint, and whatever id the reconciler recorded.
// Ranking them against each other made every reconciled host in the fleet look
// like a conflict between a deployment and its own Keystone.
func TestFoldDoesNotFightAMembershipWithTheHostsKeystone(t *testing.T) {
	row := capRow("h1", "compute", time.Now(), true)
	row.Details["keystone_url"] = "172.16.0.245:5000"
	members := map[string][]OpenStackMembership{
		"h1": {{DeploymentID: "seoul-a", Confidence: ConfidenceLocalOnly}},
	}

	got := foldCapabilityRows([]capabilityRow{row}, members)

	if got[0].Confidence == ConfidenceConflict {
		t.Error("a membership beside the host's own Keystone was reported as a conflict")
	}
	if got[0].Farm != "seoul-a" {
		t.Errorf("farm = %q, want the filed membership", got[0].Farm)
	}
}
