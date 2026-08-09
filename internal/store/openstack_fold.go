package store

import (
	"maps"
	"sort"
)

// The assembler: capability and membership rows in, OpenStackHost records out.
//
// Separate from openstack_store.go, which is the adapter — statements, scans and
// the transactions around them. What is here is judgement about the fleet: which
// roles a host currently holds, which deployment it is shown under, when the
// evidence disagrees, and how two probes' findings merge. None of it touches a
// database, and none of it should.
//
// They were one file. The adapter ran a query, folded the rows, ranked farm
// claims and decided what counted as a conflict, so "why is this host under that
// deployment" was answered in the same place as "what does this SELECT return" —
// and the answer could only be exercised through a database. Everything below is
// a pure function over rows, which is why openstack_fold_test.go can hold it to
// its cases without one.
//
// TestTheAssemblerHasNoDatabaseInIt keeps the line where it is.

// isPlaceholderRole reports whether a row's role is a bookkeeping marker rather
// than something the host does. Rendering either as a role would put "none" and
// "unknown" in a list of what a machine runs.
func isPlaceholderRole(role string) bool {
	return role == roleNone || role == RoleUnknown
}

// Parked reports whether the inventory says nothing is expected of this host
// right now.
//
// A machine in a maintenance window or already decommissioned is not a gap in
// the fleet's OpenStack coverage — somebody decided it should be out, and
// reporting its roles, its farm and its anomalies argues with that decision
// every time the listing is read. A farm whose hosts are all parked stops being
// listed at all, which is the point: some farms exist only as hardware nobody
// is operating.
//
// Broken is deliberately not parked. A broken host is one somebody wants to see.
func (h OpenStackHost) Parked() bool {
	switch h.HostState {
	case StateMaintenance, StateRetired:
		return true
	}
	return false
}

// InService drops what a fleet listing should not argue about: hosts the
// inventory has parked, and hosts belonging to a deployment somebody retired.
//
// Two keys, not one, because they answer different questions. A host in a
// maintenance window is one machine out; a farm nobody operates is a whole
// deployment out. Deriving the second from the first — hiding a farm because
// any host in it is parked — would make one controller going into maintenance
// take its entire farm off the listing, which is exactly when you want to see
// the rest of it.
//
// A function over the result rather than a filter in the query, because several
// readers must NOT use it:
//
//   - the reconciler matches inventory against what the control plane reports,
//     and hiding a parked host there would make nova's record of it look like a
//     machine no inventory has. It would then be filed as control-only, which is
//     the opposite of what parking it meant.
//   - asking for one host or one farm by name is an explicit request. Answering
//     "no such host" because somebody parked it would be a lie about the
//     inventory.
//   - the farm picker has to reach parked farms, or a retired one could never be
//     brought back.
//
// So the fleet listing hides them and everything you address by name does not.
func InService(hosts []OpenStackHost, deployments []Deployment) []OpenStackHost {
	retired := make(map[string]bool, len(deployments))
	for _, d := range deployments {
		if d.State == StateRetired {
			retired[d.ID] = true
		}
	}
	out := make([]OpenStackHost, 0, len(hosts))
	for _, h := range hosts {
		if h.Parked() || retired[h.Farm] {
			continue
		}
		out = append(out, h)
	}
	return out
}

// foldCapabilityRows turns per-role rows into per-host records, splitting the
// roles the latest probe found from the ones it no longer does.
//
// The split is by pass number, not by time. Both were the same column once, and
// the cost of that was paid on the timestamp's side: it had to be forced upward
// on every write to stay a reliable ordering, which let one host's fast clock
// pin the whole listing's freshness into the future. A counter orders the passes
// and leaves the clock alone — see the migration and ReplaceCapabilities.
func foldCapabilityRows(rows []capabilityRow, members map[string][]OpenStackMembership) []OpenStackHost {
	byHost := map[string]*OpenStackHost{}
	order := []string{}
	newest := map[string]int64{}
	for _, r := range rows {
		if _, ok := byHost[r.Hostname]; !ok {
			byHost[r.Hostname] = &OpenStackHost{
				Hostname: r.Hostname, DC: r.DC, HostState: StateOrActive(r.HostState),
			}
			order = append(order, r.Hostname)
			// Seeded from the first row rather than left at the zero value. A
			// map's missing entry is 0 and the migration numbers history
			// downward from there, so a host whose rows are all backfilled has
			// every pass below the default — and comparing against it read the
			// whole host as dropped, roles and all. Measured on the fixture in
			// TestTheBackfillNumbersExistingPassesInTheOrderTheyWereAlreadyIn.
			newest[r.Hostname] = r.PassID
			continue
		}
		if r.PassID > newest[r.Hostname] {
			newest[r.Hostname] = r.PassID
		}
	}
	for _, r := range rows {
		h := byHost[r.Hostname]
		// Only the newest pass describes the host now. Components and details
		// from a lagging row belong to a role it no longer holds, so taking them
		// would resurrect versions of software that has been removed.
		if r.PassID >= newest[r.Hostname] {
			h.ObservedAt = r.ObservedAt
			h.Detected = h.Detected || r.Detected
			if !isPlaceholderRole(r.Role) {
				h.Roles = append(h.Roles, r.Role)
				if r.Active {
					h.ActiveRoles = append(h.ActiveRoles, r.Role)
				}
			}
			mergeInto(&h.Components, r.Components)
			mergeDetails(&h.Details, r.Details)
			if r.LastError != "" {
				h.LastError = r.LastError
			}
			continue
		}
		if !isPlaceholderRole(r.Role) {
			h.Dropped = append(h.Dropped, DroppedRole{Role: r.Role, LastSeen: r.ObservedAt})
		}
	}
	out := make([]OpenStackHost, 0, len(order))
	sort.Strings(order)
	for _, name := range order {
		h := byHost[name]
		sort.Strings(h.Roles)
		sort.Strings(h.ActiveRoles)
		sort.Slice(h.Dropped, func(i, j int) bool { return h.Dropped[i].Role < h.Dropped[j].Role })
		attachFarm(h, members[name])
		out = append(out, *h)
	}
	return out
}

// attachFarm decides which deployment a host is shown under.
//
// A membership row is the answer whenever one exists: it is written by whatever
// can see the control plane, which is the only thing able to separate two farms
// behind one endpoint. Failing that, an identifier the host itself declares is
// used — that is a statement somebody placed there on purpose, not an inference
// from what the host runs. A host running OpenStack with neither is left
// unassigned rather than grouped by guesswork, because a farm invented from
// local evidence is exactly the mistake this schema was shaped to avoid.
//
// Several memberships is not an error to hide. A host genuinely moving between
// deployments, or claimed by two, is a real state and the listing has to be able
// to show it.
// farmClaim is one piece of evidence that a host belongs to a deployment.
type farmClaim struct {
	ID         string
	Name       string
	Region     string
	Confidence string
	// fromMembership marks a claim somebody or something filed, as opposed to
	// one derived from what the host says. It only breaks ties.
	fromMembership bool
}

// attachFarm decides which deployment a host is shown under, by ranking every
// claim on the same scale.
//
// Membership rows used to win outright, which inverted the scale they are
// ranked on. A host with a declared identifier and a local-only membership —
// what a dedicated Neutron or Cinder node gets, because nova never lists it —
// came out of a reconcile weaker than it went in:
//
//	declared → reconcile → local-only
//
// Now the strongest claim wins wherever it came from. A membership only breaks
// a tie, on the grounds that something filed it.
//
// Several memberships is still a conflict, and so is a declaration that
// disagrees with one. Both are real states, and picking a side would hide a
// split-brain inventory behind a confident-looking answer.
func attachFarm(h *OpenStackHost, ms []OpenStackMembership) {
	h.Memberships = ms

	claims := make([]farmClaim, 0, len(ms)+2)
	for _, m := range ms {
		claims = append(claims, farmClaim{
			ID: m.DeploymentID, Name: m.DisplayName, Region: m.Region,
			Confidence: m.Confidence, fromMembership: true,
		})
	}
	// An identifier somebody placed on the host on purpose. That is a
	// statement, not an inference.
	if id := h.Details["deployment"]; id != "" && id != "unknown" &&
		h.Details["deployment_source"] == "declared" {
		claims = append(claims, farmClaim{ID: id, Confidence: ConfidenceDeclared})
	}
	// Failing both, the Keystone every service on the host authenticates
	// against. Hosts that name the same one are almost always one deployment —
	// in this fleet a controller and its compute nodes all name
	// 172.16.0.245:5000 and are — but "almost always" is exactly why this is
	// local-only rather than confirmed. Two deployments behind one proxy would
	// look identical from here, and only something that can see the control
	// plane can tell them apart.
	//
	// Derived rather than stored: openstack_memberships is for claims somebody
	// or something made, and this is an observation that changes whenever the
	// probe runs. Writing it would age into a fact nobody filed.
	//
	// Only when nothing has been filed. A membership already answers for this
	// host, and the two name the same deployment by different labels — the
	// endpoint and whatever id the reconciler recorded. Ranking them against
	// each other made every reconciled host look like a conflict between a
	// deployment and its own Keystone.
	if u := h.Details["keystone_url"]; u != "" && len(ms) == 0 {
		claims = append(claims, farmClaim{ID: u, Confidence: ConfidenceLocalOnly})
	}
	if len(claims) == 0 {
		return
	}

	best := claims[0]
	for _, c := range claims[1:] {
		if better(c, best) {
			best = c
		}
	}
	h.Farm, h.FarmName, h.FarmRegion = best.ID, best.Name, best.Region
	h.Confidence = best.Confidence
	if conflicting(ms, claims) {
		h.Confidence = ConfidenceConflict
	}
}

// better reports whether a is the stronger claim. Rank first; a filed claim
// breaks a tie against a derived one.
func better(a, b farmClaim) bool {
	ra, rb := confidenceRank(a.Confidence), confidenceRank(b.Confidence)
	if ra != rb {
		return ra < rb
	}
	return a.fromMembership && !b.fromMembership
}

// conflicting reports whether the evidence genuinely disagrees.
//
// Two things count, and nothing else does.
//
// Two filed memberships, whatever their confidence. Two deployments each
// holding a row for one host is a split-brain inventory, and the stronger row
// winning does not make the weaker one stop claiming the machine.
//
// Two claims of equal rank naming different deployments — there the scale has
// no answer, so there is nothing to report but the disagreement.
//
// A ranking that resolves cleanly is not a conflict. A confirmed membership
// beside a stale declared label is a label somebody should fix, not a reason to
// mark the host unusable; and a local-only inference under a confirmed
// membership is the normal state of every reconciled host in the fleet.
func conflicting(ms []OpenStackMembership, claims []farmClaim) bool {
	if len(ms) > 1 {
		return true
	}
	byRank := map[int]string{}
	for _, c := range claims {
		r := confidenceRank(c.Confidence)
		if seen, ok := byRank[r]; ok && seen != c.ID {
			return true
		}
		byRank[r] = c.ID
	}
	return false
}

// confidenceRank orders the evidence, strongest first.
func confidenceRank(c string) int {
	switch c {
	case ConfidenceConfirmed:
		return 0
	case ConfidenceDeclared:
		return 1
	case ConfidenceLocalOnly:
		return 2
	case ConfidenceControlOnly:
		return 3
	default:
		return 4
	}
}

func mergeInto(dst *map[string]CapabilityComponent, src map[string]CapabilityComponent) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = map[string]CapabilityComponent{}
	}
	maps.Copy(*dst, src)
}

func mergeDetails(dst *map[string]string, src map[string]string) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = map[string]string{}
	}
	maps.Copy(*dst, src)
}
