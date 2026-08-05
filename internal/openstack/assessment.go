// Package openstack turns what has been collected about a deployment into a
// judgement about it.
//
// The collectors answer separate questions and store separate rows: a probe
// says what a host runs, a reconcile says which deployment claims it, a nova
// listing says which VMs sit on it. Reading a farm means combining all three,
// and every reader needs the same combination — is this deployment healthy, is
// what I am looking at current, and what about it is odd.
//
// That combining lived in the CLI's renderer, which meant an API or a web view
// would have had to make the same judgements again. Two implementations of "is
// this farm drifting" disagree eventually, and the one somebody is looking at
// is not necessarily the one that is right. This package is the single answer;
// the renderers turn it into text.
package openstack

import (
	"sort"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Assessment is everything known about one deployment, judged.
type Assessment struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Region string `json:"region,omitempty"`

	// State is what an operator declared about this deployment. Anomalies are
	// still reported when it is not active — a declared fault does not stop
	// being a fault — but they are marked as expected, so an unattended farm
	// and a known-broken one do not read the same.
	State      string     `json:"state,omitempty"`
	StateNote  string     `json:"state_note,omitempty"`
	StateSince *time.Time `json:"state_since,omitempty"`

	Architecture Architecture `json:"architecture"`
	Membership   Membership   `json:"membership"`
	Health       Health       `json:"health"`
	Freshness    Freshness    `json:"freshness"`
	Versions     Versions     `json:"versions"`

	// Anomalies are the things worth a second look, in one place. Scattered
	// across the other sections they are each a footnote; together they are the
	// answer to "what is wrong with this farm".
	Anomalies []Anomaly `json:"anomalies,omitempty"`
}

// Architecture is what the deployment is built out of.
type Architecture struct {
	Sections []RoleSection `json:"sections,omitempty"`
	Hosts    int           `json:"hosts"`
	VMs      int           `json:"vms"`
}

// RoleSection is one role and the hosts holding it.
type RoleSection struct {
	Role  string       `json:"role"`
	Hosts []RoleMember `json:"hosts"`
	// Down is how many hold the role with nothing running behind it. The
	// section keeps its full size — the deployment did not shrink — and this
	// says what is not working in it.
	Down int `json:"down,omitempty"`
}

// RoleMember is one host under a role.
type RoleMember struct {
	Hostname string `json:"hostname"`
	Release  string `json:"release,omitempty"`
	Roles    int    `json:"roles"`
	Down     bool   `json:"down,omitempty"`
	// AlsoIn is the earlier section this host already appeared under. Repeating
	// its facts there too would make an all-in-one deployment read as several
	// times its size.
	AlsoIn string `json:"also_in,omitempty"`
	VMs    int    `json:"vms,omitempty"`
}

// Membership is how well the deployment's roster is established.
type Membership struct {
	Confirmed int `json:"confirmed"`
	Total     int `json:"total"`
	// Unsettled are hosts resting on something weaker than confirmation, each
	// with the confidence that says why.
	Unsettled []string `json:"unsettled,omitempty"`
}

// Health is what is running versus what is deployed.
type Health struct {
	RolesDown int `json:"roles_down"`
	HostsDown int `json:"hosts_down"`
	// VMsMissing are VMs the control plane listed before and does not now.
	VMsMissing int `json:"vms_missing"`
}

// Freshness says how much to trust the rest of this.
type Freshness struct {
	// LastSuccess is when membership was last settled. Nil means never.
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	// Complete says whether the last answer was whole. A partial one may
	// confirm but may not demote, so a reader of Membership needs this.
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
	// Stale is true when the last success is older than the window a caller
	// passed — the judgement, so every renderer agrees on it.
	Stale bool `json:"stale"`
}

// Versions is the release picture.
type Versions struct {
	// ByRelease counts hosts per release string.
	ByRelease map[string]int `json:"by_release,omitempty"`
	// Drifting is true when more than one release is in the deployment.
	Drifting bool `json:"drifting"`
}

// Anomaly is one thing about the deployment worth a second look.
type Anomaly struct {
	// Kind is a stable slug so a caller can filter without parsing prose.
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// Severity orders them: "warn" is something to look at, "error" is
	// something wrong now.
	Severity string `json:"severity"`

	// Expected marks an anomaly that the declared state already accounts for.
	// It is still reported — hiding it would make a farm declared broken look
	// healthy, and somebody has to be able to see what the fault actually is —
	// but it is not news.
	Expected bool `json:"expected,omitempty"`
}

// Anomaly kinds.
const (
	AnomalyGhost       = "ghost-host"    // nova knows a machine the inventory does not
	AnomalyUnsettled   = "unsettled"     // membership rests on weak evidence
	AnomalyConflict    = "conflict"      // the evidence disagrees
	AnomalyRoleDown    = "role-down"     // a deployed role with nothing running
	AnomalyDrift       = "release-drift" // more than one release in one farm
	AnomalyStale       = "stale"         // nothing has reconciled recently
	AnomalyNeverRun    = "never-reconciled"
	AnomalyReconcileNG = "reconcile-failing"
	AnomalyVMMissing   = "vm-missing" // a VM the control plane no longer lists
)

// Severities.
const (
	SeverityWarn  = "warn"
	SeverityError = "error"
)

// Input is what a caller has collected. Every field is optional: an assessment
// built from less says less, rather than refusing.
type Input struct {
	ID     string
	Name   string
	Region string

	// State is what an operator declared. Empty is treated as active.
	State      string
	StateNote  string
	StateSince *time.Time

	// Hosts are this deployment's hosts, already filtered to it.
	Hosts []store.OpenStackHost
	// Instances are its VMs, live and missing alike — Health counts the missing
	// ones, so filtering them out beforehand would hide the number.
	Instances []store.Instance
	Run       *store.ReconcileRun
	Ghosts    []store.ControlHost

	// StaleAfter is how old a successful reconcile may be before Freshness
	// calls it stale. Zero disables the judgement rather than making everything
	// stale, which is the safer direction for a caller that forgot to set it.
	StaleAfter time.Duration
	Now        time.Time
}

// roleOrder walks the architecture the way somebody reasons about it: the
// control plane first, then what it controls, then the services around them.
// Roles outside this list follow alphabetically.
var roleOrder = []string{
	"controller", "compute", "network", "block-storage", "image",
	"identity", "dashboard", "orchestration", "load-balancer",
}

// Assess judges one deployment from what has been collected about it.
func Assess(in Input) Assessment {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	a := Assessment{
		ID: in.ID, Name: in.Name, Region: in.Region,
		State: in.State, StateNote: in.StateNote, StateSince: in.StateSince,
	}
	if a.State == "" {
		a.State = store.StateActive
	}
	a.Versions.ByRelease = map[string]int{}

	vmsByHypervisor := map[string]int{}
	for _, v := range in.Instances {
		if v.MissingSince != nil {
			a.Health.VMsMissing++
			continue
		}
		vmsByHypervisor[v.HypervisorHostname]++
	}
	a.Architecture.VMs = len(in.Instances) - a.Health.VMsMissing

	byRole := map[string][]store.OpenStackHost{}
	for _, h := range in.Hosts {
		a.Membership.Total++
		switch h.Confidence {
		case store.ConfidenceConfirmed:
			a.Membership.Confirmed++
		case store.ConfidenceConflict:
			a.Membership.Unsettled = append(a.Membership.Unsettled, h.Hostname+" ("+h.Confidence+")")
			a.Anomalies = append(a.Anomalies, Anomaly{
				Kind: AnomalyConflict, Subject: h.Hostname, Severity: SeverityError,
				Detail: "the evidence disagrees about which deployment this host belongs to",
			})
		default:
			a.Membership.Unsettled = append(a.Membership.Unsettled, h.Hostname+" ("+h.Confidence+")")
		}
		if len(h.Roles) > 0 && len(h.ActiveRoles) == 0 {
			a.Health.HostsDown++
		}
		a.Versions.ByRelease[ReleaseOf(h)]++
		for _, r := range h.Roles {
			byRole[r] = append(byRole[r], h)
		}
	}
	a.Architecture.Hosts = a.Membership.Total

	firstSeen := map[string]string{}
	for _, role := range orderedRoles(byRole) {
		hs := byRole[role]
		sort.Slice(hs, func(i, j int) bool { return hs[i].Hostname < hs[j].Hostname })
		sec := RoleSection{Role: role}
		for _, h := range hs {
			m := RoleMember{
				Hostname: h.Hostname, Release: ReleaseOf(h), Roles: len(h.Roles),
				VMs: vmsByHypervisor[h.Hostname],
			}
			if !containsFold(h.ActiveRoles, role) {
				m.Down = true
				sec.Down++
				a.Health.RolesDown++
				a.Anomalies = append(a.Anomalies, Anomaly{
					Kind: AnomalyRoleDown, Subject: h.Hostname, Severity: SeverityWarn,
					Detail: "holds " + role + " with nothing running behind it",
				})
			}
			if prev, seen := firstSeen[h.Hostname]; seen {
				m.AlsoIn = prev
			} else {
				firstSeen[h.Hostname] = role
			}
			sec.Hosts = append(sec.Hosts, m)
		}
		a.Architecture.Sections = append(a.Architecture.Sections, sec)
	}
	sort.Strings(a.Membership.Unsettled)

	a.Versions.Drifting = len(a.Versions.ByRelease) > 1
	if a.Versions.Drifting {
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyDrift, Subject: in.ID, Severity: SeverityWarn,
			Detail: "more than one release in one deployment: " + releaseSummary(a.Versions.ByRelease),
		})
	}

	a.Freshness = assessFreshness(in.Run, in.StaleAfter, now)
	switch {
	case in.Run == nil:
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyNeverRun, Subject: in.ID, Severity: SeverityWarn,
			Detail: "no reconcile has been recorded, so membership rests on local evidence alone",
		})
	case a.Freshness.Error != "":
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyReconcileNG, Subject: in.ID, Severity: SeverityError,
			Detail: "the last reconcile failed: " + a.Freshness.Error,
		})
	case a.Freshness.Stale:
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyStale, Subject: in.ID, Severity: SeverityWarn,
			Detail: "nothing has reconciled this deployment recently",
		})
	}

	for _, g := range in.Ghosts {
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyGhost, Subject: g.NovaHostname, Severity: SeverityWarn,
			Detail: "the control plane has known this host since " +
				g.FirstSeenAt.Format("2006-01-02") + " and the inventory does not have it",
		})
	}
	if a.Health.VMsMissing > 0 {
		a.Anomalies = append(a.Anomalies, Anomaly{
			Kind: AnomalyVMMissing, Subject: in.ID, Severity: SeverityWarn,
			Detail: "the control plane no longer lists VMs it listed before",
		})
	}

	// A declared state accounts for what follows from it. The anomalies stay —
	// somebody marking a farm broken still needs to see what is broken about it,
	// and hiding them would make the farm look healthy — but they stop being
	// news, which is what separates an unattended fault from a known one.
	if a.State != store.StateActive {
		for i := range a.Anomalies {
			if expectedUnder(a.State, a.Anomalies[i].Kind) {
				a.Anomalies[i].Expected = true
			}
		}
	}

	// Errors first, then by kind, so the order is the same every run and the
	// worst thing is the first thing.
	sort.SliceStable(a.Anomalies, func(i, j int) bool {
		if (a.Anomalies[i].Severity == SeverityError) != (a.Anomalies[j].Severity == SeverityError) {
			return a.Anomalies[i].Severity == SeverityError
		}
		if a.Anomalies[i].Kind != a.Anomalies[j].Kind {
			return a.Anomalies[i].Kind < a.Anomalies[j].Kind
		}
		return a.Anomalies[i].Subject < a.Anomalies[j].Subject
	})
	return a
}

// expectedUnder says whether a declared state already accounts for an anomaly.
//
// Narrow on purpose. "broken" explains a control plane that will not answer; it
// does not explain a release drift or a host claimed by two deployments, and
// marking those expected would let a farm declared broken hide problems that
// have nothing to do with the fault.
func expectedUnder(state, kind string) bool {
	switch kind {
	case AnomalyReconcileNG, AnomalyStale, AnomalyRoleDown, AnomalyVMMissing:
		return state == store.StateBroken || state == store.StateMaintenance ||
			state == store.StateRetired
	case AnomalyNeverRun, AnomalyUnsettled:
		return state == store.StateRetired
	default:
		return false
	}
}

func assessFreshness(r *store.ReconcileRun, staleAfter time.Duration, now time.Time) Freshness {
	if r == nil {
		return Freshness{}
	}
	f := Freshness{
		LastSuccess: r.SucceededAt,
		LastAttempt: &r.StartedAt,
		Complete:    r.Complete,
	}
	// An error only counts as current if the attempt carrying it came after the
	// last success. A farm that failed once last week and has worked since is
	// not failing.
	if r.LastError != "" && (r.SucceededAt == nil || r.StartedAt.After(*r.SucceededAt)) {
		f.Error = r.LastError
	}
	// Zero disables the judgement rather than marking everything stale, which
	// is the safer direction for a caller that forgot to set it.
	if staleAfter > 0 && r.SucceededAt != nil && now.Sub(*r.SucceededAt) > staleAfter {
		f.Stale = true
	}
	return f
}

// ReleaseOf is the one string that stands for what a host runs: nova's version
// where nova is present, the first component's otherwise.
//
// Exported because the flat listing summarises the same host and the two views
// must never disagree about a release.
func ReleaseOf(h store.OpenStackHost) string {
	if c, ok := h.Components["nova-compute"]; ok && c.Version != "" {
		return c.Version
	}
	names := make([]string, 0, len(h.Components))
	for name := range h.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	// A running component before a stopped one: taking the first name
	// alphabetically summarised a healthy controller by the only service on it
	// that was down.
	var fallback string
	for _, name := range names {
		c := h.Components[name]
		if c.Version == "" {
			continue
		}
		if c.Active || !c.Service {
			return c.Version
		}
		if fallback == "" {
			fallback = c.Version
		}
	}
	if fallback != "" {
		return fallback
	}
	return "-"
}

func orderedRoles(byRole map[string][]store.OpenStackHost) []string {
	rank := map[string]int{}
	for i, r := range roleOrder {
		rank[r] = i
	}
	out := make([]string, 0, len(byRole))
	for r := range byRole {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, iOK := rank[out[i]]
		rj, jOK := rank[out[j]]
		switch {
		case iOK && jOK:
			return ri < rj
		case iOK != jOK:
			return iOK
		default:
			return out[i] < out[j]
		}
	})
	return out
}

func releaseSummary(byRelease map[string]int) string {
	keys := make([]string, 0, len(byRelease))
	for r := range byRelease {
		keys = append(keys, r)
	}
	sort.Slice(keys, func(i, j int) bool {
		if byRelease[keys[i]] != byRelease[keys[j]] {
			return byRelease[keys[i]] > byRelease[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, r := range keys {
		parts = append(parts, r)
	}
	return strings.Join(parts, ", ")
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
