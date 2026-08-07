package store

import (
	"context"
	"encoding/json"
	"maps"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
)

// OpenStackHost is one host as the openstack listing sees it: the roles the last
// probe found, which deployment claims it, and how old that observation is.
//
// The database keys capabilities per (hostname, role) because a host holds
// several at once. Reading is the other way round — the question is "what is
// this machine", not "who is a controller" — so the rows are folded back into
// one record per host here rather than in every caller.
type OpenStackHost struct {
	Hostname  string `json:"hostname"`
	DC        string `json:"dc,omitempty"`
	HostState string `json:"host_state"` // active | maintenance | broken | retired

	// Detected is whether the probe found OpenStack at all. False with a row
	// present means "looked, found nothing", which is a different answer from
	// having no row.
	Detected bool `json:"detected"`

	// Roles the most recent probe found — what the host is built to do,
	// running or not.
	Roles []string `json:"roles,omitempty"`

	// ActiveRoles are the subset with a running service behind them. The
	// difference between the two lists is the outage, and keeping them apart is
	// what stops a farm's topology from shrinking while something is down.
	ActiveRoles []string `json:"active_roles,omitempty"`

	// Dropped are roles an earlier probe found and the latest one did not.
	//
	// The agent has no DELETE on server_capabilities — deliberately, so a probe
	// cannot erase a fact — which means a role a host stops holding leaves its
	// row behind forever. Every role written by one pass carries that pass's
	// timestamp, so a row that lags the newest one is a role that has gone away.
	// Reporting it as current would keep a decommissioned neutron agent in the
	// listing indefinitely; dropping it silently would hide the change.
	Dropped []DroppedRole `json:"dropped_roles,omitempty"`

	Components map[string]CapabilityComponent `json:"components,omitempty"`
	Details    map[string]string              `json:"details,omitempty"`
	LastError  string                         `json:"last_error,omitempty"`

	// ObservedAt is the newest observation across this host's rows.
	ObservedAt time.Time `json:"observed_at"`

	// Farm is the deployment this host belongs to, and Confidence says on what
	// evidence. Empty Farm means nothing has claimed it.
	Farm        string                `json:"farm,omitempty"`
	FarmName    string                `json:"farm_name,omitempty"`
	FarmRegion  string                `json:"farm_region,omitempty"`
	Confidence  string                `json:"confidence,omitempty"`
	Memberships []OpenStackMembership `json:"memberships,omitempty"`
}

// DroppedRole is a role that has fallen out of the latest probe.
type DroppedRole struct {
	Role     string    `json:"role"`
	LastSeen time.Time `json:"last_seen"`
}

// OpenStackMembership is one deployment claiming one host.
type OpenStackMembership struct {
	DeploymentID string    `json:"deployment_id"`
	DisplayName  string    `json:"display_name,omitempty"`
	Region       string    `json:"region,omitempty"`
	Confidence   string    `json:"confidence"`
	ObservedAt   time.Time `json:"observed_at"`
}

// Membership confidence values, in the order automation should trust them.
//
// Defined where the decision that produces them is — internal/openstack/
// membership — and re-exported here for the readers that compare against a
// stored row. One definition, so a rename cannot leave half the codebase
// writing a word the other half does not recognise.
const (
	ConfidenceDeclared    = membership.Declared
	ConfidenceConfirmed   = membership.Confirmed
	ConfidenceLocalOnly   = membership.LocalOnly
	ConfidenceControlOnly = membership.ControlOnly
	ConfidenceConflict    = membership.Conflict
)

// KindOpenStack is the capability kind this file reads.
const KindOpenStack = "openstack"

// roleNone is what a probe files when it found nothing, so that "probed and
// absent" has a row and can be told from "never probed".
const roleNone = "none"

// RoleUnknown is filed when a probe could not complete and there was nothing
// already recorded for the host. It is not a role — it is a place to hang the
// error so a failed first probe is visible rather than silent.
const RoleUnknown = "unknown"

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

// OpenStackCoverage says how much of the fleet has been looked at, which is the
// context an empty listing needs: no OpenStack hosts because none were found is
// a different situation from none because nothing has probed yet.
type OpenStackCoverage struct {
	// Hosts is the inventory excluding parked ones — nothing is expected of
	// those, so counting them would make coverage look permanently incomplete.
	Hosts   int `json:"hosts"`
	Probed  int `json:"probed"`
	Running int `json:"running"`

	// Failed is a probe that could not answer. Folding these into Absent would
	// report "this host does not run OpenStack" on the strength of a timeout.
	Failed   int `json:"failed"`
	Absent   int `json:"absent"`
	Unprobed int `json:"unprobed"`
}

// OpenStackHosts returns every host a probe has filed an OpenStack capability
// for, newest observation first within each host, sorted by hostname.
func (s *Store) OpenStackHosts(ctx context.Context) ([]OpenStackHost, error) {
	return openStackHostsOn(ctx, s.pool)
}

func openStackHostsOn(ctx context.Context, db rowQuerier) ([]OpenStackHost, error) {
	rows, err := queryAndCollect(ctx, db, `
		SELECT c.hostname, c.role, c.detected, c.active, c.components, c.details,
		       c.last_error, c.observed_at, c.pass_id,
		       coalesce(s.dc,''), coalesce(s.state,'active')
		FROM server_capabilities c
		LEFT JOIN servers s ON s.hostname = c.hostname
		WHERE c.kind = $1
		ORDER BY c.hostname, c.role`,
		[]any{KindOpenStack}, scanCapabilityRow)
	if err != nil {
		return nil, err
	}
	members, err := openStackMembershipsOn(ctx, db)
	if err != nil {
		return nil, err
	}
	return foldCapabilityRows(rows, members), nil
}

// capabilityRow is one (host, role) row before the fold.
type capabilityRow struct {
	Capability
	DC        string
	HostState string
}

func scanCapabilityRow(r pgx.Rows) (capabilityRow, error) {
	var row capabilityRow
	var comps, details []byte
	if err := r.Scan(&row.Hostname, &row.Role, &row.Detected, &row.Active, &comps, &details,
		&row.LastError, &row.ObservedAt, &row.PassID, &row.DC, &row.HostState); err != nil {
		return row, err
	}
	// A row with malformed JSON still says which host holds which role, which is
	// most of its value — so it stays in the listing without its detail.
	_ = json.Unmarshal(comps, &row.Components)
	_ = json.Unmarshal(details, &row.Details)
	return row, nil
}

func openStackMembershipsOn(ctx context.Context, db rowQuerier) (map[string][]OpenStackMembership, error) {
	rows, err := queryAndCollect(ctx, db, `
		SELECT m.hostname, m.deployment_id, coalesce(d.display_name,''),
		       coalesce(d.region,''), m.confidence, m.observed_at
		FROM openstack_memberships m
		LEFT JOIN openstack_deployments d ON d.id = m.deployment_id
		ORDER BY m.hostname, m.deployment_id`,
		nil, func(r pgx.Rows) (hostMembership, error) {
			var hm hostMembership
			err := r.Scan(&hm.Hostname, &hm.DeploymentID, &hm.DisplayName,
				&hm.Region, &hm.Confidence, &hm.ObservedAt)
			return hm, err
		})
	if err != nil {
		return nil, err
	}
	out := map[string][]OpenStackMembership{}
	for _, hm := range rows {
		out[hm.Hostname] = append(out[hm.Hostname], hm.OpenStackMembership)
	}
	return out, nil
}

type hostMembership struct {
	Hostname string
	OpenStackMembership
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

// FarmSnapshot is everything one farm's screen is built from, read together.
//
// Assembled inside a single read transaction so the screen describes one moment.
// It used to be five independent reads, and a reconcile finishing between the
// second and the third put a host count from before it beside a run result from
// after it — a picture of the deployment that was never true. Nothing on screen
// says which reads came from where, so there is no way to notice from the
// output.
//
// DeploymentKnown separates "this deployment was never named" from "the read
// failed", which the caller used to conflate by ignoring the error.
type FarmSnapshot struct {
	Deployment      Deployment
	DeploymentKnown bool
	Hosts           []OpenStackHost
	Instances       []Instance
	Ghosts          []ControlHost
	Run             *ReconcileRun
}

// FarmSnapshot reads one deployment's whole picture at one instant.
//
// REPEATABLE READ rather than the default: every statement in the transaction
// then sees the same snapshot, which is the entire reason this exists. Read-only
// so it cannot block a writer or be chosen as a deadlock victim.
//
// Missing VMs are included. The assessment counts them, so filtering them out
// here would hide the number it exists to report.
func (s *Store) FarmSnapshot(ctx context.Context, id string) (FarmSnapshot, error) {
	var out FarmSnapshot
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hosts, err := openStackHostsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	for _, h := range hosts {
		if h.Farm == id && h.Detected {
			out.Hosts = append(out.Hosts, h)
		}
	}
	if out.Instances, err = instancesOn(ctx, tx, InstanceFilter{
		DeploymentID: id, IncludeMissing: true,
	}); err != nil {
		return out, err
	}
	if out.Ghosts, err = controlHostsOn(ctx, tx, id); err != nil {
		return out, err
	}
	runs, err := reconcileRunsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	if r, ok := runs[id]; ok {
		out.Run = &r
	}
	ds, err := deploymentsOn(ctx, tx)
	if err != nil {
		return out, err
	}
	for _, d := range ds {
		if d.ID == id {
			out.Deployment, out.DeploymentKnown = d, true
			break
		}
	}
	return out, nil
}
