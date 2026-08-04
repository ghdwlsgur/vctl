package store

import (
	"context"
	"encoding/json"
	"maps"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
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

	// Roles the most recent probe found.
	Roles []string `json:"roles,omitempty"`

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

// Membership confidence values, in the order automation should trust them. Only
// the first two are statements; the rest are observations.
const (
	// ConfidenceDeclared: an identifier somebody placed on the host on purpose.
	ConfidenceDeclared = "declared"
	// ConfidenceConfirmed: local evidence and the control plane agree.
	ConfidenceConfirmed = "confirmed"
	// ConfidenceLocalOnly: the host runs the services, nothing has confirmed
	// which deployment they belong to.
	ConfidenceLocalOnly = "local-only"
	// ConfidenceControlOnly: registered centrally, nothing found on the host.
	ConfidenceControlOnly = "control-only"
	// ConfidenceConflict: the evidence disagrees.
	ConfidenceConflict = "conflict"
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

// OpenStackCoverage says how much of the fleet has been looked at, which is the
// context an empty listing needs: no OpenStack hosts because none were found is
// a different situation from none because nothing has probed yet.
type OpenStackCoverage struct {
	// Hosts is the inventory excluding retired ones — nothing is expected of
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
	rows, err := queryAndCollect(ctx, s.pool, `
		SELECT c.hostname, c.role, c.detected, c.components, c.details,
		       c.last_error, c.observed_at,
		       coalesce(s.dc,''), coalesce(s.state,'active')
		FROM server_capabilities c
		LEFT JOIN servers s ON s.hostname = c.hostname
		WHERE c.kind = $1
		ORDER BY c.hostname, c.role`,
		[]any{KindOpenStack}, scanCapabilityRow)
	if err != nil {
		return nil, err
	}
	members, err := s.openStackMemberships(ctx)
	if err != nil {
		return nil, err
	}
	return foldCapabilityRows(rows, members), nil
}

// OpenStackCoverageOf counts the fleet against what has been probed, from the
// same folded hosts the listing renders.
//
// The counts were SQL over server_capabilities at first, and that quietly
// disagreed with the listing: the query judged every row on its own, while the
// fold judges the newest pass. A controller whose earlier probes had failed and
// whose latest one succeeded showed nine roles in the table and "1 could not be
// probed" in the summary underneath it — the stale row was still there, and
// only one of the two readers knew it was stale.
//
// Only the inventory total stays a query, because it is not in these rows.
func (s *Store) OpenStackCoverageOf(ctx context.Context, hosts []OpenStackHost) (OpenStackCoverage, error) {
	c := OpenStackCoverage{Probed: len(hosts)}
	// Retired hosts are excluded: nothing is expected of them, so counting them
	// would leave coverage permanently short of complete.
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM servers WHERE coalesce(state,'active') <> $1`,
		StateRetired).Scan(&c.Hosts); err != nil {
		return c, err
	}
	for _, h := range hosts {
		switch {
		case h.Detected:
			c.Running++
		case h.LastError != "":
			c.Failed++
		default:
			c.Absent++
		}
	}
	// Clamped because the two numbers come from different places: a capability
	// row for a host since retired would otherwise make this negative.
	if c.Unprobed = c.Hosts - c.Probed; c.Unprobed < 0 {
		c.Unprobed = 0
	}
	return c, nil
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
	if err := r.Scan(&row.Hostname, &row.Role, &row.Detected, &comps, &details,
		&row.LastError, &row.ObservedAt, &row.DC, &row.HostState); err != nil {
		return row, err
	}
	// A row with malformed JSON still says which host holds which role, which is
	// most of its value — so it stays in the listing without its detail.
	_ = json.Unmarshal(comps, &row.Components)
	_ = json.Unmarshal(details, &row.Details)
	return row, nil
}

func (s *Store) openStackMemberships(ctx context.Context) (map[string][]OpenStackMembership, error) {
	rows, err := queryAndCollect(ctx, s.pool, `
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
func foldCapabilityRows(rows []capabilityRow, members map[string][]OpenStackMembership) []OpenStackHost {
	byHost := map[string]*OpenStackHost{}
	order := []string{}
	newest := map[string]time.Time{}
	for _, r := range rows {
		if _, ok := byHost[r.Hostname]; !ok {
			byHost[r.Hostname] = &OpenStackHost{
				Hostname: r.Hostname, DC: r.DC, HostState: StateOrActive(r.HostState),
			}
			order = append(order, r.Hostname)
		}
		if r.ObservedAt.After(newest[r.Hostname]) {
			newest[r.Hostname] = r.ObservedAt
		}
	}
	for _, r := range rows {
		h := byHost[r.Hostname]
		// Only the newest pass describes the host now. Components and details
		// from a lagging row belong to a role it no longer holds, so taking them
		// would resurrect versions of software that has been removed.
		if !r.ObservedAt.Before(newest[r.Hostname]) {
			h.ObservedAt = r.ObservedAt
			h.Detected = h.Detected || r.Detected
			if !isPlaceholderRole(r.Role) {
				h.Roles = append(h.Roles, r.Role)
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
func attachFarm(h *OpenStackHost, ms []OpenStackMembership) {
	h.Memberships = ms
	if len(ms) > 0 {
		best := ms[0]
		for _, m := range ms[1:] {
			if confidenceRank(m.Confidence) < confidenceRank(best.Confidence) {
				best = m
			}
		}
		h.Farm, h.FarmName, h.FarmRegion = best.DeploymentID, best.DisplayName, best.Region
		h.Confidence = best.Confidence
		if len(ms) > 1 {
			h.Confidence = ConfidenceConflict
		}
		return
	}
	if id := h.Details["deployment"]; id != "" && id != "unknown" &&
		h.Details["deployment_source"] == "declared" {
		h.Farm, h.Confidence = id, ConfidenceDeclared
	}
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
