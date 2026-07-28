package invcache

import (
	"context"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Memory answers inventory reads from a snapshot, reproducing the semantics of
// the Postgres queries in internal/store.
//
// The reimplementation is deliberate rather than incidental: Redis or any other
// key-value cache cannot run `ILIKE`, `inet = ANY(...)`, or the server_status
// join that Resolve depends on, so a cache that stores query results would only
// ever serve queries it had already seen. Holding the whole (small, slow-moving)
// table and filtering in Go handles arbitrary input instead — and makes the
// matching rules unit-testable without a database.
type Memory struct {
	snap *Snapshot
}

// NewMemory wraps a snapshot as a Reader. The snapshot is not copied; callers
// should not mutate it afterwards.
func NewMemory(snap *Snapshot) *Memory { return &Memory{snap: snap} }

// Snapshot returns the underlying snapshot (for age reporting).
func (m *Memory) Snapshot() *Snapshot { return m.snap }

func (m *Memory) rows() []store.ServerWithStatus {
	if m == nil || m.snap == nil {
		return nil
	}
	return m.snap.Servers
}

// Get returns the host with an exact hostname match.
//
// Postgres compares `hostname=$1` under the default collation, i.e. case
// sensitively, so this does too.
func (m *Memory) Get(_ context.Context, hostname string) (*store.Server, error) {
	for _, r := range m.rows() {
		if r.Hostname == hostname {
			sv := cloneServer(r.Server)
			return &sv, nil
		}
	}
	return nil, ErrNotFound
}

// Resolve mirrors store.Resolve: exact hostname first, then — when the query is
// an IP — any host answering on that address across the primary, operator-set,
// and agent-observed sets, and otherwise a fuzzy hostname match. One match
// returns the server; several return the candidates for the caller to choose
// between.
func (m *Memory) Resolve(ctx context.Context, query string) (*store.Server, []store.Server, error) {
	if sv, err := m.Get(ctx, query); err == nil {
		return sv, nil, nil
	}

	var match func(store.ServerWithStatus) bool
	if ip := net.ParseIP(query); ip != nil {
		match = func(r store.ServerWithStatus) bool { return rowHasIP(r, ip) }
	} else {
		re := likeContains(query)
		match = func(r store.ServerWithStatus) bool { return re.MatchString(r.Hostname) }
	}

	var cands []store.Server
	for _, r := range m.rows() {
		if match(r) {
			cands = append(cands, cloneServer(r.Server))
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Hostname < cands[j].Hostname })

	if len(cands) == 1 {
		return &cands[0], nil, nil
	}
	return nil, cands, nil
}

// List returns servers, optionally filtered by DC, ordered by (dc, hostname).
func (m *Memory) List(_ context.Context, dc string) ([]store.Server, error) {
	var out []store.Server
	for _, r := range m.filtered(dc) {
		out = append(out, cloneServer(r.Server))
	}
	return out, nil
}

// ListInventory returns the listing view — merged addresses plus the node-agent
// heartbeat — derived from the same rows ListWithStatus serves.
func (m *Memory) ListInventory(_ context.Context, dc string) ([]store.InventoryRow, error) {
	var out []store.InventoryRow
	for _, r := range m.filtered(dc) {
		row := cloneWithStatus(r).InventoryRow()
		out = append(out, row)
	}
	return out, nil
}

// ListWithStatus returns inventory rows with their last captured runtime status.
func (m *Memory) ListWithStatus(_ context.Context, dc string) ([]store.ServerWithStatus, error) {
	var out []store.ServerWithStatus
	for _, r := range m.filtered(dc) {
		out = append(out, cloneWithStatus(r))
	}
	return out, nil
}

// filtered applies the DC filter and returns rows in (dc, hostname) order. The
// snapshot is already sorted that way, so this only filters.
func (m *Memory) filtered(dc string) []store.ServerWithStatus {
	rows := m.rows()
	if dc == "" {
		return rows
	}
	var out []store.ServerWithStatus
	for _, r := range rows {
		if r.DC == dc {
			out = append(out, r)
		}
	}
	return out
}

// rowHasIP reports whether a host answers on ip, across the three address sets
// Resolve's IP branch searches: the primary column, operator-curated extra_ips,
// and the agent's observed_ips. Addresses are compared as parsed IPs, matching
// Postgres inet equality rather than text equality — so 192.0.2.1 and
// 192.000.002.001 resolve to the same host in both paths.
func rowHasIP(r store.ServerWithStatus, ip net.IP) bool {
	if p := net.ParseIP(r.IP); p != nil && p.Equal(ip) {
		return true
	}
	if containsIP(r.ExtraIPs, ip) {
		return true
	}
	return r.Status != nil && containsIP(r.Status.ObservedIPs, ip)
}

func containsIP(list []string, ip net.IP) bool {
	for _, s := range list {
		if p := net.ParseIP(s); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

// likeContains compiles the equivalent of Postgres `hostname ILIKE '%'||q||'%'`.
//
// The wildcards matter: the query is interpolated into a LIKE pattern, so a
// hostname fragment containing `_` or `%` is a wildcard server-side. Emulating
// that keeps an offline lookup from silently finding fewer hosts than the same
// lookup did online — `vctl ssh sre_srv` must not resolve one way on a good day
// and another way during an outage.
func likeContains(q string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)") // ILIKE
	for _, r := range q {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	// An invalid pattern is impossible: every rune is either a fixed
	// metacharacter or quoted. Fall back to a never-matching regexp rather than
	// panicking if that ever stops being true.
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(`$^`)
	}
	return re
}

// cloneServer copies a server and its slices so a caller mutating the result
// cannot reach into the snapshot. The database path hands out fresh values on
// every query; the cache path has to do the same or the two diverge under any
// caller that sorts or appends in place.
func cloneServer(s store.Server) store.Server {
	out := s
	out.ExtraIPs = cloneStrings(s.ExtraIPs)
	if s.LastSeenUp != nil {
		t := *s.LastSeenUp
		out.LastSeenUp = &t
	}
	return out
}

func cloneWithStatus(r store.ServerWithStatus) store.ServerWithStatus {
	out := store.ServerWithStatus{Server: cloneServer(r.Server)}
	if r.Status != nil {
		st := *r.Status
		st.ObservedIPs = cloneStrings(r.Status.ObservedIPs)
		st.Load1 = cloneFloat(r.Status.Load1)
		st.MemoryUsedPct = cloneFloat(r.Status.MemoryUsedPct)
		st.DiskRootUsedPct = cloneFloat(r.Status.DiskRootUsedPct)
		out.Status = &st
	}
	return out
}

// cloneStrings copies a slice while preserving whether it was nil or merely
// empty.
//
// The distinction is not academic here. The inventory queries wrap every address
// column in coalesce(..., ARRAY[]::text[]), so Postgres always hands back an
// empty non-nil slice for a host with no extra addresses. `append([]string(nil),
// empty...)` returns nil instead, which JSON renders as `null` where the live
// reader renders `[]` — a difference visible to anything serializing a host, the
// MCP tools included. A differential run against a real database caught it.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneFloat(v *float64) *float64 {
	if v == nil {
		return nil
	}
	f := *v
	return &f
}
