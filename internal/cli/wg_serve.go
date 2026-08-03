package cli

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

//go:embed wg_serve.html
var wgServeHTML []byte

// --- topology (built once from the DB at startup) ---

// wgIface is one WireGuard interface on a gateway (name + listen port), used to
// draw per-tunnel ports on the gateway box.
type wgIface struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// wgNode is one vertex in the dashboard graph: a collected gateway interface's
// host, or an external (uncollected) peer endpoint.
type wgNode struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Kind     string    `json:"kind"`         // gateway | vm | physical-host | device | external
	DC       string    `json:"dc"`           // datacenter/site of the gateway host; "" for external peers
	IP       string    `json:"ip,omitempty"` // gateway primary IP (from servers.ip)
	TunnelIP string    `json:"tunnelIp,omitempty"`
	Observed string    `json:"observed,omitempty"` // observed UDP endpoint; never implies physical placement
	Parent   string    `json:"parent,omitempty"`   // physical inventory host for a VM endpoint
	Warnings []string  `json:"warnings,omitempty"`
	Ifaces   []wgIface `json:"ifaces,omitempty"` // gateway interfaces, name-sorted
}

// wgEdge is one tunnel: a peer entry, resolved to the far-end gateway when both
// ends were collected.
type wgEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`

	// Iface and Allowed describe the source side only. They stay because the
	// layout groups tunnels by the gateway's own interface name, which is a
	// property of that end. What they are not is a property of the tunnel — see
	// A and B.
	Iface   string `json:"iface"`
	Allowed string `json:"allowed"`

	// A and B are the two ends, when both were collected. AllowedIPs in
	// particular are per-direction routes: what A accepts from B is a different
	// fact from what B accepts from A, and collapsing them into one string loses
	// whichever end was seen second.
	A *wgEdgeSide `json:"a,omitempty"`
	B *wgEdgeSide `json:"b,omitempty"`

	// TargetSeenAs lists the hostnames the far end was observed under when there
	// is more than one — a VIP arrangement, usually. Present so the page can say
	// "observed through" instead of silently picking a name.
	TargetSeenAs []string `json:"targetSeenAs,omitempty"`

	// Conflict marks a key whose observations disagree on interface settings,
	// meaning two machines are presenting one identity. Not set for the same
	// machine seen under several names — that is TargetSeenAs.
	Conflict bool `json:"conflict,omitempty"`
}

// wgEdgeSide is one end of a tunnel as that end reported it.
type wgEdgeSide struct {
	Host    string `json:"host"`
	Iface   string `json:"iface"`
	PubKey  string `json:"pub,omitempty"`
	Allowed string `json:"allowed,omitempty"`
}

// tunnelEdgeID identifies a tunnel by its pair of public keys, sorted so both
// ends compute the same id.
//
// A missing local key (the interface row was not collected) still yields a
// stable id from the peer key alone; it just cannot collapse with the far side.
func tunnelEdgeID(localKey, peerKey string) string {
	a, c := localKey, peerKey
	if a > c {
		a, c = c, a
	}
	return "gw|" + shortKey(a) + "|" + shortKey(c)
}

// wgAgg is a set of non-gateway inventory hosts in one dc collapsed by their
// primary-IP /24, so the dashboard can show "the rest of the site" without
// hardcoding hosts. Only dcs that own at least one WG gateway are emitted.
type wgAgg struct {
	ID    string `json:"id"`
	DC    string `json:"dc"`
	CIDR  string `json:"cidr"`
	Count int    `json:"count"`
}

// wgLink is a physical/management adjacency derived from servers.jump_via,
// resolved so both ends are a gateway hostname or an aggregate node id.
type wgLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"` // management | placement | network
}

// wgVip is an operator-recorded virtual IP from the IPAM ledger (kind=dnat-vip):
// not WireGuard state, but part of the tunnel picture (e.g. sre-lb's o11y DNAT
// addresses riding wg1/wg3). The renderer attaches it to the matching endpoint.
type wgVip struct {
	IP    string `json:"ip"`
	Label string `json:"label"`
	Iface string `json:"iface,omitempty"`
	Note  string `json:"note,omitempty"`
}

type wgTopology struct {
	Nodes []wgNode `json:"nodes"`
	Edges []wgEdge `json:"edges"`
	Aggs  []wgAgg  `json:"aggs"`
	Links []wgLink `json:"links"`
	Vips  []wgVip  `json:"vips,omitempty"`

	// CollectedAt is when `vctl wg sync` last wrote the rows this graph is drawn
	// from — not when the page rendered, and not when live polling last ran.
	//
	// In practice the two are far apart and that gap is the reason to show it.
	// Node and tunnel structure, AllowedIPs, endpoints and peer membership all
	// come from this snapshot; only traffic and handshake come from live SSH
	// polling. A fleet whose last sync was six days ago still animates traffic
	// every two seconds, and without this the page reads as current in every
	// respect. It was six days stale when this field was added.
	//
	// Zero means there are no WireGuard rows at all, which the page reports as
	// "never collected" rather than as 1970.
	CollectedAt time.Time `json:"collectedAt"`
}

// topologyCollectedAt is the newest collection timestamp across the interfaces
// this graph was built from.
//
// Newest, not oldest: gateways are collected one after another and a host that
// failed its last sync keeps an older row, so the oldest would report the worst
// gateway's staleness rather than the snapshot's. What this answers is "how long
// ago was anything learned at all". Per-gateway staleness is a different signal
// and this deliberately does not fold the two together.
func topologyCollectedAt(ifaces []store.WGInterfaceRow) time.Time {
	var newest time.Time
	for _, i := range ifaces {
		if i.CollectedAt.After(newest) {
			newest = i.CollectedAt
		}
	}
	return newest
}

// edgeStat is the live per-tunnel measurement pushed to browsers.
type edgeStat struct {
	RxPS float64 `json:"rx"` // bytes/sec toward the source gateway
	TxPS float64 `json:"tx"` // bytes/sec away from the source gateway
	HS   int64   `json:"hs"` // seconds since last handshake, -1 = never

	// Sides holds each gateway's own view, keyed by hostname.
	//
	// Both ends of a tunnel are polled, and each reports counters from its own
	// perspective: A's tx is the same bytes as B's rx. Writing both into one
	// rx/tx pair meant the later poll won and the arrow could reverse between
	// frames with no traffic change at all.
	//
	// The flat RxPS/TxPS above stay as the source side's view, because that is
	// what the page draws and what "toward the source gateway" has always meant.
	// Sides is what makes the other end visible, and what lets a reader check
	// A.tx against B.rx.
	Sides map[string]edgeSideStat `json:"sides,omitempty"`
}

// edgeSideStat is one gateway's measurement of a tunnel.
type edgeSideStat struct {
	RxPS float64 `json:"rx"`
	TxPS float64 `json:"tx"`
	HS   int64   `json:"hs"`
	At   int64   `json:"at"` // unix seconds of the poll this came from
}

// cidr24 masks an IPv4 address to its /24 network ("10.20.0.33" → "10.20.0.0/24").
func cidr24(ip string) (string, bool) {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return "", false
	}
	v4 := p.To4()
	if v4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2]), true
}

// buildWGTopology turns the collected interfaces/peers plus the server inventory
// into the dashboard graph. Peers whose public key matches another collected
// interface become a single gateway↔gateway edge (canonical side = lexically
// smaller host); the rest hang off their gateway as external nodes. Gateway
// nodes carry their dc/ip and interface list. Non-gateway hosts in any dc that
// owns a gateway are collapsed into per-/24 aggregate nodes, and servers.jump_via
// yields management links between gateways/aggregates. It also returns the
// sample→edge mapping the pollers use to attribute live rates.
//
// The build runs in phases, each adding one layer of the graph and depending
// only on the indices and on what earlier phases put in topo. Written as one
// function it was 286 lines with five comment-separated sections and five
// closures over shared state — the closures are methods here, which is what
// they were reaching for.
func buildWGTopology(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, servers []store.Server, annotations []store.WGEndpointAnnotation) (wgTopology, map[tunnelKey]string) {
	b := newWGTopologyBuilder(ifaces, peers, servers, annotations)
	b.addGateways()
	b.addPeerEdges()
	b.addAggregates()
	b.addLinks()
	b.topo.CollectedAt = topologyCollectedAt(ifaces)
	return b.topo, b.edgeFor
}

// wgTopologyBuilder holds the lookups every phase needs plus the graph being
// assembled. Phases run in order and are not independent: peer edges need the
// gateway nodes, aggregates need every node placed so far, and links need the
// aggregate membership.
type wgTopologyBuilder struct {
	ifaces  []store.WGInterfaceRow
	peers   []store.WGPeerRow
	servers []store.Server

	endpoints  endpointIndex                         // public key → canonical gateway, aliases, conflicts
	byHost     map[string]store.Server               // inventory by hostname
	byIP       map[string]store.Server               // inventory by any address it answers on
	annByKey   map[string]store.WGEndpointAnnotation // annotation by peer/interface public key
	annByHost  map[string]store.WGEndpointAnnotation // the winning annotation per gateway
	warnings   map[string][]string                   // per-gateway annotation conflicts
	endpointIP map[string]int                        // endpoint IP → how many peers claim it
	ifByHost   map[string][]wgIface                  // gateway → its interfaces, name-sorted
	gwHosts    map[string]bool                       // hosts that own at least one interface

	topo      wgTopology
	nodeSeen  map[string]bool
	edgeFor   map[tunnelKey]string
	aggOfHost map[string]string // hostname → aggregate node id, for link resolution
}

// newWGTopologyBuilder builds every index the phases read. Nothing here touches
// the output graph.
func newWGTopologyBuilder(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, servers []store.Server, annotations []store.WGEndpointAnnotation) *wgTopologyBuilder {
	b := &wgTopologyBuilder{
		ifaces: ifaces, peers: peers, servers: servers,
		endpoints:  buildEndpointIndex(ifaces),
		byHost:     make(map[string]store.Server, len(servers)),
		byIP:       make(map[string]store.Server, len(servers)),
		annByKey:   make(map[string]store.WGEndpointAnnotation, len(annotations)),
		annByHost:  map[string]store.WGEndpointAnnotation{},
		warnings:   map[string][]string{},
		endpointIP: map[string]int{},
		ifByHost:   map[string][]wgIface{},
		gwHosts:    map[string]bool{},
		nodeSeen:   map[string]bool{},
		edgeFor:    map[tunnelKey]string{},
		aggOfHost:  map[string]string{},
	}
	for _, s := range servers {
		b.byHost[s.Hostname] = s
		b.byIP[s.IP] = s
		for _, ip := range s.ExtraIPs {
			b.byIP[ip] = s
		}
	}
	for _, a := range annotations {
		b.annByKey[a.PublicKey] = a
	}
	for _, p := range peers {
		if ip := wgEndpointIP(p.Endpoint); ip != "" {
			b.endpointIP[ip]++
		}
	}
	for _, i := range ifaces {
		b.gwHosts[i.Host] = true
		b.ifByHost[i.Host] = append(b.ifByHost[i.Host], wgIface{Name: i.Iface, Port: i.ListenPort})
	}
	// Name-sorted so the dashboard's port order is stable across polls.
	for h := range b.ifByHost {
		sort.Slice(b.ifByHost[h], func(x, y int) bool { return b.ifByHost[h][x].Name < b.ifByHost[h][y].Name })
	}
	b.resolveAnnotations()
	return b
}

// resolveAnnotations picks one annotation per gateway. A host may own several
// WG interfaces, each separately annotated, so the most specific placement wins
// and any disagreement between them is surfaced as a warning rather than
// silently dropped.
func (b *wgTopologyBuilder) resolveAnnotations() {
	sortedIfaces := append([]store.WGInterfaceRow{}, b.ifaces...)
	sort.Slice(sortedIfaces, func(i, j int) bool {
		if sortedIfaces[i].Host != sortedIfaces[j].Host {
			return sortedIfaces[i].Host < sortedIfaces[j].Host
		}
		return sortedIfaces[i].Iface < sortedIfaces[j].Iface
	})
	candidatesByHost := map[string][]store.WGEndpointAnnotation{}
	for _, i := range sortedIfaces {
		if a, ok := b.annByKey[i.PublicKey]; ok {
			candidatesByHost[i.Host] = append(candidatesByHost[i.Host], a)
		}
	}
	for host, candidates := range candidatesByHost {
		selected := candidates[0]
		for _, candidate := range candidates[1:] {
			if wgAnnotationSpecificity(candidate) > wgAnnotationSpecificity(selected) {
				selected = candidate
			}
		}
		for _, candidate := range candidates {
			if wgAnnotationPlacementConflict(selected, candidate) {
				b.warnings[host] = []string{
					"conflicting endpoint annotations across WG interfaces; using the most specific placement",
				}
				break
			}
		}
		// Tunnel addresses are interface state, not one host-level scalar.
		selected.TunnelIP = ""
		b.annByHost[host] = selected
	}
}

func (b *wgTopologyBuilder) dcOf(host string) string { return b.byHost[host].DC }

// addNode appends a node once. Phases overlap on the same node ids, so
// first-write-wins is the rule that keeps the graph stable.
func (b *wgTopologyBuilder) addNode(n wgNode) {
	if !b.nodeSeen[n.ID] {
		b.nodeSeen[n.ID] = true
		b.topo.Nodes = append(b.topo.Nodes, n)
	}
}

func (b *wgTopologyBuilder) addPhysicalHost(parent store.Server) string {
	id := physicalHostNodeID(parent.Hostname)
	b.addNode(wgNode{
		ID: id, Label: parent.Hostname, Kind: "physical-host",
		DC: parent.DC, IP: parent.IP,
	})
	return id
}

// enrichEndpoint layers an operator annotation over a discovered node. The
// annotation wins over what was observed, and inventory fills the gaps.
func (b *wgTopologyBuilder) enrichEndpoint(n wgNode, a store.WGEndpointAnnotation) wgNode {
	if inv, ok := b.byHost[a.InventoryHost]; ok {
		n.Label = firstNonEmpty(a.Label, inv.Hostname, n.Label)
		n.IP = firstNonEmpty(a.UnderlayIP, inv.IP, n.IP)
		n.DC = firstNonEmpty(a.Site, inv.DC, n.DC)
	} else {
		n.Label = firstNonEmpty(a.Label, n.Label)
		n.IP = firstNonEmpty(a.UnderlayIP, n.IP)
		n.DC = firstNonEmpty(a.Site, n.DC)
	}
	n.Kind = firstNonEmpty(a.Kind, n.Kind)
	n.TunnelIP = a.TunnelIP
	if parent, ok := b.byHost[a.ParentHostname]; ok {
		n.Parent = b.addPhysicalHost(parent)
		n.DC = parent.DC
	}
	return n
}

// addGateways places one node per host that owns a WG interface.
func (b *wgTopologyBuilder) addGateways() {
	hosts := make([]string, 0, len(b.gwHosts))
	for host := range b.gwHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		n := wgNode{
			ID: host, Label: host, Kind: "gateway",
			DC: b.dcOf(host), IP: b.byHost[host].IP,
			Warnings: b.warnings[host], Ifaces: b.ifByHost[host],
		}
		if a, ok := b.annByHost[host]; ok {
			n = b.enrichEndpoint(n, a)
		}
		b.addNode(n)
	}
}

// addPeerEdges walks the collected peers. A peer whose key belongs to another
// collected interface is one gateway↔gateway tunnel; everything else becomes an
// external node hanging off its gateway. Either way the tunnel is mapped into
// edgeFor so the pollers can attribute live rates to the right edge.
// localPubKey is the public key of the interface a peer row was collected on.
// Empty when that interface was not collected, which tunnelEdgeID tolerates.
func (b *wgTopologyBuilder) localPubKey(host, iface string) string {
	for _, i := range b.ifaces {
		if i.Host == host && i.Iface == iface {
			return i.PublicKey
		}
	}
	return ""
}

// fillEdgeSide records the second end of a tunnel the far side already emitted.
// Both ends' interface names and routes belong to the edge; only the first one
// seen used to survive.
func (b *wgTopologyBuilder) fillEdgeSide(id string, p store.WGPeerRow, localKey string) {
	for i := range b.topo.Edges {
		e := &b.topo.Edges[i]
		if e.ID != id {
			continue
		}
		side := &wgEdgeSide{
			Host: p.Host, Iface: p.Iface, PubKey: localKey,
			Allowed: strings.Join(p.AllowedIPs, ", "),
		}
		if e.A != nil && e.A.Host == p.Host && e.A.Iface == p.Iface {
			return // the same side reported twice; nothing new
		}
		if e.B == nil {
			e.B = side
		}
		return
	}
}

func (b *wgTopologyBuilder) addPeerEdges() {
	edgeSeen := map[string]bool{}
	sorted := append([]store.WGPeerRow{}, b.peers...)
	sort.Slice(sorted, func(x, y int) bool {
		if sorted[x].Host != sorted[y].Host {
			return sorted[x].Host < sorted[y].Host
		}
		if sorted[x].Iface != sorted[y].Iface {
			return sorted[x].Iface < sorted[y].Iface
		}
		return sorted[x].PeerPubKey < sorted[y].PeerPubKey
	})
	for _, p := range sorted {
		k := tunnelKey{p.Host, p.Iface, p.PeerPubKey}
		if far, ok := b.endpoints.lookup(p.PeerPubKey); ok {
			// A tunnel is identified by the pair of public keys, not by an
			// interface name.
			//
			// The id used to be host|host|iface, taken from whichever side was
			// being processed. Interface names are chosen per host and often
			// differ across one tunnel — in this fleet 7 tunnels are wg3 on one
			// end and wg0 on the other — so one tunnel produced two ids and was
			// drawn twice, each copy carrying one direction's traffic. Where the
			// names happened to match, the opposite happened: both sides landed
			// on one id and the later poll overwrote the earlier one.
			//
			// Keys are what WireGuard actually negotiates on, so sorting the pair
			// gives both ends the same answer regardless of scan order.
			localKey := b.localPubKey(p.Host, p.Iface)
			id := tunnelEdgeID(localKey, p.PeerPubKey)
			b.edgeFor[k] = id
			if edgeSeen[id] {
				// The far side already emitted this tunnel. Fill in this side's
				// interface and routes rather than dropping them: AllowedIPs are
				// per-direction, so the two ends are different facts about one
				// tunnel, not a repeat of the same one.
				b.fillEdgeSide(id, p, localKey)
				continue
			}
			edgeSeen[id] = true
			e := wgEdge{
				ID: id, Source: p.Host, Target: far.host,
				Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
				A: &wgEdgeSide{
					Host: p.Host, Iface: p.Iface, PubKey: localKey,
					Allowed: strings.Join(p.AllowedIPs, ", "),
				},
			}
			if hosts := b.endpoints.observedThrough(p.PeerPubKey); len(hosts) > 1 {
				e.TargetSeenAs = hosts
			}
			if b.endpoints.conflicts[p.PeerPubKey] || b.endpoints.conflicts[localKey] {
				e.Conflict = true
			}
			b.topo.Edges = append(b.topo.Edges, e)
			continue
		}
		n := b.externalNode(p)
		b.addNode(n)
		id := p.Host + "|" + p.Iface + "|" + shortKey(p.PeerPubKey)
		b.edgeFor[k] = id
		b.topo.Edges = append(b.topo.Edges, wgEdge{
			ID: id, Source: p.Host, Target: n.ID,
			Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
		})
	}
}

// externalNode identifies the far end of an unresolved peer, in increasing
// order of confidence: an opaque key, then an inventory host guessed from a
// unique endpoint address, then whatever an operator annotated.
func (b *wgTopologyBuilder) externalNode(p store.WGPeerRow) wgNode {
	label := p.Endpoint
	if label == "" {
		label = shortKey(p.PeerPubKey)
	}
	n := wgNode{ID: "ext|" + shortKey(p.PeerPubKey), Label: label, Kind: "external"}

	// Only guess when exactly one peer claims the address; a shared NAT
	// endpoint says nothing about which host is behind it.
	if ip := wgEndpointIP(p.Endpoint); ip != "" {
		if sv, ok := b.byIP[ip]; ok && b.endpointIP[ip] == 1 {
			n.ID = "inventory|" + sv.Hostname
			n.Label = sv.Hostname + " ?"
			n.Kind = "inventory-candidate"
			n.Observed = p.Endpoint
		}
	}
	if a, ok := b.annByKey[p.PeerPubKey]; ok {
		n.ID = "endpoint|" + p.PeerPubKey
		n = b.enrichEndpoint(n, a)
	}
	return n
}

// addAggregates collapses non-gateway hosts into one node per (dc, /24), and
// only in dcs that own a gateway — elsewhere the aggregate would have nothing
// to attach to.
func (b *wgTopologyBuilder) addAggregates() {
	dcWithGW := map[string]bool{}
	for h := range b.gwHosts {
		dcWithGW[b.dcOf(h)] = true
	}
	byKey := map[string]*wgAgg{}
	members := map[string]map[string]bool{}
	add := func(dc, cidr, member string) string {
		id := "agg|" + dc + "|" + cidr
		a := byKey[id]
		if a == nil {
			a = &wgAgg{ID: id, DC: dc, CIDR: cidr}
			byKey[id] = a
		}
		if members[id] == nil {
			members[id] = map[string]bool{}
		}
		if member != "" && !members[id][member] {
			members[id][member] = true
			a.Count++
		}
		return id
	}
	for _, s := range b.servers {
		if !dcWithGW[s.DC] {
			continue
		}
		if cidr, ok := cidr24(s.IP); ok {
			b.aggOfHost[s.Hostname] = add(s.DC, cidr, s.Hostname)
		}
	}
	for _, n := range b.topo.Nodes {
		if n.Kind == "external" || n.DC == "" {
			continue
		}
		if cidr, ok := cidr24(n.IP); ok {
			member := strings.TrimPrefix(n.ID, "inventory|")
			add(n.DC, cidr, member)
		}
	}
	for _, a := range byKey {
		b.topo.Aggs = append(b.topo.Aggs, *a)
	}
	sort.Slice(b.topo.Aggs, func(x, y int) bool { return b.topo.Aggs[x].ID < b.topo.Aggs[y].ID })
}

// addLinks draws the non-tunnel relationships: management paths from
// servers.jump_via, placement onto a physical host, and membership of a /24.
func (b *wgTopologyBuilder) addLinks() {
	// Each end resolves to a gateway hostname or the aggregate the host sits in;
	// anything unresolved, or pointing at itself, is dropped.
	resolve := func(host string) (string, bool) {
		if b.gwHosts[host] {
			return host, true
		}
		id, ok := b.aggOfHost[host]
		return id, ok
	}
	seen := map[string]bool{}
	for _, s := range b.servers {
		if s.JumpVia == "" {
			continue
		}
		src, srcOK := resolve(s.Hostname)
		dst, dstOK := resolve(s.JumpVia)
		if !srcOK || !dstOK || src == dst {
			continue
		}
		key := src + "\x00" + dst
		if seen[key] {
			continue
		}
		seen[key] = true
		b.topo.Links = append(b.topo.Links, wgLink{Source: src, Target: dst, Kind: "management"})
	}
	for _, n := range b.topo.Nodes {
		if n.Kind == "external" {
			continue
		}
		if n.Parent != "" {
			b.topo.Links = append(b.topo.Links, wgLink{Source: n.ID, Target: n.Parent, Kind: "placement"})
		}
		if cidr, ok := cidr24(n.IP); ok {
			b.topo.Links = append(b.topo.Links, wgLink{
				Source: n.ID, Target: "agg|" + n.DC + "|" + cidr, Kind: "network",
			})
		}
	}
	sort.Slice(b.topo.Links, func(x, y int) bool {
		if b.topo.Links[x].Source != b.topo.Links[y].Source {
			return b.topo.Links[x].Source < b.topo.Links[y].Source
		}
		return b.topo.Links[x].Target < b.topo.Links[y].Target
	})
}

func physicalHostNodeID(hostname string) string { return "host|" + hostname }

func wgAnnotationSpecificity(a store.WGEndpointAnnotation) int {
	score := 0
	if a.ParentHostname != "" {
		score += 16
	}
	if a.InventoryHost != "" {
		score += 8
	}
	if a.UnderlayIP != "" {
		score += 4
	}
	if a.Site != "" {
		score += 2
	}
	if a.Label != "" {
		score++
	}
	return score
}

func wgAnnotationPlacementConflict(a, b store.WGEndpointAnnotation) bool {
	different := func(x, y string) bool { return x != "" && y != "" && x != y }
	return different(a.Label, b.Label) ||
		different(a.Kind, b.Kind) ||
		different(a.UnderlayIP, b.UnderlayIP) ||
		different(a.Site, b.Site) ||
		different(a.InventoryHost, b.InventoryHost) ||
		different(a.ParentHostname, b.ParentHostname)
}

func wgEndpointIP(endpoint string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(endpoint) != nil {
		return endpoint
	}
	return ""
}

// --- live state shared between pollers and SSE clients ---

type wgServeState struct {
	mu    sync.Mutex
	prev  map[tunnelKey]wgSample
	stats map[string]edgeStat // edge ID -> latest
	errs  map[string]string   // gateway -> poll error
}

func newWGServeState() *wgServeState {
	return &wgServeState{prev: map[tunnelKey]wgSample{}, stats: map[string]edgeStat{}, errs: map[string]string{}}
}

func (s *wgServeState) record(host string, peers []wgParsedPeer, at time.Time, edgeFor map[tunnelKey]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.errs, host)
	for _, p := range peers {
		k := tunnelKey{host, p.Iface, p.PubKey}
		id, ok := edgeFor[k]
		if !ok {
			continue // peer appeared after topology snapshot; ignore until re-serve
		}
		var hs *time.Time
		if p.Handshake > 0 {
			t := time.Unix(p.Handshake, 0)
			hs = &t
		}
		cur := wgSample{rx: p.Rx, tx: p.Tx, hs: hs, at: at}
		side := edgeSideStat{HS: -1, At: at.Unix()}
		if hs != nil {
			side.HS = int64(time.Since(*hs).Seconds())
		}
		if old, ok := s.prev[k]; ok {
			side.RxPS, side.TxPS = computeRate(old, cur)
		}
		s.prev[k] = cur

		// Merge into the tunnel rather than replacing it. Both gateways poll the
		// same tunnel and report counters from their own perspective, so a plain
		// assignment let whichever polled later erase the other end — and since
		// A's tx is B's rx, the drawn direction flipped with poll timing rather
		// than with traffic.
		st := s.stats[id]
		if st.Sides == nil {
			st.Sides = map[string]edgeSideStat{}
		}
		st.Sides[host] = side
		st.RxPS, st.TxPS, st.HS = flattenSides(st.Sides)
		s.stats[id] = st
	}
}

// flattenSides reduces both ends to the single rx/tx/handshake the page draws.
//
// Rates take the larger of the two sides. The ends measure the same bytes from
// opposite directions and neither is more correct, but a side that has not been
// polled yet reports zero, and taking that would show an idle tunnel as dead.
//
// Handshake takes the smaller — the most recent. A handshake is a property of
// the tunnel, not of the observer, so the fresher observation is simply the
// better-informed one. -1 means never, which loses to any real value.
func flattenSides(sides map[string]edgeSideStat) (rx, tx float64, hs int64) {
	hs = -1
	for _, s := range sides {
		rx = max(rx, s.RxPS)
		tx = max(tx, s.TxPS)
		if s.HS >= 0 && (hs < 0 || s.HS < hs) {
			hs = s.HS
		}
	}
	return rx, tx, hs
}

func (s *wgServeState) fail(host string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[host] = err.Error()
}

// snapshotJSON renders the current stats/errors as one SSE payload.
func (s *wgServeState) snapshotJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"edges": s.stats, "errors": s.errs, "at": time.Now().Unix()})
	return b
}

// --- command ---

func wgServeCmd() *cobra.Command {
	var (
		addr        string
		intervalSec int
		timeoutSec  int
	)
	cmd := &cobra.Command{
		Use:   "serve [host...]",
		Short: "Web dashboard with live animated traffic flow over the WG topology",
		Long: `serve starts a local web dashboard: the collected WireGuard topology drawn
as a graph, with per-tunnel traffic animated as flowing packets (speed and
density follow live rx/tx rates polled over SSH). The topology comes from the
DB (run 'vctl wg sync' first); rates are read live and never written back.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
			if err != nil {
				return err
			}
			defer st.Close()

			ifaces, err := st.WGInterfaces(ctx)
			if err != nil {
				return err
			}
			peers, err := st.WGPeers(ctx)
			if err != nil {
				return err
			}
			if len(ifaces) == 0 {
				return fmt.Errorf("no WireGuard data. Run 'vctl wg sync' first.")
			}
			servers, err := st.List(ctx, "")
			if err != nil {
				ui.Warnf(os.Stderr, "list servers for site grouping: %v", err)
			}
			annotations, err := st.WGEndpointAnnotations(ctx)
			if err != nil {
				ui.Warnf(os.Stderr, "list endpoint annotations (run vctl sync --migrate): %v", err)
			}
			topo, edgeFor := buildWGTopology(ifaces, peers, servers, annotations)
			if vips, err := st.IPAllocList(ctx, "dnat-vip", "", ""); err == nil {
				for _, v := range vips {
					note := strings.TrimSpace(strings.TrimSpace(v.OS) + " " + strings.TrimSpace(v.Note))
					topo.Vips = append(topo.Vips, wgVip{IP: v.IP, Label: v.Label, Iface: v.WGTunnel, Note: note})
				}
			}

			hosts, err := wgMonitorHosts(ctx, st, args, false)
			if err != nil {
				return err
			}
			targets := make([]monTarget, 0, len(hosts))
			for i := range hosts {
				tgt, err := access.BuildTarget(ctx, st, &hosts[i], a.Cfg.SSHDirectFirst)
				if err != nil {
					ui.Warnf(os.Stderr, "%s: %v", hosts[i].Hostname, err)
					continue
				}
				targets = append(targets, monTarget{name: hosts[i].Hostname, tgt: tgt})
			}
			if len(targets) == 0 {
				return fmt.Errorf("no reachable gateways to poll")
			}

			// Polling telemetry, not access: Monitor records the first poll per
			// gateway and every change of outcome after that, instead of a row
			// every 2s. See access.Monitor.
			mon := newConnector(a).Monitor()
			state := newWGServeState()
			interval := time.Duration(intervalSec) * time.Second
			timeout := time.Duration(timeoutSec) * time.Second

			pollCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			for _, t := range targets {
				go func(t monTarget) {
					for {
						res, err := mon.Poll(pollCtx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wgDumpCmd, timeout)
						if err != nil {
							state.fail(t.name, err)
						} else {
							_, ps := parseWGDump(res.Stdout)
							state.record(t.name, ps, time.Now(), edgeFor)
						}
						select {
						case <-pollCtx.Done():
							return
						case <-time.After(interval):
						}
					}
				}(t)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(wgServeHTML)
			})
			mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(topo)
			})
			mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
				fl, ok := w.(http.Flusher)
				if !ok {
					http.Error(w, "streaming unsupported", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				tick := time.NewTicker(interval)
				defer tick.Stop()
				for {
					fmt.Fprintf(w, "data: %s\n\n", state.snapshotJSON())
					fl.Flush()
					select {
					case <-r.Context().Done():
						return
					case <-pollCtx.Done():
						return
					case <-tick.C:
					}
				}
			})

			srv := &http.Server{Addr: addr, Handler: mux}
			go func() {
				<-ctx.Done()
				shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
				defer c()
				srv.Shutdown(shutdownCtx)
			}()
			ui.Successf(os.Stderr, "wg dashboard: http://%s  (%d gateways, every %s; Ctrl-C to stop)",
				displayAddr(addr), len(targets), interval)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8420", "listen address")
	cmd.Flags().IntVar(&intervalSec, "interval", 2, "poll interval (seconds)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "per-poll SSH timeout (seconds)")
	return gate(cmd, "wg", classRead)
}

// displayAddr turns a bind address into a clickable one (":8420" → "127.0.0.1:8420").
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
