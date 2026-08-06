// Package wireguard models the WireGuard overlay: which endpoints exist, which
// of them are the same machine under different names, what tunnels run between
// them, and how much of that a collection actually established.
//
// It is separate from the things that draw it. There are three of those — the
// terminal graph, the Mermaid export, and the browser dashboard — and each one
// used to reach into the same file that built the model. The dashboard reaches
// further than that: it re-derives structure in JavaScript, so "why is this
// node in the wrong place" could be a question about the model or about the
// page, with no seam to ask it at.
//
// Nothing here renders. No colours, no widths, no terminal, no HTML.
package wireguard

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
)

// --- topology (built once from the DB at startup) ---

// Iface is one WireGuard interface on a gateway (name + listen port), used to
// draw per-tunnel ports on the gateway box.
type Iface struct {
	Name string `json:"name"`
	Port int    `json:"port"`

	// PubKey is this interface's own key. A gateway has one per interface, not
	// one per host: sre-lb runs wg1 and wg-personal with different keys, and a
	// single key on the node meant whichever sorted first was the only one a VIP
	// could be matched against.
	PubKey string `json:"pub,omitempty"`
}

// Node is one vertex in the dashboard graph: a collected gateway interface's
// host, or an external (uncollected) peer endpoint.
type Node struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`         // gateway | vm | physical-host | device | external
	DC       string   `json:"dc"`           // datacenter/site of the gateway host; "" for external peers
	IP       string   `json:"ip,omitempty"` // gateway primary IP (from servers.ip)
	TunnelIP string   `json:"tunnelIp,omitempty"`
	Observed string   `json:"observed,omitempty"` // observed UDP endpoint; never implies physical placement
	Parent   string   `json:"parent,omitempty"`   // physical inventory host for a VM endpoint
	Warnings []string `json:"warnings,omitempty"`
	Ifaces   []Iface  `json:"ifaces,omitempty"` // gateway interfaces, name-sorted

	// PubKey is the endpoint's first interface key, kept for callers that want a
	// single identity for the node. It is not the whole story — a gateway has a
	// key per interface, and Ifaces carries all of them. Matching a VIP against
	// this alone missed every interface but the first.
	PubKey string `json:"pub,omitempty"`

	// SeenAs lists the hostnames this endpoint was observed under when there is
	// more than one, usually a VIP sharing a machine with its host. Present so
	// the page can name both instead of silently picking one.
	SeenAs []string `json:"seenAs,omitempty"`
}

// Edge is one tunnel: a peer entry, resolved to the far-end gateway when both
// ends were collected.
type Edge struct {
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
	A *EdgeSide `json:"a,omitempty"`
	B *EdgeSide `json:"b,omitempty"`

	// TargetSeenAs lists the hostnames the far end was observed under when there
	// is more than one — a VIP arrangement, usually. Present so the page can say
	// "observed through" instead of silently picking a name.
	TargetSeenAs []string `json:"targetSeenAs,omitempty"`

	// Conflict marks a key whose observations disagree on interface settings,
	// meaning two machines are presenting one identity. Not set for the same
	// machine seen under several names — that is TargetSeenAs.
	Conflict bool `json:"conflict,omitempty"`
}

// EdgeSide is one end of a tunnel as that end reported it.
type EdgeSide struct {
	Host    string `json:"host"`
	Iface   string `json:"iface"`
	PubKey  string `json:"pub,omitempty"`
	Allowed string `json:"allowed,omitempty"`
}

// TunnelEdgeID identifies a tunnel by its pair of public keys, sorted so both
// ends compute the same id.
//
// A missing local key (the interface row was not collected) still yields a
// stable id from the peer key alone; it just cannot collapse with the far side.
func TunnelEdgeID(localKey, peerKey string) string {
	a, c := localKey, peerKey
	if a > c {
		a, c = c, a
	}
	return "gw|" + ShortKey(a) + "|" + ShortKey(c)
}

// Agg is a set of non-gateway inventory hosts in one dc collapsed by their
// primary-IP /24, so the dashboard can show "the rest of the site" without
// hardcoding hosts. Only dcs that own at least one WG gateway are emitted.
type Agg struct {
	ID    string `json:"id"`
	DC    string `json:"dc"`
	CIDR  string `json:"cidr"`
	Count int    `json:"count"`
}

// Link is a physical/management adjacency derived from servers.jump_via,
// resolved so both ends are a gateway hostname or an aggregate node id.
type Link struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"` // management | placement | network
}

// Vip is an operator-recorded virtual IP from the IPAM ledger (kind=dnat-vip):
// not WireGuard state, but part of the tunnel picture (e.g. sre-lb's o11y DNAT
// addresses riding wg1/wg3). The renderer attaches it to the matching endpoint.
type Vip struct {
	IP    string `json:"ip"`
	Label string `json:"label"`
	Iface string `json:"iface,omitempty"`
	Note  string `json:"note,omitempty"`

	// Owner is the public key of the endpoint this address fronts, as recorded in
	// ip_allocations.owner_public_key.
	//
	// When it is set, the page attaches the VIP to that endpoint and says so.
	// When it is empty the page falls back to matching label text, which is what
	// it always did — and marks the result as a guess, because that is what it is.
	Owner string `json:"owner,omitempty"`
}

type Topology struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Aggs  []Agg  `json:"aggs"`
	Links []Link `json:"links"`
	Vips  []Vip  `json:"vips,omitempty"`

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

// CollectedAt is the newest collection timestamp across the interfaces
// this graph was built from.
//
// Newest, not oldest: gateways are collected one after another and a host that
// failed its last sync keeps an older row, so the oldest would report the worst
// gateway's staleness rather than the snapshot's. What this answers is "how long
// ago was anything learned at all". Per-gateway staleness is a different signal
// and this deliberately does not fold the two together.
func CollectedAt(ifaces []store.WGInterfaceRow) time.Time {
	var newest time.Time
	for _, i := range ifaces {
		if i.CollectedAt.After(newest) {
			newest = i.CollectedAt
		}
	}
	return newest
}

// EdgeStat is the live per-tunnel measurement pushed to browsers.
type EdgeStat struct {
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
	Sides map[string]EdgeSideStat `json:"sides,omitempty"`
}

// EdgeSideStat is one gateway's measurement of a tunnel.
type EdgeSideStat struct {
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

// Build turns the collected interfaces/peers plus the server inventory
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
func Build(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, servers []store.Server, annotations []store.WGEndpointAnnotation) (Topology, map[TunnelKey]string) {
	b := newBuilder(ifaces, peers, servers, annotations)
	b.addGateways()
	b.addPeerEdges()
	b.addAggregates()
	b.addLinks()
	b.topo.CollectedAt = CollectedAt(ifaces)
	return b.topo, b.edgeFor
}

// builder holds the lookups every phase needs plus the graph being
// assembled. Phases run in order and are not independent: peer edges need the
// gateway nodes, aggregates need every node placed so far, and links need the
// aggregate membership.
type builder struct {
	ifaces  []store.WGInterfaceRow
	peers   []store.WGPeerRow
	servers []store.Server

	endpoints  EndpointIndex                         // public key → canonical gateway, aliases, conflicts
	byHost     map[string]store.Server               // inventory by hostname
	byIP       map[string]store.Server               // inventory by any address it answers on
	annByKey   map[string]store.WGEndpointAnnotation // annotation by peer/interface public key
	annByHost  map[string]store.WGEndpointAnnotation // the winning annotation per gateway
	warnings   map[string][]string                   // per-gateway annotation conflicts
	endpointIP map[string]int                        // endpoint IP → how many peers claim it
	ifByHost   map[string][]Iface                    // gateway → its interfaces, name-sorted
	gwHosts    map[string]bool                       // hosts that own at least one interface

	topo      Topology
	nodeSeen  map[string]bool
	edgeFor   map[TunnelKey]string
	aggOfHost map[string]string // hostname → aggregate node id, for link resolution
}

// newBuilder builds every index the phases read. Nothing here touches
// the output graph.
func newBuilder(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, servers []store.Server, annotations []store.WGEndpointAnnotation) *builder {
	b := &builder{
		ifaces: ifaces, peers: peers, servers: servers,
		endpoints:  BuildEndpointIndex(ifaces),
		byHost:     make(map[string]store.Server, len(servers)),
		byIP:       make(map[string]store.Server, len(servers)),
		annByKey:   make(map[string]store.WGEndpointAnnotation, len(annotations)),
		annByHost:  map[string]store.WGEndpointAnnotation{},
		warnings:   map[string][]string{},
		endpointIP: map[string]int{},
		ifByHost:   map[string][]Iface{},
		gwHosts:    map[string]bool{},
		nodeSeen:   map[string]bool{},
		edgeFor:    map[TunnelKey]string{},
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
		if ip := EndpointIP(p.Endpoint); ip != "" {
			b.endpointIP[ip]++
		}
	}
	for _, i := range ifaces {
		b.gwHosts[i.Host] = true
		b.ifByHost[i.Host] = append(b.ifByHost[i.Host], Iface{Name: i.Iface, Port: i.ListenPort, PubKey: i.PublicKey})
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
func (b *builder) resolveAnnotations() {
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
			if AnnotationSpecificity(candidate) > AnnotationSpecificity(selected) {
				selected = candidate
			}
		}
		for _, candidate := range candidates {
			if AnnotationPlacementConflict(selected, candidate) {
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

func (b *builder) dcOf(host string) string { return b.byHost[host].DC }

// addNode appends a node once. Phases overlap on the same node ids, so
// first-write-wins is the rule that keeps the graph stable.
func (b *builder) addNode(n Node) {
	if !b.nodeSeen[n.ID] {
		b.nodeSeen[n.ID] = true
		b.topo.Nodes = append(b.topo.Nodes, n)
	}
}

func (b *builder) addPhysicalHost(parent store.Server) string {
	id := PhysicalHostNodeID(parent.Hostname)
	b.addNode(Node{
		ID: id, Label: parent.Hostname, Kind: "physical-host",
		DC: parent.DC, IP: parent.IP,
	})
	return id
}

// enrichEndpoint layers an operator annotation over a discovered node. The
// annotation wins over what was observed, and inventory fills the gaps.
func (b *builder) enrichEndpoint(n Node, a store.WGEndpointAnnotation) Node {
	if inv, ok := b.byHost[a.InventoryHost]; ok {
		n.Label = strutil.FirstNonEmpty(a.Label, inv.Hostname, n.Label)
		n.IP = strutil.FirstNonEmpty(a.UnderlayIP, inv.IP, n.IP)
		n.DC = strutil.FirstNonEmpty(a.Site, inv.DC, n.DC)
	} else {
		n.Label = strutil.FirstNonEmpty(a.Label, n.Label)
		n.IP = strutil.FirstNonEmpty(a.UnderlayIP, n.IP)
		n.DC = strutil.FirstNonEmpty(a.Site, n.DC)
	}
	n.Kind = strutil.FirstNonEmpty(a.Kind, n.Kind)
	n.TunnelIP = a.TunnelIP
	if parent, ok := b.byHost[a.ParentHostname]; ok {
		n.Parent = b.addPhysicalHost(parent)
		n.DC = parent.DC
	}
	return n
}

// addGateways places one node per host that owns a WG interface.
func (b *builder) addGateways() {
	hosts := make([]string, 0, len(b.gwHosts))
	for host := range b.gwHosts {
		// One machine reachable under two inventory names produced two gateway
		// nodes for one box — the graph drew sre-lb and sre-srv-0049 side by
		// side, each with the same interfaces and keys. The endpoint index
		// already knows they are the same; this is where that has to be applied,
		// or every later phase works from a duplicated host list.
		if c := b.canonicalHost(host); c != host {
			continue
		}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		n := Node{
			ID: host, Label: host, Kind: "gateway",
			DC: b.dcOf(host), IP: b.byHost[host].IP,
			Warnings: b.warnings[host], Ifaces: b.ifByHost[host],
		}
		// A gateway's identity is a key per interface, not one per host. Carry the
		// first by interface name so a VIP that names an owner can be matched
		// exactly; deterministic because ifByHost is name-sorted.
		if ifs := b.ifByHost[host]; len(ifs) > 0 {
			n.PubKey = b.localPubKey(host, ifs[0].Name)
			if hosts := b.endpoints.ObservedThrough(n.PubKey); len(hosts) > 1 {
				n.SeenAs = hosts
			}
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
// canonicalHost maps an inventory name to the one this graph draws the machine
// under.
//
// A host is an alias when every one of its interfaces was also observed under
// another name with the same key — a VIP and the box it lives on. The canonical
// pick comes from the endpoint index, so it is the same choice edges and nodes
// both make; deciding it twice is how the two used to disagree.
//
// A host that merely shares one key stays its own node. Two machines with one
// shared interface are still two machines.
func (b *builder) canonicalHost(host string) string {
	ifs := b.ifByHost[host]
	if len(ifs) == 0 {
		return host
	}
	canon := ""
	for _, i := range ifs {
		ref, ok := b.endpoints.Lookup(i.PubKey)
		if !ok || b.endpoints.conflicts[i.PubKey] {
			return host // unknown or genuinely conflicting: do not merge
		}
		if canon == "" {
			canon = ref.Host
		} else if canon != ref.Host {
			return host // its interfaces point at different machines
		}
	}
	if canon == "" {
		return host
	}
	return canon
}

// localPubKey is the public key of the interface a peer row was collected on.
// Empty when that interface was not collected, which TunnelEdgeID tolerates.
func (b *builder) localPubKey(host, iface string) string {
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
func (b *builder) fillEdgeSide(id string, p store.WGPeerRow, localKey string) {
	for i := range b.topo.Edges {
		e := &b.topo.Edges[i]
		if e.ID != id {
			continue
		}
		side := &EdgeSide{
			Host: p.Host, Iface: p.Iface, PubKey: localKey,
			Allowed: strings.Join(p.AllowedIPs, ", "),
		}
		// Compare by public key, not by hostname.
		//
		// A machine reachable under two inventory names is polled twice and both
		// rows carry the same key. Matching on host+iface said "different side"
		// for the alias, so it took B — and the real far end, arriving later,
		// found B occupied and was dropped. In this fleet that made the
		// wg-personal tunnel render with sre-lb on both ends and
		// wireguard-personal-incheon nowhere, which is the opposite of what the
		// wire says.
		//
		// The key is the identity. Two observations sharing one are one side of
		// the tunnel however many hostnames they arrived under.
		if e.A != nil && e.A.PubKey == localKey {
			return // the same endpoint, re-collected under another name
		}
		if e.B == nil {
			e.B = side
		}
		return
	}
}

func (b *builder) addPeerEdges() {
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
		k := TunnelKey{p.Host, p.Iface, p.PeerPubKey}
		if far, ok := b.endpoints.Lookup(p.PeerPubKey); ok {
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
			id := TunnelEdgeID(localKey, p.PeerPubKey)
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
			// Source/Target name nodes, and only canonical hosts have nodes now.
			// Whichever alias a peer row happened to be collected under, the edge
			// has to point at the box the graph actually drew — otherwise the
			// endpoint sorted first wins and the edge dangles.
			e := Edge{
				ID:     id,
				Source: b.canonicalHost(p.Host),
				Target: b.canonicalHost(far.Host),
				Iface:  p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
				A: &EdgeSide{
					Host: p.Host, Iface: p.Iface, PubKey: localKey,
					Allowed: strings.Join(p.AllowedIPs, ", "),
				},
			}
			if hosts := b.endpoints.ObservedThrough(p.PeerPubKey); len(hosts) > 1 {
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
		id := p.Host + "|" + p.Iface + "|" + ShortKey(p.PeerPubKey)
		b.edgeFor[k] = id
		b.topo.Edges = append(b.topo.Edges, Edge{
			ID: id, Source: p.Host, Target: n.ID,
			Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
		})
	}
}

// externalNode identifies the far end of an unresolved peer, in increasing
// order of confidence: an opaque key, then an inventory host guessed from a
// unique endpoint address, then whatever an operator annotated.
func (b *builder) externalNode(p store.WGPeerRow) Node {
	label := p.Endpoint
	if label == "" {
		label = ShortKey(p.PeerPubKey)
	}
	n := Node{ID: "ext|" + ShortKey(p.PeerPubKey), Label: label, Kind: "external"}

	// Only guess when exactly one peer claims the address; a shared NAT
	// endpoint says nothing about which host is behind it.
	if ip := EndpointIP(p.Endpoint); ip != "" {
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
func (b *builder) addAggregates() {
	dcWithGW := map[string]bool{}
	for h := range b.gwHosts {
		dcWithGW[b.dcOf(h)] = true
	}
	byKey := map[string]*Agg{}
	members := map[string]map[string]bool{}
	add := func(dc, cidr, member string) string {
		id := "agg|" + dc + "|" + cidr
		a := byKey[id]
		if a == nil {
			a = &Agg{ID: id, DC: dc, CIDR: cidr}
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
func (b *builder) addLinks() {
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
		b.topo.Links = append(b.topo.Links, Link{Source: src, Target: dst, Kind: "management"})
	}
	for _, n := range b.topo.Nodes {
		if n.Kind == "external" {
			continue
		}
		if n.Parent != "" {
			b.topo.Links = append(b.topo.Links, Link{Source: n.ID, Target: n.Parent, Kind: "placement"})
		}
		if cidr, ok := cidr24(n.IP); ok {
			b.topo.Links = append(b.topo.Links, Link{
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

func PhysicalHostNodeID(hostname string) string { return "host|" + hostname }

func AnnotationSpecificity(a store.WGEndpointAnnotation) int {
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

func AnnotationPlacementConflict(a, b store.WGEndpointAnnotation) bool {
	different := func(x, y string) bool { return x != "" && y != "" && x != y }
	return different(a.Label, b.Label) ||
		different(a.Kind, b.Kind) ||
		different(a.UnderlayIP, b.UnderlayIP) ||
		different(a.Site, b.Site) ||
		different(a.InventoryHost, b.InventoryHost) ||
		different(a.ParentHostname, b.ParentHostname)
}

func EndpointIP(endpoint string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(endpoint) != nil {
		return endpoint
	}
	return ""
}
