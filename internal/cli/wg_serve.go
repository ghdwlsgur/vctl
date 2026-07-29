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
	ID      string `json:"id"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	Iface   string `json:"iface"`
	Allowed string `json:"allowed"`
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
}

// edgeStat is the live per-tunnel measurement pushed to browsers.
type edgeStat struct {
	RxPS float64 `json:"rx"` // bytes/sec toward the source gateway
	TxPS float64 `json:"tx"` // bytes/sec away from the source gateway
	HS   int64   `json:"hs"` // seconds since last handshake, -1 = never
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

	pubIdx     map[string]nodeRef                    // interface public key → owning gateway
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
		pubIdx:     pubIndex(ifaces),
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
		if far, ok := b.pubIdx[p.PeerPubKey]; ok {
			// Both ends collected: one edge, canonical side first so the two
			// directions collapse into the same id.
			a, c := p.Host, far.host
			if a > c {
				a, c = c, a
			}
			id := "gw|" + a + "|" + c + "|" + p.Iface
			b.edgeFor[k] = id
			if edgeSeen[id] {
				continue
			}
			edgeSeen[id] = true
			b.topo.Edges = append(b.topo.Edges, wgEdge{
				ID: id, Source: p.Host, Target: far.host,
				Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
			})
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
		st := edgeStat{HS: -1}
		if hs != nil {
			st.HS = int64(time.Since(*hs).Seconds())
		}
		if old, ok := s.prev[k]; ok {
			st.RxPS, st.TxPS = computeRate(old, cur)
		}
		s.prev[k] = cur
		s.stats[id] = st
	}
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
