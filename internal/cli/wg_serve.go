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
func buildWGTopology(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, servers []store.Server, annotations []store.WGEndpointAnnotation) (wgTopology, map[tunnelKey]string) {
	idx := pubIndex(ifaces)

	byHost := make(map[string]store.Server, len(servers))
	byIP := make(map[string]store.Server, len(servers))
	for _, s := range servers {
		byHost[s.Hostname] = s
		byIP[s.IP] = s
		for _, ip := range s.ExtraIPs {
			byIP[ip] = s
		}
	}
	dcOf := func(host string) string { return byHost[host].DC }
	annotationByKey := make(map[string]store.WGEndpointAnnotation, len(annotations))
	for _, a := range annotations {
		annotationByKey[a.PublicKey] = a
	}
	sortedIfaces := append([]store.WGInterfaceRow{}, ifaces...)
	sort.Slice(sortedIfaces, func(i, j int) bool {
		if sortedIfaces[i].Host != sortedIfaces[j].Host {
			return sortedIfaces[i].Host < sortedIfaces[j].Host
		}
		return sortedIfaces[i].Iface < sortedIfaces[j].Iface
	})
	annotationsByHost := map[string][]store.WGEndpointAnnotation{}
	for _, i := range sortedIfaces {
		a, ok := annotationByKey[i.PublicKey]
		if !ok {
			continue
		}
		annotationsByHost[i.Host] = append(annotationsByHost[i.Host], a)
	}
	annotationByHost := map[string]store.WGEndpointAnnotation{}
	annotationWarnings := map[string][]string{}
	for host, candidates := range annotationsByHost {
		selected := candidates[0]
		for _, candidate := range candidates[1:] {
			if wgAnnotationSpecificity(candidate) > wgAnnotationSpecificity(selected) {
				selected = candidate
			}
		}
		for _, candidate := range candidates {
			if wgAnnotationPlacementConflict(selected, candidate) {
				annotationWarnings[host] = []string{
					"conflicting endpoint annotations across WG interfaces; using the most specific placement",
				}
				break
			}
		}
		// A collected host may own several WG interfaces. Their tunnel addresses
		// are interface state, not one host-level scalar.
		selected.TunnelIP = ""
		annotationByHost[host] = selected
	}
	endpointIPCount := map[string]int{}
	for _, p := range peers {
		if ip := wgEndpointIP(p.Endpoint); ip != "" {
			endpointIPCount[ip]++
		}
	}

	// Interfaces grouped per gateway host (name-sorted for a stable port order).
	ifByHost := map[string][]wgIface{}
	for _, i := range ifaces {
		ifByHost[i.Host] = append(ifByHost[i.Host], wgIface{Name: i.Iface, Port: i.ListenPort})
	}
	for h := range ifByHost {
		sort.Slice(ifByHost[h], func(a, b int) bool { return ifByHost[h][a].Name < ifByHost[h][b].Name })
	}

	var topo wgTopology
	nodeSeen := map[string]bool{}
	addNode := func(n wgNode) {
		if !nodeSeen[n.ID] {
			nodeSeen[n.ID] = true
			topo.Nodes = append(topo.Nodes, n)
		}
	}
	addPhysicalHost := func(parent store.Server) string {
		id := physicalHostNodeID(parent.Hostname)
		addNode(wgNode{
			ID: id, Label: parent.Hostname, Kind: "physical-host",
			DC: parent.DC, IP: parent.IP,
		})
		return id
	}
	enrichEndpoint := func(n wgNode, a store.WGEndpointAnnotation) wgNode {
		if inv, ok := byHost[a.InventoryHost]; ok {
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
		if parent, ok := byHost[a.ParentHostname]; ok {
			n.Parent = addPhysicalHost(parent)
			n.DC = parent.DC
		}
		return n
	}
	gwHosts := map[string]bool{}
	for _, i := range ifaces {
		gwHosts[i.Host] = true
	}
	gatewayHosts := make([]string, 0, len(gwHosts))
	for host := range gwHosts {
		gatewayHosts = append(gatewayHosts, host)
	}
	sort.Strings(gatewayHosts)
	for _, host := range gatewayHosts {
		n := wgNode{
			ID: host, Label: host, Kind: "gateway",
			DC: dcOf(host), IP: byHost[host].IP,
			Warnings: annotationWarnings[host], Ifaces: ifByHost[host],
		}
		if a, ok := annotationByHost[host]; ok {
			n = enrichEndpoint(n, a)
		}
		addNode(n)
	}

	edgeFor := map[tunnelKey]string{}
	edgeSeen := map[string]bool{}
	sorted := append([]store.WGPeerRow{}, peers...)
	sort.Slice(sorted, func(a, b int) bool {
		if sorted[a].Host != sorted[b].Host {
			return sorted[a].Host < sorted[b].Host
		}
		if sorted[a].Iface != sorted[b].Iface {
			return sorted[a].Iface < sorted[b].Iface
		}
		return sorted[a].PeerPubKey < sorted[b].PeerPubKey
	})
	for _, p := range sorted {
		k := tunnelKey{p.Host, p.Iface, p.PeerPubKey}
		if far, ok := idx[p.PeerPubKey]; ok {
			// Resolved gateway↔gateway tunnel: one edge, canonical side first.
			a, b := p.Host, far.host
			if a > b {
				a, b = b, a
			}
			id := "gw|" + a + "|" + b + "|" + p.Iface
			edgeFor[k] = id
			if edgeSeen[id] {
				continue
			}
			edgeSeen[id] = true
			topo.Edges = append(topo.Edges, wgEdge{
				ID: id, Source: p.Host, Target: far.host,
				Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
			})
			continue
		}
		extID := "ext|" + shortKey(p.PeerPubKey)
		label := p.Endpoint
		if label == "" {
			label = shortKey(p.PeerPubKey)
		}
		n := wgNode{ID: extID, Label: label, Kind: "external"}
		if ip := wgEndpointIP(p.Endpoint); ip != "" {
			if sv, ok := byIP[ip]; ok && endpointIPCount[ip] == 1 {
				n.ID = "inventory|" + sv.Hostname
				n.Label = sv.Hostname + " ?"
				n.Kind = "inventory-candidate"
				n.Observed = p.Endpoint
			}
		}
		if a, ok := annotationByKey[p.PeerPubKey]; ok {
			n.ID = "endpoint|" + p.PeerPubKey
			n = enrichEndpoint(n, a)
		}
		extID = n.ID
		addNode(n)
		id := p.Host + "|" + p.Iface + "|" + shortKey(p.PeerPubKey)
		edgeFor[k] = id
		topo.Edges = append(topo.Edges, wgEdge{
			ID: id, Source: p.Host, Target: extID,
			Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
		})
	}

	// Aggregate nodes: non-gateway inventory hosts, grouped by (dc, primary /24),
	// but only in dcs that own at least one WG gateway.
	dcWithGW := map[string]bool{}
	for h := range gwHosts {
		dcWithGW[dcOf(h)] = true
	}
	aggByKey := map[string]*wgAgg{}
	aggMembers := map[string]map[string]bool{}
	aggOfHost := map[string]string{} // hostname → agg id (for link resolution)
	addAgg := func(dc, cidr, member string) string {
		id := "agg|" + dc + "|" + cidr
		a := aggByKey[id]
		if a == nil {
			a = &wgAgg{ID: id, DC: dc, CIDR: cidr}
			aggByKey[id] = a
		}
		if aggMembers[id] == nil {
			aggMembers[id] = map[string]bool{}
		}
		if member != "" && !aggMembers[id][member] {
			aggMembers[id][member] = true
			a.Count++
		}
		return id
	}
	for _, s := range servers {
		if !dcWithGW[s.DC] {
			continue
		}
		if cidr, ok := cidr24(s.IP); ok {
			aggOfHost[s.Hostname] = addAgg(s.DC, cidr, s.Hostname)
		}
	}
	for _, n := range topo.Nodes {
		if n.Kind == "external" || n.DC == "" {
			continue
		}
		if cidr, ok := cidr24(n.IP); ok {
			member := n.ID
			if strings.HasPrefix(n.ID, "inventory|") {
				member = strings.TrimPrefix(n.ID, "inventory|")
			}
			addAgg(n.DC, cidr, member)
		}
	}
	for _, a := range aggByKey {
		topo.Aggs = append(topo.Aggs, *a)
	}
	sort.Slice(topo.Aggs, func(a, b int) bool { return topo.Aggs[a].ID < topo.Aggs[b].ID })

	// Management links from servers.jump_via, each end resolved to a gateway
	// hostname or the aggregate node the host belongs to; unresolved/self dropped.
	resolve := func(host string) (string, bool) {
		if gwHosts[host] {
			return host, true
		}
		if id, ok := aggOfHost[host]; ok {
			return id, true
		}
		return "", false
	}
	linkSeen := map[string]bool{}
	for _, s := range servers {
		if s.JumpVia == "" {
			continue
		}
		src, ok1 := resolve(s.Hostname)
		dst, ok2 := resolve(s.JumpVia)
		if !ok1 || !ok2 || src == dst {
			continue
		}
		key := src + "\x00" + dst
		if linkSeen[key] {
			continue
		}
		linkSeen[key] = true
		topo.Links = append(topo.Links, wgLink{Source: src, Target: dst, Kind: "management"})
	}
	for _, n := range topo.Nodes {
		if n.Kind == "external" {
			continue
		}
		if n.Parent != "" {
			topo.Links = append(topo.Links, wgLink{Source: n.ID, Target: n.Parent, Kind: "placement"})
		}
		if cidr, ok := cidr24(n.IP); ok {
			topo.Links = append(topo.Links, wgLink{
				Source: n.ID, Target: "agg|" + n.DC + "|" + cidr, Kind: "network",
			})
		}
	}
	sort.Slice(topo.Links, func(a, b int) bool {
		if topo.Links[a].Source != topo.Links[b].Source {
			return topo.Links[a].Source < topo.Links[b].Source
		}
		return topo.Links[a].Target < topo.Links[b].Target
	})

	return topo, edgeFor
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
