package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

func TestWGMermaid(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "hub", Iface: "wg0", ListenPort: 51820, PublicKey: "HUBKEY"}},
		{WGInterface: store.WGInterface{Host: "leaf", Iface: "wg0", ListenPort: 51820, PublicKey: "LEAFKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{Host: "hub", Iface: "wg0", PeerPubKey: "LEAFKEY", AllowedIPs: []string{"10.0.0.2/32"}}},
		{WGPeer: store.WGPeer{Host: "leaf", Iface: "wg0", PeerPubKey: "HUBKEY", AllowedIPs: []string{"10.0.0.1/32"}}},
		{WGPeer: store.WGPeer{Host: "hub", Iface: "wg0", PeerPubKey: "EXTKEY", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.3.0.0/24"}}},
	}
	out := wgMermaid(ifaces, peers)

	for _, want := range []string{"graph LR", `subgraph hub["hub"]`, `subgraph leaf["leaf"]`, `hub_wg0["wg0 :51820"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("mermaid missing %q\n%s", want, out)
		}
	}
	// resolved edge appears exactly once (bidirectional collapse): only one
	// edge should point into leaf_wg0, and leaf must not emit its reverse edge.
	if c := strings.Count(out, "| leaf_wg0"); c != 1 {
		t.Errorf("expected exactly one edge into leaf_wg0, got %d\n%s", c, out)
	}
	// external node defined with endpoint label + edge to it
	if !strings.Contains(out, `1.2.3.4:51820`) || !strings.Contains(out, "ext_") {
		t.Errorf("external node/edge missing\n%s", out)
	}
}

func TestBuildWGTopologyPlacesAnnotatedVMOnPhysicalHost(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{
			Host: "wg-hub", Iface: "wg2", ListenPort: 51822, PublicKey: "HUBKEY",
		}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{
			Host: "wg-hub", Iface: "wg2", PeerPubKey: "VMKEY",
			Endpoint: "198.51.100.10:51822", AllowedIPs: []string{"10.10.2.0/24"},
		}},
	}
	servers := []store.Server{
		{Hostname: "wg-hub", IP: "192.168.10.240", DC: "incheon-vm"},
		{Hostname: "compute-01", IP: "172.16.0.31", DC: "seoul-onprem"},
	}
	annotations := []store.WGEndpointAnnotation{
		{
			PublicKey: "VMKEY", Label: "ai-platform-incheon-gw", Kind: "vm",
			UnderlayIP: "10.10.2.192", TunnelIP: "10.0.92.1",
			Site: "seoul", ParentHostname: "compute-01",
		},
	}

	topo, _ := wireguard.Build(ifaces, peers, servers, annotations)

	vm := topologyNode(topo, "endpoint|VMKEY")
	if vm == nil {
		t.Fatalf("annotated VM endpoint missing: %+v", topo.Nodes)
	}
	if vm.Label != "ai-platform-incheon-gw" || vm.Kind != "vm" ||
		vm.Parent != "host|compute-01" || vm.IP != "10.10.2.192" || vm.TunnelIP != "10.0.92.1" {
		t.Errorf("annotated VM = %+v", *vm)
	}
	host := topologyNode(topo, "host|compute-01")
	if host == nil || host.Kind != "physical-host" {
		t.Fatalf("physical parent host missing: %+v", topo.Nodes)
	}
	if !hasTopologyLink(topo, "endpoint|VMKEY", "host|compute-01", "placement") {
		t.Errorf("VM placement link missing: %+v", topo.Links)
	}
	if !hasTopologyLink(topo, "endpoint|VMKEY", "agg|seoul-onprem|10.10.2.0/24", "network") {
		t.Errorf("VM host-network link missing: %+v", topo.Links)
	}
}

func TestBuildWGTopologyKeepsEndpointVisibleWhenParentIsUnknown(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg2", PublicKey: "HUBKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{
			Host: "wg-hub", Iface: "wg2", PeerPubKey: "VMKEY",
			Endpoint: "198.51.100.10:51822",
		}},
	}
	annotations := []store.WGEndpointAnnotation{
		{
			PublicKey: "VMKEY", Label: "orphan-vm", Kind: "vm",
			UnderlayIP: "10.10.2.192", Site: "seoul", ParentHostname: "stale-compute-name",
		},
	}

	topo, _ := wireguard.Build(ifaces, peers, nil, annotations)

	vm := topologyNode(topo, "endpoint|VMKEY")
	if vm == nil {
		t.Fatal("annotated endpoint disappeared with an unknown parent")
	}
	if vm.Parent != "" || vm.DC != "seoul" {
		t.Errorf("unknown parent must degrade to an unplaced site endpoint: %+v", *vm)
	}
	if hasTopologyLink(topo, vm.ID, "stale-compute-name", "placement") {
		t.Errorf("invalid placement link emitted: %+v", topo.Links)
	}
}

func TestBuildWGTopologyInheritsEndpointIdentityFromInventoryHost(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg2", PublicKey: "HUBKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg2", PeerPubKey: "VMKEY"}},
	}
	servers := []store.Server{
		{Hostname: "ai-platform-incheon-gw", IP: "10.10.2.192", DC: "seoul-vm"},
	}
	annotations := []store.WGEndpointAnnotation{
		{PublicKey: "VMKEY", Kind: "vm", InventoryHost: "ai-platform-incheon-gw"},
	}

	topo, _ := wireguard.Build(ifaces, peers, servers, annotations)

	vm := topologyNode(topo, "endpoint|VMKEY")
	if vm == nil || vm.Label != "ai-platform-incheon-gw" ||
		vm.IP != "10.10.2.192" || vm.DC != "seoul-vm" {
		t.Fatalf("inventory identity was not inherited: %+v", vm)
	}
}

func TestBuildWGTopologyPlacesCollectedGatewayVMOnPhysicalHost(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{
			Host: "sre-lb", Iface: "wg1", ListenPort: 51821, PublicKey: "SRELBKEY",
		}},
	}
	servers := []store.Server{
		{Hostname: "sre-lb", IP: "192.168.201.12", DC: "seoul-onprem"},
		{Hostname: "compute-49", IP: "172.16.0.49", DC: "seoul-onprem"},
	}
	annotations := []store.WGEndpointAnnotation{
		{
			PublicKey: "SRELBKEY", Label: "sre-lb", Kind: "vm",
			UnderlayIP: "192.168.201.12", Site: "seoul", InventoryHost: "sre-lb",
			ParentHostname: "compute-49",
		},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, annotations)

	vm := topologyNode(topo, "sre-lb")
	if vm == nil || vm.Kind != "vm" || vm.Parent != "host|compute-49" || len(vm.Ifaces) != 1 {
		t.Fatalf("collected VM gateway not placed: %+v", vm)
	}
	host := topologyNode(topo, "host|compute-49")
	if host == nil || host.Kind != "physical-host" {
		t.Fatalf("physical parent host missing: %+v", topo.Nodes)
	}
	if !hasTopologyLink(topo, "sre-lb", "host|compute-49", "placement") {
		t.Errorf("gateway VM placement link missing: %+v", topo.Links)
	}
	if !hasTopologyLink(topo, "sre-lb", "agg|seoul-onprem|192.168.201.0/24", "network") {
		t.Errorf("gateway VM host-network link missing: %+v", topo.Links)
	}
}

func TestBuildWGTopologyMergesAnnotationAcrossHostInterfaces(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "multi-gw", Iface: "wg0", PublicKey: "WG0KEY"}},
		{WGInterface: store.WGInterface{Host: "multi-gw", Iface: "wg1", PublicKey: "WG1KEY"}},
	}
	servers := []store.Server{
		{Hostname: "multi-gw", IP: "192.168.201.12", DC: "seoul-onprem"},
		{Hostname: "compute-49", IP: "172.16.0.49", DC: "seoul-onprem"},
	}
	annotations := []store.WGEndpointAnnotation{
		{
			PublicKey: "WG1KEY", Label: "multi-gw-vm", Kind: "vm",
			InventoryHost: "multi-gw", ParentHostname: "compute-49",
		},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, annotations)

	vm := topologyNode(topo, "multi-gw")
	if vm == nil || vm.Label != "multi-gw-vm" || vm.Parent != "host|compute-49" ||
		len(vm.Ifaces) != 2 {
		t.Fatalf("host interface annotations were not merged: %+v", vm)
	}
}

func TestBuildWGTopologyWarnsOnConflictingHostInterfaceAnnotations(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "multi-gw", Iface: "wg0", PublicKey: "WG0KEY"}},
		{WGInterface: store.WGInterface{Host: "multi-gw", Iface: "wg1", PublicKey: "WG1KEY"}},
	}
	servers := []store.Server{
		{Hostname: "multi-gw", IP: "192.168.201.12", DC: "seoul-onprem"},
		{Hostname: "compute-01", IP: "172.16.0.31", DC: "seoul-onprem"},
		{Hostname: "compute-02", IP: "172.16.0.32", DC: "seoul-onprem"},
	}
	annotations := []store.WGEndpointAnnotation{
		{PublicKey: "WG0KEY", Kind: "vm", ParentHostname: "compute-01", TunnelIP: "10.0.90.1"},
		{PublicKey: "WG1KEY", Kind: "vm", ParentHostname: "compute-02", TunnelIP: "10.0.91.1"},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, annotations)

	node := topologyNode(topo, "multi-gw")
	if node == nil || len(node.Warnings) == 0 {
		t.Fatalf("conflicting host annotations were silently merged: %+v", node)
	}
	if node.TunnelIP != "" {
		t.Fatalf("interface-specific tunnel IP leaked into host-level node: %+v", node)
	}
}

func TestBuildWGTopologySeparatesPhysicalHostFromItsWGEndpoint(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{
			Host: "compute-49", Iface: "wg0", PublicKey: "COMPUTEKEY",
		}},
		{WGInterface: store.WGInterface{
			Host: "guest-vm", Iface: "wg1", PublicKey: "GUESTKEY",
		}},
	}
	servers := []store.Server{
		{Hostname: "compute-49", IP: "172.16.0.49", DC: "seoul-onprem"},
		{Hostname: "guest-vm", IP: "192.168.201.12", DC: "seoul-onprem"},
	}
	annotations := []store.WGEndpointAnnotation{
		{
			PublicKey: "GUESTKEY", Kind: "vm", InventoryHost: "guest-vm",
			ParentHostname: "compute-49",
		},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, annotations)

	host := topologyNode(topo, "host|compute-49")
	wgEndpoint := topologyNode(topo, "compute-49")
	if host == nil || host.Kind != "physical-host" {
		t.Fatalf("physical host node missing: %+v", topo.Nodes)
	}
	if wgEndpoint == nil || len(wgEndpoint.Ifaces) != 1 {
		t.Fatalf("host's own WG endpoint was overwritten: %+v", topo.Nodes)
	}
}

func TestBuildWGTopologyResolvesEndpointIPFromInventory(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{
			Host: "wg-hub", Iface: "wg3", ListenPort: 51823, PublicKey: "HUBKEY",
		}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{
			Host: "wg-hub", Iface: "wg3", PeerPubKey: "GPUKEY",
			Endpoint: "192.168.40.76:39047", AllowedIPs: []string{"10.0.93.7/32"},
		}},
	}
	servers := []store.Server{
		{Hostname: "wg-hub", IP: "192.168.10.240", DC: "incheon-vm"},
		{Hostname: "gpu-worker-incheon", IP: "192.168.40.76", DC: "incheon-vm"},
	}

	topo, _ := wireguard.Build(ifaces, peers, servers, nil)

	endpoint := topologyNode(topo, "inventory|gpu-worker-incheon")
	if endpoint == nil {
		t.Fatalf("inventory endpoint missing: %+v", topo.Nodes)
	}
	if endpoint.Label != "gpu-worker-incheon ?" || endpoint.Kind != "inventory-candidate" ||
		endpoint.IP != "" || endpoint.DC != "" || endpoint.Observed != "192.168.40.76:39047" {
		t.Errorf("resolved inventory endpoint = %+v", *endpoint)
	}
	if hasTopologyLink(topo, "inventory|gpu-worker-incheon", "agg|incheon-vm|192.168.40.0/24", "network") {
		t.Errorf("inferred endpoint must not claim a physical network: %+v", topo.Links)
	}
}

func TestBuildWGTopologyDoesNotResolveSharedNATEndpointAsPeer(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg0", PublicKey: "HUBKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg0", PeerPubKey: "PEER1", Endpoint: "192.168.10.1:10001"}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg0", PeerPubKey: "PEER2", Endpoint: "192.168.10.1:10002"}},
	}
	servers := []store.Server{
		{Hostname: "incheon-edge", IP: "192.168.10.1", DC: "incheon-onprem"},
	}

	topo, _ := wireguard.Build(ifaces, peers, servers, nil)

	if topologyNode(topo, "inventory|incheon-edge") != nil {
		t.Fatal("shared NAT endpoint was incorrectly asserted as both peer identities")
	}
	if topologyNode(topo, "ext|PEER1") == nil || topologyNode(topo, "ext|PEER2") == nil {
		t.Fatalf("shared NAT peers must remain external until annotated: %+v", topo.Nodes)
	}
}

func TestBuildWGTopologyComposesAnnotationWithObservedEndpointCandidate(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg3", PublicKey: "HUBKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{
			Host: "wg-hub", Iface: "wg3", PeerPubKey: "GPUKEY",
			Endpoint: "192.168.40.76:39047",
		}},
	}
	servers := []store.Server{
		{Hostname: "gpu-worker-incheon", IP: "192.168.40.76", DC: "incheon-vm"},
	}
	annotations := []store.WGEndpointAnnotation{
		{PublicKey: "GPUKEY", Label: "gpu endpoint", Kind: "device"},
	}

	topo, _ := wireguard.Build(ifaces, peers, servers, annotations)

	endpoint := topologyNode(topo, "endpoint|GPUKEY")
	if endpoint == nil || endpoint.Label != "gpu endpoint" || endpoint.Kind != "device" ||
		endpoint.Observed != "192.168.40.76:39047" {
		t.Fatalf("annotation did not compose with observed endpoint candidate: %+v", endpoint)
	}
	if endpoint.IP != "" || endpoint.DC != "" {
		t.Fatalf("observed endpoint candidate asserted physical placement: %+v", endpoint)
	}
}

func hasTopologyLink(topo wireguard.Topology, source, target, kind string) bool {
	for _, link := range topo.Links {
		if link.Source == source && link.Target == target && link.Kind == kind {
			return true
		}
	}
	return false
}

func TestWGServeDashboardWiringLayout(t *testing.T) {
	html := string(wgServeHTML)

	// The dashboard renders the approved wiring layout: hub iface ports feeding
	// orthogonal elbows through NAT into per-zone endpoints and reachable-CIDR
	// bands, with a /32 mesh stack and a WG_BOOT snapshot-replay contract.
	for _, want := range []string{
		"window.WG_BOOT",
		"hubPort",
		"reachable ranges",
		"mesh ×",
		"NAT / WAN",
		"EDGE / NAT",
		"kindLabel",
		"focusClosure",
		`id="zoom-fit"`,
		`id="live-summary"`,
		`fetch("topology")`,
		`EventSource("events")`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard is missing %q", want)
		}
	}
	if strings.Contains(html, " Q ") || strings.Contains(html, " C ") {
		t.Error("WireGuard tunnels must stay orthogonal (no curves)")
	}
}

// TestWGServeInterfaceFilterIsolatesOneTunnel locks the filter contract: picking
// an interface highlights that tunnel alone. The dashboard used to walk onward
// through transit nodes, so selecting wg1 also lit wg9 behind a relay and
// reported "+N connected" — the opposite of isolating what was clicked.
func TestWGServeInterfaceFilterIsolatesOneTunnel(t *testing.T) {
	html := string(wgServeHTML)

	// "hops" on its own is the mesh renderer's own variable, so key off the label
	// the closure walk used to print instead.
	if strings.Contains(html, "connected") {
		t.Error("filter must not report extra connected interfaces; focus is one tunnel")
	}
	// A closure that walks the graph needs a queue and an incident-edge index.
	// Their absence is what keeps the selection exact.
	for _, banned := range []string{"const incident=new Map()", "queue.shift()"} {
		if strings.Contains(html, banned) {
			t.Errorf("filter walks beyond the selected tunnel: found %q", banned)
		}
	}
	// The legend must be built from drawn geometry. Interfaces the hub-centric
	// layout never draws have nothing to highlight, so a chip for one would dim
	// the whole diagram and light nothing.
	if !strings.Contains(html, `svg.querySelectorAll("[data-ifc],[data-ifs]")`) {
		t.Error("legend must be built from the drawn canvas, not from every topology edge")
	}
	if strings.Contains(html, "(curTopo.edges||[]).forEach(e=>ifs.add(e.iface))") {
		t.Error("legend is back to enumerating every topology edge; undrawn ifaces get dead chips")
	}
}

func TestComputeRate(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	prev := wireguard.Sample{Rx: 1000, Tx: 500, At: t0}
	cur := wireguard.Sample{Rx: 3000, Tx: 1500, At: t0.Add(2 * time.Second)}
	rx, tx := wireguard.ComputeRate(prev, cur)
	if rx != 1000 || tx != 500 { // (3000-1000)/2, (1500-500)/2
		t.Errorf("rate = %v/%v, want 1000/500", rx, tx)
	}
	// counter reset: cur < prev -> 0, not negative
	if r, _ := wireguard.ComputeRate(wireguard.Sample{Rx: 5000, At: t0}, wireguard.Sample{Rx: 10, At: t0.Add(time.Second)}); r != 0 {
		t.Errorf("reset rate = %v, want 0", r)
	}
	// non-positive dt -> 0
	if r, _ := wireguard.ComputeRate(prev, wireguard.Sample{Rx: 9999, At: t0}); r != 0 {
		t.Errorf("zero-dt rate = %v, want 0", r)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{512: "512B", 2048: "2.0K", 5 * 1024 * 1024: "5.0M"}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// Management links come from servers.jump_via and were the one part of the
// graph with no test at all — the gap only became visible once wireguard.Build
// was split into phases and addLinks reported its own coverage.
//
// Each end resolves to a gateway hostname, or to the aggregate node the host
// sits in when it is not a gateway itself.
func TestBuildWGTopologyDrawsManagementLinksFromJumpVia(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "gw-a", Iface: "wg0", PublicKey: "AKEY"}},
	}
	servers := []store.Server{
		{Hostname: "gw-a", IP: "10.10.0.1", DC: "incheon"},
		// Reaches the world through the gateway: gw-a is a gateway, so the link
		// lands on the hostname directly.
		{Hostname: "app-01", IP: "10.10.0.20", DC: "incheon", JumpVia: "gw-a"},
		// Not a gateway on either end, so both collapse into their /24 aggregate
		// — and because that is the same aggregate, the self-link is dropped.
		{Hostname: "app-02", IP: "10.10.0.21", DC: "incheon", JumpVia: "app-01"},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, nil)

	agg := "agg|incheon|10.10.0.0/24"
	if !hasTopologyLink(topo, agg, "gw-a", "management") {
		t.Errorf("management link from the aggregate to its gateway missing: %+v", topo.Links)
	}
	for _, l := range topo.Links {
		if l.Kind == "management" && l.Source == l.Target {
			t.Errorf("self management link emitted: %+v", l)
		}
	}
}

// An unresolvable jump target must be dropped rather than drawn as a dangling
// edge: a host in a dc with no gateway gets no aggregate, so there is nothing
// to point at.
func TestBuildWGTopologyDropsUnresolvableJumpVia(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "gw-a", Iface: "wg0", PublicKey: "AKEY"}},
	}
	servers := []store.Server{
		{Hostname: "gw-a", IP: "10.10.0.1", DC: "incheon"},
		{Hostname: "app-01", IP: "10.10.0.20", DC: "incheon", JumpVia: "does-not-exist"},
		// Different dc with no gateway: no aggregate, so this end never resolves.
		{Hostname: "far-01", IP: "10.99.0.5", DC: "nowhere", JumpVia: "gw-a"},
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, nil)

	for _, l := range topo.Links {
		if l.Kind != "management" {
			continue
		}
		if l.Target == "does-not-exist" || l.Source == "agg|nowhere|10.99.0.0/24" {
			t.Errorf("unresolvable jump_via produced a link: %+v", l)
		}
	}
}

// Many hosts jumping through the same gateway collapse to one link, not one per
// host: the graph shows adjacency, not host count.
func TestBuildWGTopologyDeduplicatesManagementLinks(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "gw-a", Iface: "wg0", PublicKey: "AKEY"}},
	}
	servers := []store.Server{{Hostname: "gw-a", IP: "10.10.0.1", DC: "incheon"}}
	for _, h := range []string{"app-01", "app-02", "app-03"} {
		servers = append(servers, store.Server{
			Hostname: h, IP: "10.10.0.2" + h[len(h)-1:], DC: "incheon", JumpVia: "gw-a",
		})
	}

	topo, _ := wireguard.Build(ifaces, nil, servers, nil)

	var management int
	for _, l := range topo.Links {
		if l.Kind == "management" {
			management++
		}
	}
	if management != 1 {
		t.Errorf("3 hosts through one gateway produced %d management links, want 1: %+v", management, topo.Links)
	}
}

// topologyNode finds a node by id, or nil. The page tests below assert on one
// node at a time and reading it out of the slice by hand at each call site was
// the same three lines repeated.
func topologyNode(topo wireguard.Topology, id string) *wireguard.Node {
	for i := range topo.Nodes {
		if topo.Nodes[i].ID == id {
			return &topo.Nodes[i]
		}
	}
	return nil
}
