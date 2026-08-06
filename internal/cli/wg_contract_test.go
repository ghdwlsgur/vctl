package cli

import (
	"strings"
	"testing"
)

// The browser reads the topology this serves, and parts of it are a contract
// rather than a payload. These pin the parts wg_serve.html depends on.
//
// The dashboard is not a passive renderer: it merges gateways that share an IP,
// elects a hub, splits mesh from spokes, and groups by zone. Doing that means
// reading the shape, and where it reads the shape it has assumed things Go
// happens to do. Nothing failed if Go stopped doing them — the page just drew
// something else, and there was no way to tell a rendering fault from a data
// one, which is exactly the complaint that started this.

// A node id says whether it is a hostname, and edgeHosts in wg_serve.html reads
// it that way:
//
//	if(!hs.length){for(const id of [e.source,e.target])if(id&&!id.includes("|"))hs.push(id);}
//
// A tunnel whose ends were not both collected is attributed by taking the node
// ids that look like hostnames. Give a gateway an id containing "|" and its
// tunnels lose their host; give an endpoint a bare id and its key gets reported
// as a machine that does not exist.
func TestGatewayIDsAreHostnamesAndNothingElseIs(t *testing.T) {
	topo := wgDashboardFixture()
	var gateways int
	for _, n := range topo.Nodes {
		bare := !strings.Contains(n.ID, "|")
		if n.Kind == "gateway" {
			gateways++
			if !bare {
				t.Errorf("gateway %q has an id the page cannot read as a hostname", n.ID)
			}
			continue
		}
		if bare {
			t.Errorf("%s node %q has a bare id; the page will report it as a host", n.Kind, n.ID)
		}
	}
	if gateways == 0 {
		t.Fatal("the fixture has no gateways, so this proves nothing")
	}
}

// prep() dedups gateways that share an IP and elects the hub by interface
// count. Both need the fields present on gateway nodes:
//
//	for(const n of N.values())if(n.kind==="gateway"&&n.ip)…
//	…(n.ifaces||[]).length>…
//
// Without ip the dedup silently never fires — two names for one machine draw as
// two machines. Without ifaces there is no hub, and the layout has nothing to
// arrange around.
func TestGatewayNodesCarryWhatTheLayoutGroupsOn(t *testing.T) {
	topo := wgDashboardFixture()
	var withIfaces int
	for _, n := range topo.Nodes {
		if n.Kind != "gateway" {
			continue
		}
		if n.IP == "" {
			t.Errorf("gateway %q has no ip; the page cannot merge it with its other name", n.ID)
		}
		if len(n.Ifaces) > 0 {
			withIfaces++
		}
	}
	if withIfaces == 0 {
		t.Error("no gateway carries interfaces, so the page would elect no hub")
	}
}

// Every edge has to land on nodes that exist. The page looks both ends up in a
// map built from Nodes and drops what it cannot find, so a dangling end is a
// tunnel that silently disappears from the diagram rather than an error.
func TestEveryEdgeEndExists(t *testing.T) {
	topo := wgDashboardFixture()
	known := make(map[string]bool, len(topo.Nodes))
	for _, n := range topo.Nodes {
		known[n.ID] = true
	}
	if len(topo.Edges) == 0 {
		t.Fatal("the fixture has no edges, so this proves nothing")
	}
	for _, e := range topo.Edges {
		for _, end := range []string{e.Source, e.Target} {
			if !known[end] {
				t.Errorf("edge %q points at %q, which is not a node", e.ID, end)
			}
		}
	}
}

// The kinds the page switches on have to be the kinds Go emits. "gateway" is
// the one it branches on by name; the rest reach kindLabel, which renders
// whatever it is given and so cannot fail visibly.
func TestTheKindThePageBranchesOnIsEmitted(t *testing.T) {
	topo := wgDashboardFixture()
	for _, n := range topo.Nodes {
		if n.Kind == "gateway" {
			return
		}
	}
	t.Error(`no node has kind "gateway"; the page would find no hub and draw nothing`)
}

// The id builders hold the same rule, asserted directly.
//
// The fixture above never produces a physical-host node — that needs an
// annotation naming an inventory parent — so a test that only walked it left
// physicalHostNodeID uncovered. Removing its prefix passed. This is the part
// that would break the browser's host attribution most quietly, because a
// physical host's id *is* a hostname and looks entirely reasonable.
func TestEveryNonGatewayIDBuilderKeepsItOutOfHostnameSpace(t *testing.T) {
	for _, tc := range []struct{ name, id string }{
		{"physical host", physicalHostNodeID("sre-srv-0047")},
		{"external peer", "ext|" + shortKey("SOMEKEY")},
		{"endpoint", "endpoint|" + "SOMEKEY"},
	} {
		if !strings.Contains(tc.id, "|") {
			t.Errorf("%s id %q is bare; edgeHosts would report it as a gateway hostname", tc.name, tc.id)
		}
	}
}
