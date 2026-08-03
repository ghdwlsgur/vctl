package cli

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A gateway node has to carry its public key, because that is what a VIP points
// at. Matching on a substring of the display label is what this replaces.
func TestGatewayNodeCarriesItsPublicKey(t *testing.T) {
	topo, _ := buildWGTopology(
		[]store.WGInterfaceRow{iface("gw-a", "wg0", "AKEY", 51820, "10.0.1.1")},
		nil, nil, nil)

	n := topologyNode(topo, "gw-a")
	if n == nil {
		t.Fatal("gateway node missing")
	}
	if n.PubKey != "AKEY" {
		t.Errorf("node.PubKey = %q, want the interface's key", n.PubKey)
	}
}

// One machine under two inventory names should say so on the node, not silently
// render as whichever name sorted first.
func TestGatewayNodeNamesEveryHostItWasSeenAs(t *testing.T) {
	topo, _ := buildWGTopology([]store.WGInterfaceRow{
		iface("sre-srv-0049", "wg1", "LBKEY", 51821, "10.0.91.1"),
		iface("sre-lb", "wg1", "LBKEY", 51821, "10.0.91.1"),
	}, nil, nil, nil)

	var withSeen *wgNode
	for i := range topo.Nodes {
		if len(topo.Nodes[i].SeenAs) > 0 {
			withSeen = &topo.Nodes[i]
			break
		}
	}
	if withSeen == nil {
		t.Fatalf("no node reports the two names: %+v", topo.Nodes)
	}
	if len(withSeen.SeenAs) != 2 {
		t.Errorf("SeenAs = %v, want both hostnames", withSeen.SeenAs)
	}
}

// The VIP's owner has to survive to the browser under a name the page reads.
func TestVipCarriesTheRecordedOwner(t *testing.T) {
	page := string(wgServeHTML)
	// The page prefers the stated owner and only then falls back.
	for _, want := range []string{"v.owner", "byKey", "guessed"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not use %q", want)
		}
	}
	// And it must still be able to fall back, or every un-annotated VIP vanishes.
	if !strings.Contains(page, "v.label.includes(tok)") {
		t.Error("the label fallback is gone; VIPs with no recorded owner would disappear")
	}
}

// A stated owner attaches exactly; a missing one falls back to label text and is
// marked. Substring matching on two human-typed strings attaches a VIP to the
// wrong endpoint when one label contains another's prefix, and the screen could
// not say which had happened.
func TestDashboardVipPrefersTheRecordedOwner(t *testing.T) {
	got := runDashboardJS(t, `
vipFocusNodes=new Map();
const N=new Map([
  ["sre-lb",{label:"sre-lb",pub:"LBKEY"}],
  ["sre-lb-standby",{label:"sre-lb-standby",pub:"SBKEY"}],
]);
const spokes=[{oid:"sre-lb",iface:"wg1"},{oid:"sre-lb-standby",iface:"wg1"}];
// The label contains "sre-lb", which is also a prefix of "sre-lb-standby" —
// exactly the ambiguity substring matching cannot resolve.
const stated=attachVips({vips:[{ip:"1.2.3.4",label:"sre-lb DNAT",iface:"wg1",owner:"SBKEY"}]},N,spokes);
const out=[];
out.push([...stated.keys()].join(",")+":"+(stated.get("sre-lb-standby")||[{}])[0].guessed);
vipFocusNodes=new Map();
const guessed=attachVips({vips:[{ip:"1.2.3.4",label:"sre-lb DNAT",iface:"wg1"}]},N,spokes);
const g=[...guessed.keys()][0];
out.push(g+":"+guessed.get(g)[0].guessed);
console.log(out.join(" | "));
`)
	// Stated: lands on SBKEY's node and is not marked as a guess.
	// Guessed: lands wherever the longest token matched, and is marked.
	if !strings.HasPrefix(got, "sre-lb-standby:false") {
		t.Errorf("a recorded owner was not honoured: %s", got)
	}
	if !strings.Contains(got, ":true") {
		t.Errorf("the fallback was not marked as a guess: %s", got)
	}
}

// The legend has to separate recorded from inferred, or the shapes carry a
// distinction nothing explains.
func TestDashboardLegendSeparatesRecordedFromInferred(t *testing.T) {
	page := string(wgServeHTML)
	for _, want := range []string{">recorded<", ">inferred<", "conf i.hollow"} {
		if !strings.Contains(page, want) {
			t.Errorf("the confidence legend does not carry %q", want)
		}
	}
}
