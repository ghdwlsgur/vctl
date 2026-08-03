package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The dashboard's filter keys, exercised against a topology shaped like this
// fleet: a hub with wg0/wg1/wg3, remote hosts reusing those names, a VIP whose
// ledger entry names a different host's interface, and two tunnels between
// non-hub nodes.
const filterFixtureJS = `
const topo={
  collectedAt:"2026-08-03T00:00:00Z",
  nodes:[
    {id:"hub",label:"hub",kind:"gateway",dc:"incheon",pub:"KH0",
     ifaces:[{name:"wg0",pub:"KH0"},{name:"wg1",pub:"KH1"},{name:"wg3",pub:"KH3"}]},
    {id:"lb",label:"lb",kind:"gateway",dc:"seoul",pub:"KLB1",
     ifaces:[{name:"wg1",pub:"KLB1"}]},
    {id:"staging",label:"staging",kind:"gateway",dc:"incheon",pub:"KST3",
     ifaces:[{name:"wg3",pub:"KST3"}]},
    {id:"srv32",label:"srv32",kind:"gateway",dc:"incheon",pub:"KS0",
     ifaces:[{name:"wg0",pub:"KS0"}]},
    {id:"ext|a",label:"ext-a",kind:"external"},
    {id:"ext|b",label:"ext-b",kind:"external"}
  ],
  edges:[
    {id:"e-hub-lb",source:"hub",target:"lb",iface:"wg1",allowed:"10.0.1.0/24",
     a:{host:"hub",iface:"wg1",pub:"KH1"},b:{host:"lb",iface:"wg1",pub:"KLB1"}},
    {id:"e-hub-srv32",source:"hub",target:"srv32",iface:"wg0",allowed:"10.0.0.0/24",
     a:{host:"hub",iface:"wg0",pub:"KH0"},b:{host:"srv32",iface:"wg0",pub:"KS0"}},
    // Between two non-hub nodes, on names the hub also uses.
    {id:"e-staging-ext",source:"staging",target:"ext|a",iface:"wg3",allowed:"10.9.0.0/24"},
    {id:"e-srv32-ext",source:"srv32",target:"ext|b",iface:"wg0",allowed:"10.8.0.0/24"}
  ],
  aggs:[],links:[],
  // The ledger names wg3 — an interface the owner does not have. The owner key
  // says otherwise.
  vips:[{ip:"192.0.2.231",label:"lb DNAT (wg3)",iface:"wg3",owner:"KLB1"}]
};
curTopo=topo; vipFocusNodes=new Map();
const {N,E,hub}=prep(topo);
const spokes=[{oid:"lb",iface:"wg1"},{oid:"staging",iface:"wg3"},{oid:"srv32",iface:"wg0"}];
const vipsBy=attachVips(topo,N,spokes);
`

// A VIP is focused by the interface that carries it, not by whatever the ledger's
// free-text wg_tunnel field says.
//
// In this fleet that field names the destination mesh: the o11y VIPs read "wg3",
// which lives on the incheon hub, while they are DNAT'd on sre-lb and leave over
// wg1. Keying on it meant selecting the hub's wg3 lit up sre-lb — a host with no
// wg3 — and selecting the interface that really carries them lit no VIP at all.
func TestFilterVipFollowsItsOwningInterface(t *testing.T) {
	got := runDashboardJS(t, filterFixtureJS+`
const entries=[...vipFocusNodes].map(([k,v])=>k+"="+[...v].join(","));
console.log(entries.sort().join(" "));
`)
	if got != "wg1=lb" {
		t.Errorf("vipFocusNodes = %q, want the VIP keyed by its owner's interface (wg1=lb)", got)
	}
}

func TestFilterHubInterfaceDoesNotLightAHostWithoutIt(t *testing.T) {
	got := runDashboardJS(t, filterFixtureJS+`
console.log([...focusClosure("wg3").nodes].sort().join(","));
`)
	if strings.Contains(got, "lb") {
		t.Errorf("focusing the hub's wg3 selected %q; lb has no wg3", got)
	}
}

// Interface names are per host. When the hub uses the same name, a tunnel
// between two remote hosts is dropped by the hub guard and selected by nothing —
// clicking it dimmed the whole diagram and lit nothing.
func TestFilterScopedKeyReachesATunnelThatAvoidsTheHub(t *testing.T) {
	got := runDashboardJS(t, filterFixtureJS+`
console.log(JSON.stringify({
  bare:[...focusClosure("wg3").edges].sort(),
  scoped:[...focusClosure("staging/wg3").edges].sort(),
}));
`)
	var out struct{ Bare, Scoped []string }
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", got, err)
	}
	// The hub guard keeps the bare name meaning "the hub's wg3 world", so it must
	// not reach a tunnel between two remote hosts.
	if slices.Contains(out.Bare, "e-staging-ext") {
		t.Errorf("the bare hub name selected a tunnel that avoids the hub: %v", out.Bare)
	}
	if len(out.Scoped) != 1 || out.Scoped[0] != "e-staging-ext" {
		t.Errorf("scoped key selected %v, want just the staging tunnel", out.Scoped)
	}
}

// Scoping is only for names that collide. A unique name stays plain, so the
// common case reads unchanged.
func TestFilterScopesOnlyCollidingNames(t *testing.T) {
	got := runDashboardJS(t, filterFixtureJS+`
const keys=topo.edges.map(e=>hopKey(e,hub)).sort();
console.log(JSON.stringify(keys));
`)
	for _, want := range []string{`"staging/wg3"`, `"srv32/wg0"`} {
		if !strings.Contains(got, want) {
			t.Errorf("colliding hop was not scoped; keys = %s", got)
		}
	}
	// Hub-attached tunnels keep the plain name.
	if !strings.Contains(got, `"wg1"`) || !strings.Contains(got, `"wg0"`) {
		t.Errorf("hub-attached tunnels lost their plain names; keys = %s", got)
	}
}

// Every drawn tunnel must be selectable by some key, or the diagram offers a
// control that does nothing for it.
func TestFilterEveryEdgeIsReachable(t *testing.T) {
	got := runDashboardJS(t, filterFixtureJS+`
const keys=new Set(topo.edges.map(e=>hopKey(e,hub)));
const reach=new Set();
for(const k of keys)for(const id of focusClosure(k).edges)reach.add(id);
console.log(topo.edges.filter(e=>!reach.has(e.id)).map(e=>e.id).join(",")||"OK");
`)
	if got != "OK" {
		t.Errorf("tunnels no filter can select: %s", got)
	}
}
