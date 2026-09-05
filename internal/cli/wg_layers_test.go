package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runLayersJS evaluates the caller's assertions with wg_model.js and
// wg_layers.js in scope. The layout is geometry over the topology and never
// touches the document, so it is exercised the way the model is: under node,
// against a fixture, skipping where node is absent.
func runLayersJS(t *testing.T, body string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping layers view test")
	}
	model, err := filepath.Abs("wg_model.js")
	if err != nil {
		t.Fatalf("locate wg_model.js: %v", err)
	}
	layers, err := filepath.Abs("wg_layers.js")
	if err != nil {
		t.Fatalf("locate wg_layers.js: %v", err)
	}
	script := fmt.Sprintf("Object.assign(globalThis, require(%q));\nObject.assign(globalThis, require(%q));\n%s", model, layers, body)
	path := filepath.Join(t.TempDir(), "layers.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// layersFixtureJS is two sites, one farm, a collected gateway on a host, a
// declared VM on the same host with an unsynced tunnel, a farm network, a
// site-level network, an edge, and a client nobody placed. Example ranges only.
const layersFixtureJS = `
const topo = { nodes: [
  {id:"site/a",kind:"site",label:"A",layer:"underlay"},
  {id:"site/b",kind:"site",label:"B",layer:"underlay"},
  {id:"farm/x",kind:"farm",label:"x",dc:"a",layer:"underlay"},
  {id:"host|h1",kind:"physical-host",label:"h1",dc:"a",layer:"underlay",ip:"203.0.113.1"},
  {id:"host|h9",kind:"physical-host",label:"h9",dc:"b",layer:"underlay"},
  {id:"gw1",kind:"gateway",label:"gw1",dc:"a",parent:"host|h1",layer:"overlay",ifaces:[{name:"wg0"}]},
  {id:"vm/v2",kind:"vm",label:"v2",dc:"a",layer:"underlay"},
  {id:"tunnel/t2/wg0",kind:"tunnel",label:"t2",dc:"a",layer:"overlay",attrs:{host:"v2",iface:"wg0"}},
  {id:"net/x/tenant",kind:"network",label:"tenant",dc:"a",layer:"underlay",attrs:{cidr:"192.0.2.0/24"}},
  {id:"net/b/lan",kind:"network",label:"lan",dc:"b",layer:"underlay",attrs:{cidr:"198.51.100.0/24"}},
  {id:"edge/fw",kind:"edge",label:"fw",dc:"a",layer:"underlay"},
  {id:"ext|k1",kind:"device",label:"laptop",dc:"b",layer:"overlay"},
  {id:"gw9",kind:"gateway",label:"gw9",dc:"b",layer:"underlay",ifaces:[{name:"wg1"}]},
], links: [
  {source:"gw9",target:"site/b",kind:"member-of"},
  {source:"farm/x",target:"site/a",kind:"member-of"},
  {source:"host|h1",target:"farm/x",kind:"member-of"},
  {source:"host|h9",target:"site/b",kind:"member-of"},
  {source:"vm/v2",target:"host|h1",kind:"placed-on"},
  {source:"edge/fw",target:"site/a",kind:"member-of"},
  {source:"gw1",target:"net/b/lan",kind:"carries",attrs:{method:"direct",snat_at:"gw1",oif:["eth0"]}},
  {source:"gw1",target:"edge/fw",kind:"transits",attrs:{order:1}},
], edges: [{id:"e1",source:"gw1",target:"ext|k1",iface:"wg0",allowed:"10.0.0.2/32"}],
  derived: { failure_domains: [{host:"host|h1",label:"h1",farm:"farm/x",site:"a",dependents:["gw1","vm/v2"],tunnels:["gw1"],carries:1}],
    paths: [{network:"net/b/lan",cidr:"198.51.100.0/24",tunnel:"gw1",method:"direct",snat_at:"gw1",hops:["gw1","host|h1","farm/x","site/a","edge/fw","net/b/lan"]}],
    snat: [{at:"gw1",tunnel:"gw1",network:"net/b/lan",oif:["eth0"]}], gaps: [{kind:"uncollected-tunnel",subject:"tunnel/t2/wg0"}] } };
`

// Placement is the whole claim of the view: what the database says sits on what
// is what the picture nests. A host inside its farm, a gateway and an unsynced
// tunnel inside their host, a farm network inside the farm, a site network in
// its site, and an unplaced client in that site's tray — none of it by name.
func TestLayersLayoutNestsByDeclaredPlacement(t *testing.T) {
	out := runLayersJS(t, layersFixtureJS+`
const L = layersLayout(topo);
const inside = (a, b) => a.x >= b.x && a.y >= b.y && a.x + a.w <= b.x + b.w && a.y + a.h <= b.y + b.h;
const p = id => { const q = L.pos.get(id); if (!q) throw new Error("no position for " + id); return q; };
console.log(JSON.stringify({
  columns: L.columns.map(c => c.site),
  hostInFarm: inside(p("host|h1"), p("farm/x")),
  gwInHost: inside(p("gw1"), p("host|h1")),
  tunnelInHost: inside(p("tunnel/t2/wg0"), p("host|h1")),
  netInFarm: inside(p("net/x/tenant"), p("farm/x")),
  siteNet: L.siteOf.get("net/b/lan"),
  chipSite: L.siteOf.get("edge/fw"),
  laptopTray: !!p("ext|k1").tray && L.siteOf.get("ext|k1") === "site/b",
  gw9Machine: !!p("gw9").machine && L.columns.some(c => c.site === "site/b" && c.hostBoxes.includes("gw9")),
  unpositioned: topo.nodes.filter(n => n.kind !== "site" && !L.pos.has(n.id)).map(n => n.id),
  sized: L.W > 0 && L.H > 0,
}));`)
	var got struct {
		Columns                                              []string
		HostInFarm, GwInHost, TunnelInHost, NetInFarm, Sized bool
		SiteNet, ChipSite                                    string
		LaptopTray, Gw9Machine                               bool
		Unpositioned                                         []string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse layout report %q: %v", out, err)
	}
	if strings.Join(got.Columns, ",") != "site/a,site/b" {
		t.Errorf("columns = %v, want the two declared sites in order", got.Columns)
	}
	for name, ok := range map[string]bool{"host in farm": got.HostInFarm, "gateway in host": got.GwInHost, "unsynced tunnel in host": got.TunnelInHost, "farm network in farm": got.NetInFarm, "laptop in site b tray": got.LaptopTray, "standalone gateway as machine box": got.Gw9Machine, "sized": got.Sized} {
		if !ok {
			t.Errorf("%s: not nested where the declaration puts it", name)
		}
	}
	if got.SiteNet != "site/b" || got.ChipSite != "site/a" {
		t.Errorf("site-level placement: net/b/lan → %q (want site/b), edge/fw → %q (want site/a)", got.SiteNet, got.ChipSite)
	}
	if len(got.Unpositioned) != 0 {
		t.Errorf("nodes left without a position: %v", got.Unpositioned)
	}
}

// renderLayers runs against a stub document here only to catch what the
// layout test cannot: a draw call that reaches for a field the topology does
// not have, or a tooltip thunk that returns the wrong shape for hot().
func TestLayersRenderDrawsEveryDeclaredPattern(t *testing.T) {
	out := runLayersJS(t, layersFixtureJS+`
const mkEl = tag => ({ tag, attrs: {}, children: [], _text: "", _html: "",
  classList: { add() {}, contains() { return false } }, dataset: {}, style: {},
  setAttribute(k, v) { this.attrs[k] = String(v) }, appendChild(c) { this.children.push(c); return c },
  addEventListener() {}, get firstChild() { return this.children[0] },
  set textContent(v) { this._text = String(v) }, get textContent() { return this._text },
  set innerHTML(v) { this._html = String(v); this.children = [] }, get innerHTML() { return this._html } });
let created = 0, sized = null;
const H = {
  mk: (t, a, p) => { const e = mkEl(t); for (const k in a) e.setAttribute(k, a[k]); if (p) p.appendChild(e); created++; return e },
  hot: (el, fn) => { const r = fn(); if (!Array.isArray(r) || typeof r[0] !== "string" || typeof r[1] !== "string") throw new Error("tooltip must be [title, meta]: " + JSON.stringify(r)) },
  esc: s => String(s ?? ""), cssv: () => "#000", ifColor: () => "#fff", sizeCanvas: (w, h) => { sized = [w, h] }, kindLabel: k => k,
};
const count = (el, cls) => (el.attrs.class || "").split(" ").includes(cls) + el.children.reduce((n, c) => n + count(c, cls), 0);
const svg = mkEl("svg"), aside = mkEl("aside");
renderLayers(svg, aside, topo, H);
console.log(JSON.stringify({ created, sized: !!sized, viewBox: svg.attrs.viewBox || "",
  carries: count(svg, "ly-carry"), tunnels: count(svg, "ly-wire"), transits: count(svg, "ly-transit"), snat: count(svg, "ly-snat"),
  hosts: count(svg, "ly-host"), nets: count(svg, "ly-net"), unsynced: count(svg, "ly-unsynced"),
  aside: aside.innerHTML.includes("Failure domains") && aside.innerHTML.includes("uncollected-tunnel") }));`)
	var got struct {
		Created                                                 int
		Sized, Aside                                            bool
		ViewBox                                                 string
		Carries, Tunnels, Transits, Snat, Hosts, Nets, Unsynced int
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("parse render report %q: %v", out, err)
	}
	if got.Created == 0 || !got.Sized || got.ViewBox == "" {
		t.Fatalf("render produced nothing: %+v", got)
	}
	want := map[string][2]int{"carries": {got.Carries, 1}, "tunnels": {got.Tunnels, 1}, "transits": {got.Transits, 1}, "snat markers": {got.Snat, 1}, "hosts": {got.Hosts, 3}, "networks": {got.Nets, 2}}
	for name, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s drawn = %d, want %d", name, v[0], v[1])
		}
	}
	if got.Unsynced == 0 {
		t.Errorf("the unsynced declared tunnel should be drawn as such")
	}
	if !got.Aside {
		t.Errorf("derived aside should list failure domains and gaps")
	}
}
