package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runModelJS evaluates the caller's assertions with wg_model.js in scope.
//
// The state machine this checks lives in the page, not in Go, and a Go
// reimplementation of it would only prove that the copy agrees with itself. The
// interesting failure — "down" meaning three different things — is in the
// browser, so that is where it has to be exercised.
//
// This used to cut the <script> block out of wg_serve.html with a regular
// expression and evaluate it against a hand-built stub DOM. The stub had to grow
// a new method every time the page reached for something new, and it could only
// reach the functions that happened to touch no document at all — which is why
// the focus rules, the ones that kept being got wrong, had no unit test. The
// model is a file now, so this is require().
//
// Skips when node is unavailable rather than failing: this asserts on the shipped
// asset, and a machine without node can still build and test everything else.
func runModelJS(t *testing.T, body string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping dashboard model test")
	}
	model, err := filepath.Abs("wg_model.js")
	if err != nil {
		t.Fatalf("locate wg_model.js: %v", err)
	}
	// Spread onto the global scope so a test body reads the way the page does:
	// hopKey(...), not M.hopKey(...).
	script := fmt.Sprintf("Object.assign(globalThis, require(%q));\n%s", model, body)
	path := filepath.Join(t.TempDir(), "check.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// The page is served as one document, so the two script files have to end up
// inside it. A missing tag would leave the browser asking for wg_model.js on a
// route the server does not have, and the dashboard would come up blank with
// nothing in the Go tests to say why.
func TestDashboardPageInlinesItsScripts(t *testing.T) {
	page := string(wgServeHTML)
	if strings.Contains(page, "<script src=") {
		t.Error("the served page still points at a script file; the inlining did not happen")
	}
	// A function from each file, so a silently-empty embed is caught too.
	for _, want := range []string{"function focusVerdict", "function drawZones"} {
		if !strings.Contains(page, want) {
			t.Errorf("the served page is missing %q", want)
		}
	}
	// Inlining is a text splice, so a "</script>" inside the JS would end the
	// block early and drop the rest of the file into the document as markup.
	for name, body := range map[string]string{"wg_model.js": wgModelJS, "wg_view.js": wgViewJS} {
		if strings.Contains(body, "</script") {
			t.Errorf("%s contains a closing script tag; inlining it would truncate the page", name)
		}
	}
}

// TestDashboardPageDump writes the page exactly as `vctl wg serve` sends it,
// where scripts/wg-dashboard-check.mjs can drive it under a real browser.
// Skipped unless asked for, so normal runs and CI stay unaffected.
//
//	WG_PAGE_OUT=/tmp/dashboard.html go test ./internal/cli/ -run TestDashboardPageDump
//
// The check script used to splice the three files together itself, which meant
// it measured a page resembling the served one rather than the served one. This
// hands it the real bytes, the way TestWGDashboardFixtureDump hands it a real
// topology.
func TestDashboardPageDump(t *testing.T) {
	out := os.Getenv("WG_PAGE_OUT")
	if out == "" {
		t.Skip("WG_PAGE_OUT not set")
	}
	if err := os.WriteFile(out, wgServeHTML, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %d bytes", len(wgServeHTML))
}

// A failed poll must outrank the last sample. Whatever that sample said, the
// current state is unknown — rendering the stale value as fact is how a dead
// gateway reads as healthy.
func TestDashboardStateSeparatesTheSixCases(t *testing.T) {
	got := runModelJS(t, `
const cases={
  active:  {edge:{id:"e",a:{host:"h"}}, stats:{e:{hs:30,sides:{h:{at:995}}}}, errs:{}},
  idle:    {edge:{id:"e",a:{host:"h"}}, stats:{e:{hs:900,sides:{h:{at:995}}}}, errs:{}},
  never:   {edge:{id:"e",a:{host:"h"}}, stats:{e:{hs:-1,sides:{h:{at:995}}}}, errs:{}},
  stale:   {edge:{id:"e",a:{host:"h"}}, stats:{e:{hs:30,sides:{h:{at:100}}}}, errs:{}},
  unknown: {edge:{id:"e",a:{host:"h"}}, stats:{}, errs:{}},
  error:   {edge:{id:"e",a:{host:"h"}}, stats:{e:{hs:30,sides:{h:{at:995}}}}, errs:{h:"ssh timeout"}},
};
const out=[];
for(const want in cases){
  const c=cases[want];
  // The frame is an argument now, so no case can leak into the next one.
  const got=tunnelState(c.edge,{stats:c.stats,pollErrors:c.errs,at:1000});
  out.push(got===want?"":want+"→"+got);
}
console.log(out.filter(Boolean).join(",")||"OK");
`)
	if got != "OK" {
		t.Errorf("state machine disagrees: %s", got)
	}
}

// The summary used to count Object.values(stats) — only tunnels a poll reached.
// A fleet with 12 of 30 observed and all 12 fine rendered as "12 active", with
// the other 18 missing from both the numerator and the denominator. Absence was
// the one thing the screen could not say.
func TestDashboardSummaryCountsUnobservedTunnels(t *testing.T) {
	got := runModelJS(t, `
const edges=[];
for(let i=0;i<30;i++)edges.push({id:"e"+i,a:{host:"h"+i}});
const stats={};
for(let i=0;i<12;i++)stats["e"+i]={hs:30,sides:{["h"+i]:{at:995}}};
const n=countStates(edges,{stats,pollErrors:{},at:1000});
console.log(liveSummary(n,edges.length).text);
`)
	if !strings.Contains(got, "12/30") {
		t.Errorf("summary does not report coverage: %q", got)
	}
	if !strings.Contains(got, "18 unobserved") {
		t.Errorf("summary hides the 18 tunnels nothing reported: %q", got)
	}
}

// Every state must have a colour class, or a state added later silently renders
// as whatever the map's default happens to be.
func TestDashboardStatesAllHaveAColour(t *testing.T) {
	got := runModelJS(t, `
console.log(TUNNEL_STATES.filter(s=>!STATE_CLS[s]).join(",")||"OK");
`)
	if got != "OK" {
		t.Errorf("states with no colour class: %s", got)
	}
}

// The legend names each state, because the summary uses those words. A key that
// still said only active/idle/down would leave three of them unexplained.
//
// The check is also stronger than naming the six: a state nobody is in stays out
// of the key, which is what makes its presence worth reading.
func TestDashboardLegendNamesEveryState(t *testing.T) {
	got := runModelJS(t, `
const all={}; for(const s of TUNNEL_STATES)all[s]=1;
console.log(JSON.stringify([stateKeyHTML(all),stateKeyHTML({active:3})]));
`)
	for _, want := range []string{">active ", ">idle ", ">never ", ">stale ", ">unobserved ", ">poll error "} {
		if !strings.Contains(got, want) {
			t.Errorf("the status key does not name %q", want)
		}
	}
	if strings.Contains(got, ">down") {
		t.Error(`the key still says "down"; that word stood for three different states`)
	}
	// The second call is a fleet in one state, so it names that one and no other.
	rows := strings.Split(got, `","`)
	if len(rows) != 2 {
		t.Fatalf("expected two rendered keys, got %q", got)
	}
	if !strings.Contains(rows[1], "active 3") {
		t.Errorf("a fleet of active tunnels does not say so: %q", rows[1])
	}
	for _, absent := range []string{"idle", "never", "stale", "unobserved", "poll error"} {
		if strings.Contains(rows[1], ">"+absent) {
			t.Errorf("the key lists %q for a fleet that is not in it: %q", absent, rows[1])
		}
	}
}

// Component kinds are a legend too, and the same rule holds: it names the kinds
// that were drawn, not the kinds the renderer knows how to draw.
//
// This half — given a set of kinds, name those and no others — is the filter.
// That the set really comes off the canvas is a property of the drawn SVG, and
// scripts/wg-dashboard-check.mjs asserts it there.
func TestDashboardKindKeyNamesOnlyWhatWasDrawn(t *testing.T) {
	got := runModelJS(t, `
console.log(kindKeyHTML(new Set(["k-gateway","k-vm"])));
`)
	for _, want := range []string{"gateway", "VM"} {
		if !strings.Contains(got, want) {
			t.Errorf("the kind key does not name %q: %q", want, got)
		}
	}
	for _, absent := range []string{"physical host", "routed network", "unresolved endpoint"} {
		if strings.Contains(got, absent) {
			t.Errorf("the kind key names %q, which nothing on the canvas is: %q", absent, got)
		}
	}
}

// Both themes define every token. A colour defined in one and missing from the
// other inherits whatever the other theme left behind, which is the failure this
// shape exists to prevent — and it shows up as one unreadable element rather
// than as anything that looks like a bug.
func TestDashboardDefinesEveryColourInBothThemes(t *testing.T) {
	page, err := os.ReadFile("wg_serve.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	dark := s[strings.Index(s, `:root,[data-theme="dark"]`):strings.Index(s, `[data-theme="light"]`)]
	light := s[strings.Index(s, `[data-theme="light"]`):strings.Index(s, "*{box-sizing")]
	tokenRe := regexp.MustCompile(`(--[a-z0-9-]+)\s*:`)
	seen := map[string]bool{}
	for _, m := range tokenRe.FindAllStringSubmatch(dark, -1) {
		seen[m[1]] = true
	}
	for name := range seen {
		if !strings.Contains(light, name+":") {
			t.Errorf("%s is defined for dark and not for light", name)
		}
	}
	if len(seen) < 20 {
		t.Errorf("only %d tokens found; the theme block moved and this test is not reading it", len(seen))
	}
	// And nothing paints outside them.
	literal := regexp.MustCompile(`(?m)^[^-\n]*(?:fill|stroke|color|background(?:-color)?)\s*:\s*(#[0-9a-fA-F]{3,6}|rgba?\()`)
	for _, line := range strings.Split(s[strings.Index(s, "*{box-sizing"):strings.Index(s, "</style>")], "\n") {
		if literal.MatchString(line) {
			t.Errorf("a literal colour outside the theme tokens: %s", strings.TrimSpace(line))
		}
	}
}

// A VIP naming any interface — not just the first — must match exactly.
func TestDashboardVipMatchesAnyInterfaceKey(t *testing.T) {
	got := runModelJS(t, `
const N=new Map([["lb",{label:"lb",pub:"KPERSONAL",ifaces:[{name:"wg-personal",pub:"KPERSONAL"},{name:"wg1",pub:"KWG1"}]}]]);
const spokes=[{oid:"lb",iface:"wg1"}];
// Names the SECOND interface's key, which the node-level key alone would miss.
const {vipsBy}=attachVips({vips:[{ip:"1.2.3.4",label:"unrelated text",iface:"wg1",owner:"KWG1"}]},N,spokes);
const v=(vipsBy.get("lb")||[])[0];
console.log(v?String(v.guessed):"unmatched");
`)
	if got != "false" {
		t.Errorf("a VIP naming the second interface was %q, want an exact match (false)", got)
	}
}

// Two clocks, deliberately. Structure comes from the last `vctl wg sync`; only
// traffic and handshake come from live polling. One "Updated" made a six-day-old
// graph look current, because the page kept animating.
func TestDashboardSeparatesTopologyAndTelemetryClocks(t *testing.T) {
	page := string(wgServeHTML)
	for _, want := range []string{
		`id="topology-at"`, // structural age, from collectedAt
		`id="updated-at"`,  // live poll time
		">Topology<",
		">Telemetry<",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard does not carry %q", want)
		}
	}
	// The old single-clock label would put the two facts back under one word.
	if strings.Contains(page, ">Updated<") {
		t.Error(`the dashboard still labels a clock "Updated"; that is the ambiguity this removes`)
	}
	// And the structural clock actually ages. This used to be a grep for
	// "collectedAt" and "TOPOLOGY_STALE_SECONDS" in the page source, which would
	// have passed on a page that computed the age and never showed it.
	got := runModelJS(t, `
const day=86400e3, now=Date.parse("2026-08-08T00:00:00Z");
console.log(JSON.stringify([
  topologyClock("2026-08-07T23:40:00Z",now).stale,
  topologyClock("2026-08-02T00:00:00Z",now).stale,
  topologyClock("",now).text,
]));
`)
	if want := `[false,true,"never"]`; got != want {
		t.Errorf("topology clock = %s, want %s", got, want)
	}
}

// The page has to name the peers and say what to run. A count with no next step
// leaves the reader with a number and no action.
func TestDashboardDriftPanelSaysWhatToRun(t *testing.T) {
	got := runModelJS(t, `
console.log(driftText([{host:"gw-a",iface:"wg0",pub:"ABCDEFGHIJKLMNOP",endpoint:"203.0.113.9:51820",allowed:["10.9.0.0/24"]}]));
`)
	for _, want := range []string{"not in this snapshot", "gw-a/wg0", "203.0.113.9:51820", "10.9.0.0/24", "vctl wg sync"} {
		if !strings.Contains(got, want) {
			t.Errorf("drift panel does not mention %q:\n%s", want, got)
		}
	}
}

// Nothing to report means nothing on screen.
func TestDashboardDriftPanelIsEmptyWithNoDrift(t *testing.T) {
	got := runModelJS(t, `console.log(JSON.stringify(driftText([])));`)
	if got != `""` {
		t.Errorf("drift panel rendered %s with nothing to report", got)
	}
}

// A stated owner attaches exactly; a missing one falls back to label text and is
// marked. Substring matching on two human-typed strings attaches a VIP to the
// wrong endpoint when one label contains another's prefix, and the screen could
// not say which had happened.
func TestDashboardVipPrefersTheRecordedOwner(t *testing.T) {
	got := runModelJS(t, `
const N=new Map([
  ["sre-lb",{label:"sre-lb",pub:"LBKEY"}],
  ["sre-lb-standby",{label:"sre-lb-standby",pub:"SBKEY"}],
]);
const spokes=[{oid:"sre-lb",iface:"wg1"},{oid:"sre-lb-standby",iface:"wg1"}];
// The label contains "sre-lb", which is also a prefix of "sre-lb-standby" —
// exactly the ambiguity substring matching cannot resolve.
const stated=attachVips({vips:[{ip:"1.2.3.4",label:"sre-lb DNAT",iface:"wg1",owner:"SBKEY"}]},N,spokes).vipsBy;
const out=[];
out.push([...stated.keys()].join(",")+":"+(stated.get("sre-lb-standby")||[{}])[0].guessed);
// A second call must not inherit the first one's focus entries. attachVips used
// to write vipFocusNodes into the enclosing scope, so it did.
const guessed=attachVips({vips:[{ip:"1.2.3.4",label:"sre-lb DNAT",iface:"wg1"}]},N,spokes).vipsBy;
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

// An interface is (host, name), never a name.
//
// wg3 on the hub and wg3 on the Seoul gateway are two interfaces on two
// machines. The operations ledger warns about the same trap from the other
// side: three separate nodes are called wireguard-gw-incheon.
//
// hopKey used to qualify a hop only when its name collided with one of the
// hub's, which merged two hops that shared a name with each other, and made
// whether a hop was qualified at all depend on how somebody had named an
// interface on a different node.
func TestAHopInterfaceIsIdentifiedByItsHostNotOnlyItsName(t *testing.T) {
	got := runModelJS(t, `
const hub={id:"hub",ifaces:[{name:"wg0"},{name:"wg3"}]};
const out=[
  // hub-adjacent: one hub, so the bare name cannot be ambiguous
  hopKey({source:"hub",target:"gw-a",iface:"wg3"},hub),
  // a hop whose name collides with a hub interface
  hopKey({source:"gw-a",target:"x",iface:"wg3"},hub),
  // a hop whose name collides with another hop and NOT with the hub —
  // this is the one that used to merge
  hopKey({source:"gw-a",target:"y",iface:"wg-seoul"},hub),
  hopKey({source:"gw-b",target:"z",iface:"wg-seoul"},hub),
];
console.log(JSON.stringify(out));
`)
	want := `["wg3","gw-a/wg3","gw-a/wg-seoul","gw-b/wg-seoul"]`
	if got != want {
		t.Errorf("hop keys = %s, want %s", got, want)
	}
}

// The chip says the short name while it still picks out one interface, and
// grows the host back the moment two chips would read the same. A legend that
// prints two different interfaces under one word is worse than a long word.
func TestAFilterChipGrowsItsHostOnlyWhenItWouldBeAmbiguous(t *testing.T) {
	got := runModelJS(t, `
const keys=["wg0","wg3","gw-a/wg3","gw-a/wg-seoul","gw-b/wg-personal"];
console.log(JSON.stringify(keys.map(k=>ifLabel(k,keys))));
`)
	// wg3 appears bare (the hub's) and as gw-a/wg3, so the qualified one keeps
	// its host. wg-seoul and wg-personal are unique, so they stay short.
	want := `["wg0","wg3","gw-a/wg3","wg-seoul","wg-personal"]`
	if got != want {
		t.Errorf("labels = %s, want %s", got, want)
	}
}

// The local-fabric lane is decided by the wire, not by an operator's label.
//
// AllowedIPs describe what the far side of a tunnel accepts, so the hub's own
// ranges appear in the lists the other gateways advertise. Reading every edge
// would mark the hub's own fabric as remote and empty the lane; only edges
// leaving the hub say what the hub reaches through a peer.
func TestARangeReachedOverATunnelIsNotTheHubsOwnFabric(t *testing.T) {
	got := runModelJS(t, `
const hub={id:"hub",dc:"incheon"};
const topo={edges:[
  // what the hub reaches through its peers — remote, whatever a label says
  {source:"hub",target:"seoul-gw",allowed:"10.0.90.1/32, 192.168.201.0/24"},
  {source:"hub",target:"sre-lb",  allowed:"192.168.110.0/24, 192.168.130.0/24"},
  // the far side advertising a route back to the hub's own range: this must
  // NOT make the hub's fabric look remote
  {source:"seoul-gw",target:"hub",allowed:"10.0.90.2/32, 192.168.10.0/24"},
]};
console.log(JSON.stringify([...reachedOverATunnel(topo,hub)].sort()));
`)
	// cidrs() drops /32 host routes; a single address is not a network.
	want := `["192.168.110.0/24","192.168.130.0/24","192.168.201.0/24"]`
	if got != want {
		t.Errorf("reached over a tunnel = %s, want %s", got, want)
	}
}
