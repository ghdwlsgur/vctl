package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scriptRe pulls the dashboard's script body out of the page so it can be run.
var scriptRe = regexp.MustCompile(`(?s)<script>(.*)</script>`)

// runDashboardJS evaluates the dashboard's own script under node with a stub DOM,
// then runs the caller's assertions against it.
//
// The state machine this checks lives in the page, not in Go, and a Go
// reimplementation of it would only prove that the copy agrees with itself. The
// interesting failure — "down" meaning three different things — is in the
// browser, so that is where it has to be exercised.
//
// Skips when node is unavailable rather than failing: this asserts on the shipped
// asset, and a machine without node can still build and test everything else.
func runDashboardJS(t *testing.T, body string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping dashboard script test")
	}
	page, err := os.ReadFile("wg_serve.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	m := scriptRe.FindStringSubmatch(string(page))
	if m == nil {
		t.Fatal("no <script> block in the dashboard")
	}
	// The script touches the DOM at load. Stub only what it reaches before the
	// functions under test — enough to evaluate, not a DOM implementation.
	const stub = `
globalThis.window=globalThis;
const el=()=>({textContent:"",className:"",title:"",style:{},dataset:{},innerHTML:"",
  setAttribute(){},getAttribute(){return null},appendChild(){},addEventListener(){},
  classList:{add(){},remove(){},contains(){return false}},
  querySelector(){return el()},querySelectorAll(){return []},getBoundingClientRect(){return{width:800,height:600}}});
globalThis.document={getElementById:el,querySelector:()=>el(),querySelectorAll:()=>[],
  addEventListener(){},createElementNS:el,createElement:el,documentElement:el(),body:el()};
globalThis.getComputedStyle=()=>({getPropertyValue:()=>"#fff"});
globalThis.EventSource=function(){this.onmessage=null};
// A promise that never settles: the page's live path must not run here, but its
// chain has to type-check all the way through .then().then().catch().
const pending={then(){return pending},catch(){return pending}};
globalThis.fetch=()=>pending;
globalThis.WG_BOOT=null;
`
	dir := t.TempDir()
	path := filepath.Join(dir, "check.mjs")
	if err := os.WriteFile(path, []byte(stub+m[1]+"\n"+body), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := exec.Command(node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// A failed poll must outrank the last sample. Whatever that sample said, the
// current state is unknown — rendering the stale value as fact is how a dead
// gateway reads as healthy.
func TestDashboardStateSeparatesTheSixCases(t *testing.T) {
	got := runDashboardJS(t, `
frameAt=1000;
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
  stats=c.stats; pollErrors=c.errs;
  const got=tunnelState(c.edge);
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
	got := runDashboardJS(t, `
frameAt=1000;
const edges=[];
for(let i=0;i<30;i++)edges.push({id:"e"+i,a:{host:"h"+i}});
curTopo={edges};
stats={}; pollErrors={};
for(let i=0;i<12;i++)stats["e"+i]={hs:30,sides:{["h"+i]:{at:995}}};
let text="";
document.getElementById=()=>({className:"",title:"",querySelector:()=>({set textContent(v){text=v}})});
applyStats();
console.log(text);
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
	got := runDashboardJS(t, `
console.log(TUNNEL_STATES.filter(s=>!STATE_CLS[s]).join(",")||"OK");
`)
	if got != "OK" {
		t.Errorf("states with no colour class: %s", got)
	}
}

// The legend names each state, because the summary uses those words. A key that
// still said only active/idle/down would leave three of them unexplained.
func TestDashboardLegendNamesEveryState(t *testing.T) {
	page, err := os.ReadFile("wg_serve.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	for _, want := range []string{">active<", ">idle<", ">never<", ">stale<", ">unobserved<", ">poll error<"} {
		if !strings.Contains(s, want) {
			t.Errorf("the status key does not name %q", want)
		}
	}
	if strings.Contains(s, ">down<") {
		t.Error(`the key still says "down"; that word stood for three different states`)
	}
}
