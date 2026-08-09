#!/usr/bin/env node
// What the WireGuard dashboard actually draws, measured in a real browser.
//
//   node scripts/wg-dashboard-check.mjs              # fixture from the Go test
//   node scripts/wg-dashboard-check.mjs --topology /tmp/topo.json
//   node scripts/wg-dashboard-check.mjs --keep       # leave the built page on disk
//
// This exists because the interesting failures in this page are not in what its
// functions return — they are in what is left on the screen afterwards, and the
// Go tests cannot see that. Every one of them was found by building a throwaway
// harness: dump a topology, splice it into the HTML, open it under headless
// Chrome, dump the DOM, read it. That got rebuilt from memory each time, slightly
// differently, and twice it measured the wrong thing and sent a fix the wrong way.
//
// Two conditions were rediscovered by hand every round and are now stated here
// rather than remembered:
//
//   Stats have to be present. The bug where a filtered-out bead kept its glow
//   only existed while applyStats was running — it wrote the drop-shadow as an
//   inline style every two seconds, which outranked the .dim class rule. A
//   replay with no stats never called that code, so the harness came back clean
//   on a page that was visibly wrong.
//
//   Elements that are not rendered must be excluded and counted. #errs, #drift,
//   #selection and the empty status keys are display:none until they have
//   something to say, and .flow paths sit at opacity 0 until traffic turns them
//   on. Measuring their computed style answers a question nobody asked, and a
//   check that silently skipped them read the same as a check that passed.
//
// Exits non-zero when a check fails, so it can be run in anger.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const argOf = name => { const i = args.indexOf(name); return i < 0 ? null : args[i + 1]; };
const KEEP = args.includes("--keep");

// ---------- chrome ----------
function findChrome() {
  const candidates = [
    process.env.CHROME,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium", "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

// ---------- topology ----------
// The fixture is the one the Go tests already keep honest:
// internal/wireguard/wg_fixture_test.go asserts it still satisfies every
// renderer branch's precondition, so a layout path cannot quietly stop being
// exercised here without that test going red first.
function loadTopology() {
  const given = argOf("--topology");
  if (given) return JSON.parse(readFileSync(given, "utf8"));
  const out = join(mkdtempSync(join(tmpdir(), "wg-fixture-")), "topology.json");
  execFileSync("go", ["test", "./internal/wireguard/", "-run", "TestWGDashboardFixtureDump", "-count=1"],
    { cwd: ROOT, env: { ...process.env, WG_FIXTURE_OUT: out }, stdio: "pipe" });
  return JSON.parse(readFileSync(out, "utf8"));
}

// ---------- the poll frame ----------
// One frame that puts the fleet into every state at once, so a single render can
// be measured against all six. The clock is fixed and the sample times are
// relative to it: "stale" means a sample older than POLL_STALE_SECONDS, and
// pinning `at` is what makes that reproducible instead of a race with wall time.
const AT = 1780000000;
function frameFor(topo) {
  const edges = {}, errors = {};
  const hostOf = e => (e.a && e.a.host) || (e.b && e.b.host) ||
    [e.source, e.target].find(id => id && !id.includes("|")) || "unknown";
  topo.edges.forEach((e, i) => {
    const host = hostOf(e);
    switch (i % 6) {
      case 0: // active, and carrying traffic — this is what turns the glow on
        edges[e.id] = { hs: 20, rx: 4_000_000, tx: 900_000, sides: { [host]: { at: AT - 2 } } }; break;
      case 1: // idle: polled, handshake is old
        edges[e.id] = { hs: 900, rx: 0, tx: 0, sides: { [host]: { at: AT - 2 } } }; break;
      case 2: // never handshook
        edges[e.id] = { hs: -1, rx: 0, tx: 0, sides: { [host]: { at: AT - 2 } } }; break;
      case 3: // stale: the newest sample for this tunnel has aged out
        edges[e.id] = { hs: 20, rx: 10_000, tx: 10_000, sides: { [host]: { at: AT - 600 } } }; break;
      case 4: break; // unknown: no sample at all, deliberately
      case 5: errors[host] = "ssh: connect: connection refused"; break; // poll error
    }
  });
  const drift = [{
    host: topo.nodes.find(n => n.kind === "gateway")?.id || "gw",
    iface: "wg0", pub: "DRIFTKEY0123456789", endpoint: "203.0.113.9:51820",
    allowed: ["10.99.0.0/24"],
  }];
  return { edges, errors, at: AT, drift };
}

// ---------- the measurement, run inside the page ----------
// Written as a string because it executes in Chrome, not here. It reads the
// drawn SVG and reports facts about it; it deliberately does not re-derive what
// should be lit, because a checker that reimplements focusVerdict only proves
// the copy agrees with itself. Every assertion below is a property that holds
// whatever the focus rules are.
const MEASURE = String.raw`
(function(){
  const out={checks:[],facts:{},fail:[]};
  const ok=(name,pass,detail)=>{out.checks.push({name,pass,detail});if(!pass)out.fail.push(name+": "+detail);};

  const all=[...document.querySelectorAll("#net *")];
  // Not rendered = nothing to look at. display:none ancestors, zero-size boxes.
  // Counted rather than quietly dropped: a measurement over an empty set reads
  // exactly like a measurement that passed.
  const painted=all.filter(el=>el.getClientRects().length>0);
  const unpainted=all.length-painted.length;
  out.facts.elements=all.length;
  out.facts.unpainted=unpainted;
  ok("something was drawn",painted.length>50,painted.length+" painted elements");

  const chips=[...document.querySelectorAll("#legend .i[data-if]")].map(c=>c.dataset.if);
  out.facts.legend=chips;
  ok("the legend offers a filter",chips.length>0,chips.length+" chips");

  // The kind key names the kinds on the canvas and no others. This used to be
  // asserted in Node against a hand-made list of fake elements, which could not
  // fail when the canvas drew something the key did not know about.
  const drawn=new Set();
  for(const el of document.querySelectorAll("#net rect.nbox"))
    for(const c of el.classList)if(c.startsWith("k-"))drawn.add(c);
  const named=[...document.querySelectorAll("#kind-key .kind")]
    .flatMap(s=>[...s.classList]).filter(c=>c.startsWith("k-"));
  out.facts.kinds={drawn:[...drawn].sort(),named:named.sort()};
  ok("the kind key matches the canvas",
    [...drawn].sort().join(",")===named.sort().join(","),
    "canvas "+[...drawn].sort().join(" ")+" / key "+named.sort().join(" "));

  // With stats applied, some tunnel must be animating. If none is, the glow
  // check below is measuring a page where the code that caused the bug never
  // ran — which is how a clean result got reported on a broken screen.
  const flowing=[...document.querySelectorAll("#net .flow.on")].length;
  out.facts.flowing=flowing;
  ok("stats reached the canvas",flowing>0,flowing+" tunnels animating");

  // The glow belongs to the tunnel beads, and only to them. .pdot/.sdot carry
  // drop-shadow(var(--glow)), which applyStats repaints every frame; .dim is
  // supposed to switch it off.
  //
  // .nbox carries a drop-shadow as well and that one is not a glow — it is the
  // card's own shadow, in --node-shadow, and it fades with the box because a
  // filter is applied before opacity. Measuring every filtered element instead
  // of the beads reported eleven failures on a page with nothing wrong, which is
  // the same mistake as measuring a display:none element: an answer to a
  // question nobody asked, in a shape that looks like a finding.
  const isBead=el=>el.classList.contains("pdot")||el.classList.contains("sdot");
  const glowing=el=>{const f=getComputedStyle(el).filter;return f&&f!=="none";};

  // Per-interface focus, measured on the real SVG.
  const perFocus={};
  for(const key of chips){
    setFocus(key);
    const dim=painted.filter(el=>el.classList.contains("dim"));
    const lit=painted.filter(el=>!el.classList.contains("dim"));
    // The bug that kept coming back: a dimmed bead still painting its glow at
    // full strength, so filtering read as "a few dots changed colour".
    const beads=painted.filter(isBead);
    const stillGlowing=dim.filter(isBead).filter(glowing);
    const stillFlowing=dim.filter(el=>el.classList.contains("flow")&&el.classList.contains("on"));
    // A container that dims takes its matched descendants with it.
    const dimmedContainers=dim.filter(el=>el.children.length>0);
    // Chrome is the frame, not the drawing.
    const dimmedChrome=dim.filter(el=>
      ["lanerule","lanehead","zone","zlab","zsub","nat","natlab"].some(c=>el.classList.contains(c)));
    // The selected interface's own geometry must survive its own selection.
    const ownDimmed=dim.filter(el=>el.dataset&&el.dataset.ifc===key);
    // A compact mesh card contains several node rows. If its aggregate group
    // matches one focused edge, unrelated rows still need their own edge/node
    // tags or every peer in the card stays bright.
    const idsByLabel=new Map();
    for(const n of ((curTopo&&curTopo.nodes)||[])){
      const a=idsByLabel.get(n.label)||[];a.push(n.id);idsByLabel.set(n.label,a);
    }
    const foreignNodeLabels=lit.filter(el=>el.tagName&&el.tagName.toLowerCase()==="text")
      .filter(el=>{
        const owner=el.closest("[data-nodes]");if(!owner)return false;
        let owned=[];try{owned=JSON.parse(owner.dataset.nodes||"[]");}catch(_){return false;}
        const candidates=(idsByLabel.get((el.textContent||"").trim())||[]).filter(id=>owned.includes(id));
        return candidates.length>0&&candidates.every(id=>!focus.nodes.has(id));
      });
    // Clean isolation is still wrong if it achieves that by hiding one end of
    // the selected tunnel. Every focused endpoint must retain a visible label.
    // Resolve through data-nodes so duplicate labels in different farms do not
    // accidentally satisfy each other.
    const hubId=(prep(curTopo).hub||{}).id;
    const missingNodeLabels=[...focus.nodes].filter(id=>id!==hubId).filter(id=>{
      const n=(curTopo.nodes||[]).find(x=>x.id===id);if(!n)return true;
      const labels=painted.filter(el=>el.tagName&&el.tagName.toLowerCase()==="text")
        .filter(el=>(el.textContent||"").trim()===n.label)
        .filter(el=>{const owner=el.closest("[data-nodes]");if(!owner)return false;
          try{return JSON.parse(owner.dataset.nodes||"[]").includes(id);}catch(_){return false;}});
      return labels.length===0||labels.every(el=>el.classList.contains("dim"));
    });
    // Placement is part of the tunnel architecture, not optional decoration.
    // A selected VM may live in a far-zone card, a same-site top chip, or a
    // compact mesh row; all three renderers must keep its physical host visible.
    const missingParentLabels=[...focus.nodes].filter(id=>id!==hubId).flatMap(id=>{
      const n=(curTopo.nodes||[]).find(x=>x.id===id);if(!n||!n.parent)return [];
      const parent=(curTopo.nodes||[]).find(x=>x.id===n.parent);if(!parent)return [n.parent];
      const labels=painted.filter(el=>el.tagName&&el.tagName.toLowerCase()==="text")
        .filter(el=>(el.textContent||"").includes(parent.label))
        .filter(el=>{const owner=el.closest("[data-nodes]");if(!owner)return false;
          try{return JSON.parse(owner.dataset.nodes||"[]").includes(id);}catch(_){return false;}});
      return labels.length===0||labels.every(el=>el.classList.contains("dim"))?[parent.id]:[];
    });
    perFocus[key]={lit:lit.length,dim:dim.length,
      dimmedBeads:dim.filter(isBead).length,glowWhileDim:stillGlowing.length,
      flowWhileDim:stillFlowing.length,
      dimmedContainers:dimmedContainers.length,dimmedChrome:dimmedChrome.length,
      ownDimmed:ownDimmed.length,foreignNodeLabels:foreignNodeLabels.length,
      missingNodeLabels:missingNodeLabels.length,missingParentLabels:missingParentLabels.length};
    ok("focus "+key+" isolates something",dim.length>0,"nothing dimmed");
    ok("focus "+key+" leaves something",lit.length>0,"everything dimmed");
    // A pass here is only worth reading if some bead was actually dimmed. Zero
    // dimmed beads and zero glowing ones look identical in the result.
    ok("focus "+key+" dims some beads",dim.filter(isBead).length>0,
      "no bead dimmed out of "+beads.length+" — the glow check could not fire");
    ok("focus "+key+" dims no glow",stillGlowing.length===0,
      stillGlowing.length+" of "+dim.filter(isBead).length+" dimmed beads still painting a glow: "+
      [...new Set(stillGlowing.map(el=>"."+[...el.classList].join(".")+
        " {"+getComputedStyle(el).filter+"}"))].slice(0,3).join(" | "));
    ok("focus "+key+" stops dimmed flow",stillFlowing.length===0,
      stillFlowing.length+" dimmed flow paths still carry the active class: "+
      stillFlowing.slice(0,3).map(el=>{const s=getComputedStyle(el);return "."+
        [...el.classList].join(".")+" {opacity:"+s.opacity+"; animation:"+s.animationName+"}";
      }).join(" | "));
    ok("focus "+key+" dims no container",dimmedContainers.length===0,
      dimmedContainers.length+" containers dimmed, taking their children with them");
    ok("focus "+key+" spares the chrome",dimmedChrome.length===0,
      dimmedChrome.length+" frame elements dimmed");
    ok("focus "+key+" spares its own geometry",ownDimmed.length===0,
      ownDimmed.length+" elements tagged "+key+" were dimmed by selecting "+key);
    ok("focus "+key+" dims unrelated node rows",foreignNodeLabels.length===0,
      foreignNodeLabels.length+" unrelated node labels stayed lit: "+
      foreignNodeLabels.slice(0,3).map(el=>(el.textContent||"").trim()).join(", "));
    ok("focus "+key+" lights every tunnel endpoint",missingNodeLabels.length===0,
      missingNodeLabels.length+" endpoint labels are missing or dim: "+missingNodeLabels.join(", "));
    ok("focus "+key+" shows every endpoint's physical host",missingParentLabels.length===0,
      missingParentLabels.length+" physical-host labels are missing or dim: "+missingParentLabels.join(", "));
  }
  out.facts.focus=perFocus;

  setFocus(null);
  const dimAfterClear=painted.filter(el=>el.classList.contains("dim")).length;
  ok("clearing the selection restores everything",dimAfterClear===0,dimAfterClear+" still dim");

  // The panels that only appear when they have something to say.
  const drift=document.getElementById("drift");
  ok("the drift panel says what to run",
    drift.textContent.includes("vctl wg sync"),JSON.stringify(drift.textContent.slice(0,60)));
  const live=document.getElementById("live-summary").querySelector("span").textContent;
  out.facts.summary=live;
  ok("the summary reports coverage",/observed \d+\/\d+/.test(live),live);
  out.facts.stateKey=document.getElementById("state-key").textContent.trim();

  // The theme toggle is a full re-render: it drops the colour cache and redraws
  // from the topology in hand, then puts the zoom and the selection back. It is
  // the only path that calls render() twice, so it is the one that finds a
  // draw phase left holding a stale handle.
  setFocus(chips[0]);
  const beforeTheme=document.documentElement.getAttribute("data-theme");
  document.getElementById("theme-toggle").click();
  const afterTheme=document.documentElement.getAttribute("data-theme");
  const redrawn=[...document.querySelectorAll("#net *")].filter(el=>el.getClientRects().length>0);
  out.facts.theme={from:beforeTheme,to:afterTheme,elements:redrawn.length};
  ok("the theme toggle switches",beforeTheme!==afterTheme,beforeTheme+" → "+afterTheme);
  ok("the theme toggle redraws the canvas",Math.abs(redrawn.length-painted.length)<=2,
    painted.length+" elements before, "+redrawn.length+" after");
  ok("the theme toggle keeps the selection",
    document.getElementById("selection").querySelector("b").textContent===chips[0],
    "selection is now "+JSON.stringify(document.getElementById("selection").querySelector("b").textContent));
  // Colours are baked onto SVG attributes at draw time, so a theme switch that
  // did not re-render would leave the old palette on screen.
  const strokes=new Set(redrawn.filter(el=>el.classList.contains("tun"))
    .map(el=>el.getAttribute("stroke")));
  ok("the theme toggle repaints the interface colours",strokes.size>0,
    "no tunnel strokes after the switch");

  const pre=document.createElement("pre");
  pre.id="wg-measure"; pre.textContent=JSON.stringify(out);
  document.body.appendChild(pre);
})();
`;

// ---------- build the page ----------
// The page comes from Go, not from re-doing Go's splice here. Anything this
// script assembled itself would only resemble what `vctl wg serve` sends, and
// the difference between those two is exactly where a wrong measurement hides.
//
// Two scripts are wrapped around it: the boot payload before the page's own
// first <script>, because wg_view.js reads window.WG_BOOT while booting, and the
// measurement last, after everything has drawn.
function buildPage(topo, frame) {
  const out = join(mkdtempSync(join(tmpdir(), "wg-page-")), "dashboard.html");
  execFileSync("go", ["test", "./internal/cli/", "-run", "TestDashboardPageDump", "-count=1"],
    { cwd: ROOT, env: { ...process.env, WG_PAGE_OUT: out }, stdio: "pipe" });
  const served = readFileSync(out, "utf8");
  if (served.includes("<script src=")) {
    throw new Error("the served page still points at a script file; Go did not inline it");
  }
  const boot = `window.WG_BOOT=${JSON.stringify({ topology: topo, frames: [frame] })};`;
  // String patterns replace the first occurrence only, which is what both of
  // these want.
  return served
    .replace("<script>", `<script>${boot}</script>\n<script>`)
    .replace("</body>", `<script>${MEASURE}</script>\n</body>`);
}

// ---------- run ----------
const chrome = findChrome();
if (!chrome) {
  console.error("no Chrome found. Set CHROME=/path/to/chrome, or install Google Chrome.");
  process.exit(2);
}

const topo = loadTopology();
const frame = frameFor(topo);
const dir = mkdtempSync(join(tmpdir(), "wg-dashboard-"));
const pagePath = join(dir, "dashboard.html");
writeFileSync(pagePath, buildPage(topo, frame));

// No --virtual-time-budget. It hangs new headless indefinitely here rather than
// capping anything, and nothing on this page needs it: the replay path renders
// synchronously from window.WG_BOOT, so the DOM is final by the time the load
// event fires. The timeout below is the backstop for a page that throws early.
const res = spawnSync(chrome, [
  "--headless", "--disable-gpu", "--no-sandbox",
  `--user-data-dir=${join(dir, "profile")}`,
  "--dump-dom", "file://" + pagePath,
], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 60_000 });

if (res.status !== 0 && !res.stdout) {
  console.error("chrome failed:", res.stderr || res.error);
  process.exit(2);
}

const m = /<pre id="wg-measure">([\s\S]*?)<\/pre>/.exec(res.stdout || "");
if (!m) {
  console.error("the page did not report a measurement — it threw before finishing.");
  console.error(String(res.stderr || "").split("\n").filter(l => /error|Error|Uncaught/.test(l)).slice(0, 12).join("\n"));
  if (KEEP) console.error("page kept at " + pagePath);
  process.exit(2);
}
const dec = s => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
const report = JSON.parse(dec(m[1]));

// ---------- report ----------
const f = report.facts;
const pad = (s, n) => String(s).padEnd(n);
console.log(`wg dashboard · headless measurement`);
console.log(`  topology   ${topo.nodes.length} nodes, ${topo.edges.length} edges, ${(topo.vips || []).length} vips`);
console.log(`  frame      stats on ${Object.keys(frame.edges).length}/${topo.edges.length} tunnels, ` +
  `${Object.keys(frame.errors).length} gateway poll errors, clock pinned at ${AT}`);
console.log(`  rendered   ${f.elements} elements, ${f.unpainted} not painted (display:none or zero-size) — excluded`);
console.log(`  animating  ${f.flowing} tunnels`);
console.log(`  summary    ${f.summary}`);
console.log(`  state key  ${f.stateKey}`);
console.log(`  theme      ${f.theme.from} → ${f.theme.to}, ${f.theme.elements} elements redrawn`);
console.log(`  kinds      canvas ${f.kinds.drawn.join(" ")} | key ${f.kinds.named.join(" ")}`);
console.log();
console.log(`  ${pad("FOCUS", 22)}${pad("lit", 7)}${pad("dim", 7)}${pad("dim beads", 11)}${pad("glow-while-dim", 16)}own`);
for (const [key, v] of Object.entries(f.focus)) {
  console.log(`  ${pad(key, 22)}${pad(v.lit, 7)}${pad(v.dim, 7)}${pad(v.dimmedBeads, 11)}${pad(v.glowWhileDim, 16)}${v.ownDimmed}`);
}
console.log();

const failed = report.checks.filter(c => !c.pass);
console.log(`  ${report.checks.length - failed.length}/${report.checks.length} checks passed`);
for (const c of failed) console.log(`  FAIL  ${c.name} — ${c.detail}`);

if (KEEP) console.log(`\n  page kept at ${pagePath}`);
else rmSync(dir, { recursive: true, force: true });

process.exit(failed.length ? 1 : 0);
