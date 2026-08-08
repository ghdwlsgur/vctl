"use strict";
// The dashboard's model: everything that decides *what* the diagram says, with
// nothing that touches a document.
//
// Split out of wg_serve.html, where it sat inside the <script> block with the
// drawing code. Testing it there meant regex-cutting the script out of the page
// and evaluating it against a stubbed DOM — a harness that had to grow a new
// stub every time a function reached for something new, and that could only
// reach the functions which happened not to touch the page at all.
//
// Two rules keep this file testable, and both are load-bearing:
//
//   No DOM. Not document, not window, not getComputedStyle. A function here
//   returns a value or a string; putting that value on the screen is wg_view.js.
//
//   No module state. tunnelState used to read `stats`, `pollErrors` and
//   `frameAt` off the enclosing scope, and focusClosure read `curTopo` — so a
//   test had to assign those globals before calling, and two tests in a row
//   could leak into each other. Everything a function needs is an argument.
//
// Loaded twice, deliberately. The browser gets it as a classic script, so these
// declarations land on the global scope where wg_view.js reads them. Node gets
// it through require(), via the guarded module.exports at the foot of the file.
// There is no build step and no bundler between the two.

// ---------- palette and formatting ----------

const PALETTE = ["--c0", "--c1", "--c2", "--c3", "--c5", "--c4", "--c6", "--c7"];

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtRate = b => { if (!b || b < 1) return "·"; const k = 1024; return b >= k * k ? (b / k / k).toFixed(1) + "M/s" : b >= k ? (b / k).toFixed(1) + "K/s" : b.toFixed(0) + "B/s" };
const hsLabel = s => s == null || s < 0 ? "no-handshake" : s <= 180 ? `up · ${s}s` : `idle · ${Math.round(s / 60)}m`;

const zoneKey = dc => dc ? String(dc).split("-")[0] : "etc";
const ifCmp = (a, b) => {
  const m = x => /^(.*?)(\d*)$/.exec(String(x)); const A = m(a), B = m(b);
  return A[1] === B[1] ? (parseInt(A[2] || "-1") - parseInt(B[2] || "-1")) : (A[1] < B[1] ? -1 : 1)
};
const kindLabel = k => ({
  "gateway": "WG HUB", "physical-host": "PHYSICAL HOST", vm: "VIRTUAL MACHINE",
  device: "DEVICE", external: "EXTERNAL PEER"
}[k] || String(k || "ENDPOINT").replaceAll("-", " ").toUpperCase());

// kindClass maps a collected node kind onto the typed token that colours it.
// Unknown kinds fall through to the external token rather than to a default
// that looks like a known one — a shape nobody has classified should not be
// dressed as a gateway.
const kindClass = k => ({ "gateway": "k-gateway", "physical-host": "k-host", "vm": "k-vm", "network": "k-net" })[k] || "k-external";

const cidrs = a => String(a || "").split(",").map(s => s.trim()).filter(s => s && !/\/32$|\/128$/.test(s));
const slash32 = a => String(a || "").split(",").map(s => s.trim()).find(s => /\/32$/.test(s)) || "";

// ago renders a coarse age. Precision is not the point: the reader needs to know
// whether this is minutes or days, and a seconds-accurate "6d 3h 12m" invites
// them to read a snapshot as a live figure.
function ago(sec) {
  if (sec < 90) return "just now";
  if (sec < 5400) return `${Math.round(sec / 60)}m ago`;
  if (sec < 172800) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}

// ---------- tunnel state ----------

// POLL_STALE_SECONDS is how long a tunnel's newest sample may age before it stops
// counting as observed. Pollers run every few seconds, so anything past a minute
// means this tunnel's gateway has gone quiet even if others are reporting.
const POLL_STALE_SECONDS = 60;

// TOPOLOGY_STALE_SECONDS is when a snapshot stops describing the network well
// enough to trust. `vctl wg sync` runs on no timer, so this is not a missed
// schedule — it is the point past which peers may have come or gone without the
// graph knowing.
const TOPOLOGY_STALE_SECONDS = 24 * 3600;

// Six states, because "down" was answering three different questions at once:
// the tunnel never handshook, or nobody asked it, or the gateway could not be
// reached. Those need different responses and used to look identical.
//
//   active   recent handshake
//   idle     polled, handshake is old
//   never    polled, no handshake has ever completed
//   stale    the newest sample for this tunnel has aged out
//   unknown  no poll has attributed anything here yet
//   error    a gateway on this tunnel failed to poll
const TUNNEL_STATES = ["active", "idle", "never", "stale", "unknown", "error"];
const STATE_CLS = { active: "ok", idle: "warn", never: "crit", stale: "warn", unknown: "muted", error: "crit" };
const STATE_WORD = {
  active: "active", idle: "idle", never: "never", stale: "stale",
  unknown: "unobserved", error: "poll error"
};
const STATE_KEY_CLS = { ok: "up", warn: "idle", crit: "down", muted: "unk" };

// edgeHosts is the gateways a tunnel runs between. Both ends when the edge
// carries them; otherwise the node ids, which for gateways are the hostnames.
function edgeHosts(e) {
  const hs = [];
  if (e.a && e.a.host) hs.push(e.a.host);
  if (e.b && e.b.host) hs.push(e.b.host);
  if (!hs.length) { for (const id of [e.source, e.target]) if (id && !id.includes("|")) hs.push(id); }
  return hs;
}

// tunnelState reads one tunnel against one poll frame.
//
// `reading` is that frame — {stats, pollErrors, at} — and it is an argument
// rather than three globals because this is the function the whole screen is
// derived from, and a test of it should not depend on what the last test left
// lying around.
function tunnelState(e, reading) {
  const { stats = {}, pollErrors = {}, at = 0 } = reading || {};
  // A failed poll outranks everything. Whatever the last sample said, we do not
  // currently know — reporting the stale value as fact is how a dead gateway
  // reads as healthy.
  for (const h of edgeHosts(e)) if (pollErrors[h]) return "error";
  const st = stats[e.id];
  if (!st) return "unknown";
  // Newest sample across both ends. `at` is absent on older payloads, in which
  // case age cannot be judged and the handshake is taken at face value.
  let newest = 0;
  for (const k in (st.sides || {})) { const a = st.sides[k].at || 0; if (a > newest) newest = a; }
  if (newest && at && at - newest > POLL_STALE_SECONDS) return "stale";
  if (st.hs == null || st.hs < 0) return "never";
  return st.hs <= 180 ? "active" : "idle";
}

// countStates tallies every tunnel in the topology, not the samples that arrived.
//
// The summary used to count Object.values(stats), which holds only tunnels a
// poll has reached. A fleet where 12 of 30 tunnels were observed and all 12
// looked fine rendered as "12 active" — the other 18 were missing from the
// numerator and from the denominator, so the screen was silent about them.
// Absence was the one thing it could not say.
function countStates(edges, reading) {
  const n = {}; for (const s of TUNNEL_STATES) n[s] = 0;
  for (const e of (edges || [])) n[tunnelState(e, reading)]++;
  return n;
}

// ---------- model prep: dedup same-IP gateways, pick hub ----------
function prep(topo) {
  const N = new Map(topo.nodes.map(n => [n.id, { ...n }]));
  const alias = new Map(), byIp = {};
  for (const n of N.values()) if (n.kind === "gateway" && n.ip) (byIp[n.ip] = byIp[n.ip] || []).push(n);
  for (const ip in byIp) {
    const g = byIp[ip]; if (g.length < 2) continue;
    g.sort((a, b) => a.label.length - b.label.length || (a.id < b.id ? -1 : 1));
    for (const d of g.slice(1)) { alias.set(d.id, g[0].id); N.delete(d.id); }
  }
  const eseen = new Set(), E = [];
  for (const e of topo.edges) {
    const s = alias.get(e.source) || e.source, t = alias.get(e.target) || e.target;
    if (s === t) continue;
    const k = [s, t, e.iface, e.allowed].join("~"); if (eseen.has(k)) continue; eseen.add(k);
    E.push({ ...e, source: s, target: t });
  }
  let hub = null;
  for (const n of N.values()) if (n.kind === "gateway" && (n.ifaces || []).length > ((hub && hub.ifaces || []).length || 0)) hub = n;
  return { N, E, hub };
}

// ---------- wiring model: what the hub sees, before any geometry ----------
// Groups the hub's peers per interface and sorts them into the buckets the layout
// draws differently. A tunnel collected only from the far side is flipped so it
// still reads hub→peer, which is why a reverse-only peer gets promoted here
// rather than in the drawing code.
//   mesh      — an interface with >=4 peers routing nothing wider than /32
//   topSpokes — peers sitting in the hub's own zone
//   farSpokes — peers in another zone
//   hops      — edges that never touch the hub at all
function wiringModel(N, E, hub) {
  const touch = new Map();
  const T = id => { if (!touch.has(id)) touch.set(id, { fwd: [], rev: [] }); return touch.get(id) };
  // The far end's AllowedIPs used to arrive as a second edge, because one tunnel
  // produced two — the id carried the observing side's interface name. One
  // tunnel is now one edge with both ends on it, so the reverse route is read
  // off e.b instead of from an edge that no longer exists.
  //
  // sideEdge presents one end of an edge in the shape the layout expects: a
  // flat iface/allowed pair, since every consumer below reads those two fields.
  const sideEdge = (e, side, source, target) => ({
    ...e, source, target,
    iface: (side && side.iface) || e.iface, allowed: (side && side.allowed) || "", _side: true
  });
  for (const e of E) {
    if (e.source === hub.id) {
      T(e.target).fwd.push(e);
      if (e.b) T(e.target).rev.push(sideEdge(e, e.b, e.target, hub.id));
    }
    else if (e.target === hub.id) {
      T(e.source).rev.push(e);
      if (e.b) T(e.source).fwd.push(sideEdge(e, e.b, hub.id, e.source));
    }
  }
  const perIface = new Map();
  for (const [oid, g] of touch) {
    if (g.fwd.length === 0 && g.rev.length > 0) { for (const e of g.rev) g.fwd.push({ ...e, source: hub.id, target: oid, _rev: true }); g.rev = []; }
    for (const e of g.fwd) { if (!perIface.has(e.iface)) perIface.set(e.iface, []); perIface.get(e.iface).push({ oid, e, back: g.rev }); }
  }
  const meshIf = new Set();
  for (const [ifc, list] of perIface)
    if (list.length >= 4 && list.every(s => cidrs(s.e.allowed).length === 0)) meshIf.add(ifc);
  const spokes = [], mesh = [];
  for (const [ifc, list] of perIface)
    for (const s of list) (meshIf.has(ifc) ? mesh : spokes).push({ ...s, iface: ifc });
  const hops = E.filter(e => e.source !== hub.id && e.target !== hub.id);
  const topSpokes = spokes.filter(s => { const n = N.get(s.oid); return n && zoneKey(n.dc) === zoneKey(hub.dc); });
  const farSpokes = spokes.filter(s => !topSpokes.includes(s));
  return { meshIf, spokes, mesh, hops, topSpokes, farSpokes };
}

// Buckets the far endpoints into the right-hand zone columns, keyed by zone. Hop
// endpoints that no bucket claimed yet join their own zone so a transit node in
// another site still gets drawn; hub-zone and external nodes are left out because
// the hub row and the external column already own them.
function zoneBuckets(N, hub, { farSpokes, spokes, mesh, hops }) {
  const zmap = new Map();
  const Z = k => { if (!zmap.has(k)) zmap.set(k, []); return zmap.get(k) };
  for (const s of farSpokes) { const n = N.get(s.oid); Z(n ? zoneKey(n.dc) : "etc").push(s); }
  const placed = new Set([hub.id, ...spokes.map(s => s.oid), ...mesh.map(s => s.oid)]);
  for (const e of hops) for (const id of [e.source, e.target]) {
    const n = N.get(id);
    if (n && !placed.has(id) && n.kind !== "external" && zoneKey(n.dc) !== zoneKey(hub.dc)) {
      placed.add(id); Z(zoneKey(n.dc)).push({ oid: id, e: null, iface: null, back: [] });
    }
  }
  return zmap;
}

// ---------- VIPs from the IPAM ledger ----------

// Attaches IPAM-ledger VIPs (e.g. o11y DNAT) to the endpoint that owns them, and
// records which node each interface fronts — that map is what lets a wg3
// selection light its DNAT owner.
//
// Two ways to decide the owner, and the page keeps them apart:
//
//   stated    ip_allocations.owner_public_key names the endpoint. Exact.
//   guessed   the endpoint label's first token appears in the VIP label,
//             longest match winning.
//
// The guess is what this always did, and it is substring matching on two
// human-typed strings: it attaches a VIP to the wrong endpoint when one label
// contains another's prefix, attaches nothing when either side is renamed, and
// the screen could not say which had happened. It stays as the fallback for rows
// nobody has filled in, but it is marked, so a reader can tell a fact from an
// inference without reading this function.
//
// Returns both maps rather than writing vipFocusNodes into an enclosing scope.
// The old signature returned one and assigned the other, so calling it twice in
// one test accumulated focus entries from the first call into the second.
function attachVips(topo, N, spokes) {
  const vipsBy = new Map(), vipFocusNodes = new Map();
  // Endpoint public key → node id, for the stated case.
  const byKey = new Map();
  // Every interface's key, not just the node's first. A gateway has one key per
  // interface — sre-lb runs wg1 and wg-personal with different keys — so
  // indexing the node key alone made a VIP naming the second interface fall
  // through to the label guess and render as an inference.
  for (const s of spokes) {
    const n = N.get(s.oid); if (!n) continue;
    if (n.pub) byKey.set(n.pub, s.oid);
    for (const i of (n.ifaces || [])) if (i.pub) byKey.set(i.pub, s.oid);
  }
  for (const v of (topo.vips || [])) {
    let oid = null, guessed = false;
    if (v.owner && byKey.has(v.owner)) oid = byKey.get(v.owner);
    if (!oid) {
      let best = null;
      for (const s of spokes) {
        const n = N.get(s.oid); if (!n) continue;
        const tok = String(n.label).split(/[\s(]/)[0];
        if (tok && v.label.includes(tok) && (!best || tok.length > best.tok)) best = { oid: s.oid, tok: tok.length };
      }
      if (!best) continue;
      oid = best.oid; guessed = true;
    }
    // Focus by the interface that actually carries the VIP, not by the name in
    // the ledger's wg_tunnel field.
    //
    // That field is free text and in this fleet it names the *destination* mesh:
    // the o11y VIPs read "wg3", which lives on the incheon hub, while the VIPs
    // are DNAT'd on sre-lb and leave over wg1. Keying on it meant selecting the
    // hub's wg3 lit up sre-lb — a host with no wg3 at all — and selecting sre-lb's
    // wg1, the interface that really carries them, brought no VIP into focus.
    //
    // The owner key resolves it exactly: find which of the owner's interfaces
    // holds that key. Fall back to wg_tunnel only when there is no owner, where
    // it remains a guess like everything else about an unbound VIP.
    const owner = N.get(oid), ifc = vipIface(owner, v);
    if (!vipsBy.has(oid)) vipsBy.set(oid, []);
    vipsBy.get(oid).push({ ...v, guessed, iface: ifc || v.iface });
    if (ifc) {
      if (!vipFocusNodes.has(ifc)) vipFocusNodes.set(ifc, new Set());
      vipFocusNodes.get(ifc).add(oid);
    }
  }
  return { vipsBy, vipFocusNodes };
}

// vipIface is the interface on the owning endpoint that carries a VIP.
//
// With a recorded owner key this is exact. Without one, wg_tunnel is all there
// is — and it is only trusted when the owner actually has an interface by that
// name, because naming another host's interface is how it is usually wrong.
function vipIface(owner, v) {
  if (!owner) return "";
  const ifs = owner.ifaces || [];
  if (v.owner) {
    const hit = ifs.find(i => i.pub === v.owner);
    if (hit) return hit.name;
  }
  if (v.iface && ifs.some(i => i.name === v.iface)) return v.iface;
  return "";
}

// ---------- interface identity ----------

// hopKey identifies the interface a hop tunnel leaves from.
//
// An interface is (host, name), never a name. wg3 on the hub and wg3 on the
// Seoul gateway are two interfaces on two machines that happen to share a
// word — the operations ledger warns about exactly this and names three
// separate nodes called wireguard-gw-incheon.
//
// This used to qualify a hop only when its name collided with one of the hub's,
// which got both halves wrong. Two hops sharing a name with each other but not
// with the hub merged into one filter chip, so selecting it lit tunnels on
// different machines as though they were one interface. And whether a hop was
// qualified at all depended on how somebody had named an interface on a
// different node, so adding a hub interface silently renamed unrelated filters.
//
// Hub-adjacent edges keep the bare name: there is one hub, so its names cannot
// be ambiguous. Everything else carries its owner. e.iface describes the source
// side, so the owner is e.source.
function hopKey(e, hub) {
  const bare = e.iface;
  if (!hub || !bare) return bare;
  if (e.source === hub.id || e.target === hub.id) return bare;
  return e.source + "/" + bare;
}

// ifLabel is what a filter chip says, which is not what it means.
//
// The key is always (host, name); the label drops the host while the bare name
// still picks out one chip, and grows it back the moment two chips would read
// the same. So the common case stays short and the ambiguous case stops lying.
function ifLabel(key, keys) {
  const cut = key.lastIndexOf("/");
  if (cut < 0) return key;
  const bare = key.slice(cut + 1);
  let n = 0;
  for (const k of keys) if (k === bare || k.endsWith("/" + bare)) n++;
  return n > 1 ? key : bare;
}

// ---------- geometry: the layout grid, measured once ----------
// Every column x, the hub's height, and each zone's box are derived from content
// (longest label, peer counts, VIP stacks) rather than fixed, so this computes
// them up front and hands the drawing phases one immutable record. rowH/clH ride
// along because the zone drawing has to measure rows the same way this did.
function wiringGeometry(topo, N, hub, { meshIf, mesh, hops, topSpokes, farSpokes }, zmap, vipsBy) {
  const HUBX = 310, HUBW = Math.max(170, hub.label.length * 7.2 + 26), NATX = HUBX + HUBW + 130;
  const epNodes = farSpokes.map(s => N.get(s.oid) || {});
  const epNeed = Math.max(0, ...epNodes.map(n => String(n.label || "").length * 7 + kindLabel(n.kind).length * 5.2 + 48));
  const EPW = Math.min(340, Math.max(220, epNeed));
  const hasExt = [...N.values()].some(n => n.kind === "external");
  const EPX = NATX + 50, LANE0 = EPX + EPW + 34, BANDX = LANE0 + 150, BANDW = 400;
  const EXTX = BANDX + BANDW + 28, ZONE_R = EXTX + (hasExt ? 196 : -4) + (hasExt ? 16 : 0);
  const hubIfaces = (hub.ifaces || []).map(i => i.name).sort(ifCmp);
  const remoteIf = hubIfaces.filter(i => !meshIf.has(i));
  const hubH = Math.max(110, 46 + remoteIf.length * 38);
  const HUBY = 170;
  const ROWH = 64, HOSTPAD = 34;

  const vipExtra = oid => { const vs = vipsBy.get(oid); return vs ? 28 + vs.length * 17 : 0; };
  const zones = [...zmap.entries()].sort((a, b) => b[1].length - a[1].length);
  // cluster same-parent endpoints so one physical host box holds all its VMs
  const clusterize = list => {
    list.sort((a, b) => ifCmp(a.iface || "~", b.iface || "~") || String(a.oid).localeCompare(b.oid));
    const out = [], by = new Map();
    for (const s of list) {
      const pid = (N.get(s.oid) || {}).parent || null;
      if (pid && by.has(pid)) { by.get(pid).items.push(s); continue; }
      const cl = { parent: pid ? N.get(pid) : null, items: [s] };
      out.push(cl); if (pid) by.set(pid, cl);
    }
    return out;
  };
  const rowH = s => ROWH - 10 + vipExtra(s.oid);
  const clH = cl => (cl.parent ? HOSTPAD - 6 : 0) + cl.items.reduce((a, s) => a + rowH(s) + 10, 0);
  let zy = topSpokes.length ? 180 : 130; const zoneGeo = [];
  for (const [zk, list] of zones) {
    const clusters = clusterize(list);
    let rows = 0, bandRefs = 0; const cs = new Set();
    for (const cl of clusters) {
      rows += clH(cl) + 14;
      for (const s of cl.items) if (s.e) cidrs(s.e.allowed).forEach(c => { cs.add(c); bandRefs++; });
    }
    const bandH = [...cs].length ? ([...cs].length * 56 + bandRefs * 6) : 0;
    const h = 52 + Math.max(rows, bandH);
    zoneGeo.push({ zk, clusters, y: zy, h }); zy += h + 26;
  }
  const meshHeights = [...meshIf].map(ifc => 48 + mesh.filter(s => s.iface === ifc).length * 20 + 44 + 180);
  const leftH = HUBY + hubH + 84 + meshHeights.reduce((a, b) => a + b, 0) + hops.length * 180 + 160;
  const H = Math.max(zy + 40, leftH, 720), W = ZONE_R + 20;
  const drawW = Math.min(W, 1560);
  return {
    HUBX, HUBW, NATX, EPW, EPX, LANE0, BANDX, BANDW, EXTX, ZONE_R,
    remoteIf, hubH, HUBY, ROWH, HOSTPAD, zoneGeo, H, W, drawW, rowH, clH
  };
}

// reachedOverATunnel is every network the hub gets to by going through a peer.
//
// Only edges leaving the hub count. AllowedIPs describe what the far side of a
// tunnel will accept, so the hub's own ranges appear in the lists the *other*
// gateways advertise — reading every edge would mark the hub's own fabric as
// remote and empty the lane.
function reachedOverATunnel(topo, hub) {
  const out = new Set();
  if (!hub) return out;
  for (const e of (topo.edges || [])) {
    if (e.source !== hub.id) continue;
    for (const c of cidrs(e.allowed)) out.add(c);
  }
  return out;
}

// ---------- tunnel focus: the selected tunnel and nothing else ----------
// Selecting an interface isolates that tunnel: its own edges, the nodes they
// land on, the networks routed over them, and any DNAT VIP the interface owns.
// It deliberately does not follow the branch onward through transit nodes — a
// wg1 selection must not also light up wg9 on the far side of a relay.
function focusClosure(seed, topo, vipFocusNodes) {
  const result = { ifaces: new Set(seed ? [seed] : []), nodes: new Set(), edges: new Set(), hubIfaces: new Set(), cidrs: new Set() };
  if (!seed || !topo) return result;
  const { E, hub } = prep(topo);
  if (!hub) return result;
  // A hub iface name such as wg0 can also exist on unrelated remote hosts. Keep
  // only the edges attached to this topology's hub, so the selection stays one
  // tunnel instead of every tunnel that happens to share the name.
  // A seed may be scoped as "host/iface". Interface names are chosen per host, so
  // a bare name cannot address a tunnel between two remote hosts when the hub
  // happens to use the same name: the guard below drops it, and nothing else
  // selects it, leaving the tunnel unreachable by any filter. Two of this
  // fleet's nineteen edges were in that state.
  const slash = seed.lastIndexOf("/");
  const scopeHost = slash > 0 ? seed.slice(0, slash) : "";
  const seedIf = scopeHost ? seed.slice(slash + 1) : seed;

  const hubOwns = !scopeHost && (hub.ifaces || []).some(i => i.name === seedIf);
  for (const e of E) {
    if (e.iface !== seedIf) continue;
    if (scopeHost && e.source !== scopeHost && e.target !== scopeHost) continue;
    if (hubOwns && e.source !== hub.id && e.target !== hub.id) continue;
    result.edges.add(e.id);
    result.nodes.add(e.source); result.nodes.add(e.target);
    for (const c of cidrs(e.allowed)) result.cidrs.add(c);
    if (e.source === hub.id || e.target === hub.id) result.hubIfaces.add(e.iface);
  }
  // A VIP is labelled with the interface that fronts it, so it belongs to this
  // tunnel's picture even though no edge carries it.
  for (const id of ((vipFocusNodes && vipFocusNodes.get(seed)) || [])) result.nodes.add(id);
  return result;
}

// Chrome is the drawing's frame rather than anything on it: lane headings, the
// zone boxes, the NAT divider. It belongs to no interface and never dims — a
// filter that hides where "EDGE / NAT" was does not isolate anything.
const CHROME_CLASSES = new Set(["lanerule", "lanehead", "zone", "zlab", "zsub", "nat", "natlab"]);
const hasChromeClass = classes => { for (const c of (classes || [])) if (CHROME_CLASSES.has(c)) return true; return false; };

// focusVerdict answers one question about one element: given what its parent
// decided, is this element part of the selected tunnel's picture?
//
// It reads a plain dataset object, so it can be exercised without a document —
// which is the point. The rules below are precedence rules, and every one of
// them exists because getting it wrong produced a specific wrong screen; a test
// can now state the case as an object instead of building SVG to reach it.
//
// An explicit tag beats an inherited verdict in both directions, so a wg3 glyph
// on a node wg0 also reaches goes dark during a wg0 focus.
//
// keep means "always part of the picture", and it has to reach the children or
// it means nothing: the hub is one group whose box, title and address are
// untagged children of it, so a keep that stopped at the group left the hub
// drawn as an empty outline during a focus on its own interface.
//
// No tag at all means "ask my parent". The pass used to be a flat
// querySelectorAll where each element judged itself alone and anything untagged
// was skipped outright, so untagged geometry never dimmed. Selecting wg1 dimmed
// the few tagged things and left the wg3 mesh lit beside it — ten beads with
// nothing to do with wg1 — which reads as "a few dots changed colour" instead
// of isolating an interface.
function focusVerdict(data, inherited, focus) {
  const own = data.ifc, ifs = data.ifs, keep = data.keep;
  const precise = data.eids !== undefined || data.nodes !== undefined || data.hubif !== undefined || data.cidr !== undefined;
  if (keep != null) return true;
  if (own !== undefined) {
    let matched = focus.ifaces.has(own);
    // An interface tag that does not match is not the last word when the same
    // group also names nodes or edges that are in focus. A tunnel's far end is
    // drawn by the chip that owns it — tagged with the interface facing the
    // hub, which is a different name — so short-circuiting here dimmed the node
    // at the other end of the very tunnel being focused. Measured: wg-seoul lit
    // its tunnel and its hub and nothing else.
    if (!matched && precise) {
      if (data.eids !== undefined) matched = JSON.parse(data.eids).some(id => focus.edges.has(id));
      if (!matched && data.nodes !== undefined) matched = JSON.parse(data.nodes).some(id => focus.nodes.has(id));
    }
    return matched;
  }
  // A routed-network band is semantic, not owned by the first interface that
  // happened to create it. The same CIDR can later receive wg-seoul/wg1 routes,
  // so CIDR focus must beat the band's initial data-ifs value.
  if (data.cidr !== undefined) return focus.cidrs.has(data.cidr);
  if (ifs !== undefined) return inherited || ifs.split("|").some(i => focus.ifaces.has(i));
  if (precise) {
    let matched = inherited;
    if (data.eids !== undefined) matched = matched || JSON.parse(data.eids).some(id => focus.edges.has(id));
    if (data.nodes !== undefined) matched = matched || JSON.parse(data.nodes).some(id => focus.nodes.has(id));
    if (data.hubif !== undefined) matched = matched || focus.hubIfaces.has(data.hubif);
    return matched;
  }
  return inherited;
}

// focusPass is the whole per-element rule: the verdict its children inherit, and
// whether this element itself goes dim.
//
// An element with children never dims itself. Dimming a container takes its
// matched descendants down with it, which blacked out the entire diagram the
// first time this was attempted.
function focusPass({ data, classes, leaf }, inherited, focus, focused) {
  const matched = focusVerdict(data || {}, inherited, focus);
  return { matched, dim: !!focused && !matched && !hasChromeClass(classes) && !!leaf };
}

// ---------- the strings the chrome shows ----------
// These build markup and text and hand it back. They used to end in a
// getElementById and an assignment, which meant a test had to fake a document to
// read what they produced — and could only read the last thing assigned.

// The state key shows the states the fleet is in, with how many tunnels are in
// each. A count beside the word turns the key from a list of words into a
// reading of the fleet, and an absent state is absent rather than zero.
//
// Only the states this fleet is actually in. The key used to list all six
// whatever was on screen, so "poll error" and "never" sat in the legend of a
// healthy fleet and read as categories somebody should go looking for.
function stateKeyHTML(counts) {
  return TUNNEL_STATES.filter(s => counts[s] > 0)
    .map(s => `<span class="${STATE_KEY_CLS[STATE_CLS[s]] || "unk"}"><i></i>${esc(STATE_WORD[s])} ${counts[s]}</span>`)
    .join("");
}

// kindKeyHTML names the typed colours, and only the ones on screen.
//
// It is given the kinds the canvas actually drew rather than the kinds the
// renderer knows how to draw, for the same reason the interface chips are built
// from the canvas: a kind the layout never drew would be a legend entry pointing
// at nothing.
const KIND_KEY = [["k-gateway", "gateway"], ["k-host", "physical host"], ["k-vm", "VM"],
["k-net", "routed network"], ["k-external", "unresolved endpoint"]];
function kindKeyHTML(kinds) {
  return KIND_KEY.filter(([c]) => kinds.has(c))
    .map(([c, label]) => `<span class="kind ${c}"><i></i>${esc(label)}</span>`).join("");
}

// liveSummary is the headline: coverage first, then what is wrong, then what is
// unknown, then what is fine.
function liveSummary(n, edgeCount) {
  const observed = n.active + n.idle + n.never;
  const parts = [];
  if (n.error) parts.push(`${n.error} poll error`);
  if (n.stale) parts.push(`${n.stale} stale`);
  if (n.unknown) parts.push(`${n.unknown} unobserved`);
  if (n.never) parts.push(`${n.never} never`);
  if (n.idle) parts.push(`${n.idle} idle`);
  if (n.active) parts.push(`${n.active} active`);
  return {
    cls: "live-summary " + (n.error ? "warn" : (n.stale || n.unknown) ? "warn" : n.active ? "ok" : ""),
    // The coverage fraction is the honest headline: how much of the graph this
    // reading actually covers.
    text: edgeCount ? `observed ${observed}/${edgeCount} · ${parts.join(" · ")}` : "waiting for tunnel state",
    title: TUNNEL_STATES.map(s => `${s}: ${n[s]}`).join("\n"),
  };
}

// driftText lists peers the pollers see that the drawn snapshot does not have.
//
// They are not added to the graph: the layout comes from the snapshot, and
// re-deriving it every two seconds would shift the diagram under the reader's
// cursor for what is really a prompt to re-sync. Naming them, and saying what to
// run, is the part that was missing — until now they were dropped in silence.
// Nothing to report means nothing on screen.
function driftText(list) {
  if (!list || !list.length) return "";
  const lines = list.slice(0, 8).map(p => {
    const where = `${p.host}/${p.iface}`;
    const via = p.endpoint ? ` via ${p.endpoint}` : "";
    const routes = (p.allowed || []).length ? ` allowed ${p.allowed.join(", ")}` : "";
    return `  + ${where} ${String(p.pub || "").slice(0, 12)}…${via}${routes}`;
  });
  if (list.length > 8) lines.push(`  … and ${list.length - 8} more`);
  return [`${list.length} peer(s) on the wire are not in this snapshot`,
    ...lines, "run `vctl wg sync` to draw them"].join("\n");
}

// topologyClock is the structural age. Everything drawn — nodes, tunnels,
// AllowedIPs, endpoints — is as old as this, however fast the traffic animates.
// One "Updated" made a six-day-old graph look current, because the page kept
// animating.
function topologyClock(collectedAt, now) {
  const t = collectedAt ? Date.parse(collectedAt) : NaN;
  if (!t || isNaN(t)) {
    return { text: "never", title: "no WireGuard rows in the database — run `vctl wg sync`", stale: true };
  }
  const age = (now - t) / 1000;
  return {
    text: ago(age),
    title: new Date(t).toLocaleString() + " — last `vctl wg sync`",
    stale: age > TOPOLOGY_STALE_SECONDS,
  };
}

// Node reads this file through require(); the browser loads it as a classic
// script and never sees the export. Keeping both paths on one file is what lets
// a test call these functions as functions instead of cutting them out of a page.
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    PALETTE, POLL_STALE_SECONDS, TOPOLOGY_STALE_SECONDS,
    TUNNEL_STATES, STATE_CLS, STATE_WORD, STATE_KEY_CLS, KIND_KEY, CHROME_CLASSES,
    esc, fmtRate, hsLabel, zoneKey, ifCmp, kindLabel, kindClass, cidrs, slash32, ago,
    edgeHosts, tunnelState, countStates,
    prep, wiringModel, zoneBuckets, attachVips, vipIface, hopKey, ifLabel,
    wiringGeometry, reachedOverATunnel,
    focusClosure, hasChromeClass, focusVerdict, focusPass,
    stateKeyHTML, kindKeyHTML, liveSummary, driftText, topologyClock,
  };
}
