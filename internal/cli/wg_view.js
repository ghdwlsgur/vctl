"use strict";
// The dashboard's view: everything that puts the model on the screen.
//
// Wiring-diagram renderer: hub iface ports -> NAT -> per-zone endpoints (nested in
// physical hosts) -> reachable-CIDR bands. Band hookups are a grey underlay bus plus
// per-tunnel dashed colour branches (both sides, Seoul like Incheon). Orthogonal
// elbows only; clicking any tunnel focuses that iface and dims the rest.
// Fully driven by /topology + /events; window.WG_BOOT {topology,frames} replays.
//
// Everything this file calls that does not touch a document lives in
// wg_model.js, loaded ahead of it. In the browser that file is a classic script,
// so its declarations are already on the global scope by the time this runs;
// under Node it is required directly and this file is not loaded at all.
//
// Nothing here runs on load. boot() is called at the foot of the file, and only
// when there is a document with the dashboard's markup in it — the page used to
// reach for #net and #theme-toggle at top level, which is what forced every test
// to bring a stub DOM along before it could reach a single function.

const SVGNS = "http://www.w3.org/2000/svg";
const mk = (t, a, p) => { const e = document.createElementNS(SVGNS, t); for (const k in a) e.setAttribute(k, a[k]); if (p) p.appendChild(e); return e };
const cssv = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const ifColMap = new Map();
const ifColor = i => { if (!ifColMap.has(i)) ifColMap.set(i, cssv(PALETTE[ifColMap.size % PALETTE.length])); return ifColMap.get(i) };

// The page's own handles, assigned by boot().
let svg = null, tip = null, canvas = null;

// What is drawn, and what the last frame said about it.
let tunnels = [], statusDots = new Map(), curTopo = null, lastTopo = null, vipFocusNodes = new Map();
// The poll frame, in the shape tunnelState reads. "no traffic" and "we could not
// ask" used to arrive as the same absence, so the errors travel with the samples.
let reading = { stats: {}, pollErrors: {}, at: 0 };
// The current selection, in the shape focusClosure returns.
let focusIf = null, focus = { ifaces: new Set(), nodes: new Set(), edges: new Set(), hubIfaces: new Set(), cidrs: new Set() };
let canvasBase = { w: 800, h: 200 }, zoom = 1;

function sizeCanvas(w, h) {
  canvasBase = { w, h };
  svg.setAttribute("width", Math.round(w * zoom));
  svg.setAttribute("height", Math.round(h * zoom));
}
function setZoom(next) {
  zoom = Math.max(.55, Math.min(1.8, next));
  sizeCanvas(canvasBase.w, canvasBase.h);
}
function fitCanvas() {
  const room = Math.max(320, canvas.clientWidth - 44);
  setZoom(Math.min(1, room / canvasBase.w));
}

function hot(el, fn) {
  el.classList.add("hot");
  el.addEventListener("mouseenter", ev => { const [t, m] = fn(); tip.innerHTML = `<div class="t">${esc(t)}</div><div class="m">${esc(m)}</div>`; tip.style.opacity = 1; mv(ev); });
  el.addEventListener("mousemove", mv); el.addEventListener("mouseleave", () => tip.style.opacity = 0);
}
function mv(ev) { let x = ev.clientX + 12, y = ev.clientY + 12; if (x + 290 > innerWidth) x = ev.clientX - 290; tip.style.left = x + "px"; tip.style.top = y + "px"; }
function clickFocus(el, ifc) { el.addEventListener("click", ev => { ev.stopPropagation(); setFocus(focusIf === ifc ? null : ifc); }); }

// ---------- shared glyphs ----------
// Every box on the canvas is the same card: kind eyebrow, title, address line.
// The hub passes its own sub text because it shows only an underlay address.
// Returns the rect so callers can attach tooltips and focus clicks.
function nodeCard(p, { x, y, w, h, node, sub, cls = "" }) {
  const box = mk("rect", {
    x, y, width: w, height: h, rx: cls.includes("hub") ? 9 : 8,
    class: ("nbox " + kindClass(node.kind) + " " + cls).trim()
  }, p);
  mk("text", { x: x + 12, y: y + 14, class: "nkind" }, p).textContent = kindLabel(node.kind);
  mk("text", { x: x + 12, y: y + 30, class: "ntit" }, p).textContent = node.label;
  mk("text", { x: x + 12, y: y + 46, class: "nsub" }, p).textContent =
    sub !== undefined ? sub : [node.ip, node.tunnelIp].filter(Boolean).join(" · ");
  return box;
}

// A drawn tunnel: the static run plus the animated flow twin that rides it,
// registered for stat updates and wired so clicking the run focuses its
// interface. title carries the arrow the calling section uses — "→" for a
// dial-in leg, "↔" for a mesh or hop leg.
function tunnelRun(gt, gf, { d, col, edge, iface, title }) {
  const base = mk("path", { d, class: "tun", stroke: col }, gt);
  const fl = mk("path", { d, class: "flow", stroke: col }, gf);
  // The run carries its interface as data, not only in a click handler. Focus
  // asks "does this belong to the selected interface", and a listener cannot
  // answer that — so the tunnels were invisible to the dim pass and stayed
  // bright under every filter.
  if (iface) { base.dataset.ifc = iface; fl.dataset.ifc = iface; }
  tunnels.push({ id: edge.id, base, fl });
  hot(base, () => {
    const st = reading.stats[edge.id] || {};
    return [title, `allowed ${edge.allowed} · ${hsLabel(st.hs)} · rx ${fmtRate(st.rx)} · tx ${fmtRate(st.tx)} · click to focus`]
  });
  clickFocus(base, iface);
  return base;
}

// A tunnel's live bead: colour by interface, registered for stat updates, and
// captioned with handshake age plus rx/tx. prefix/detail wrap that caption with
// tunnel-specific text (a /32 mesh address, a reverse route), and cls picks the
// bead style — "sdot" for the compact mesh stack, "pdot" everywhere else.
function statusDot(p, { cx, cy, r = 5.5, eid, col, title, prefix = "", detail = "", cls = "pdot" }) {
  const dot = mk("circle", { cx, cy, r, fill: col, class: cls + " hot" }, p);
  if (eid) statusDots.set(eid, dot);
  hot(dot, () => {
    const st = reading.stats[eid] || {};
    return [title, `${prefix}${hsLabel(st.hs)} · rx ${fmtRate(st.rx)} · tx ${fmtRate(st.tx)}${detail}`];
  });
  return dot;
}

function physicalHostOf(N, node) {
  return node && node.parent ? N.get(node.parent) : null;
}

function physicalHostLabel(host) {
  return "PHYSICAL HOST · " + host.label + (host.ip ? " · " + host.ip : "");
}

// Column headings, the hub-zone box, and the NAT divider — the quiet backdrop
// that makes the wiring scannable before anyone traces a coloured route.
function drawChrome({ gz }, { ZONE_R, HUBX, NATX, EPX, BANDX, H }, hub) {
  mk("line", { x1: 40, y1: 64, x2: ZONE_R, y2: 64, class: "lanerule" }, gz);
  mk("text", { x: 64, y: 52, class: "lanehead" }, gz).textContent = "LOCAL FABRIC";
  mk("text", { x: HUBX, y: 52, class: "lanehead" }, gz).textContent = "WIREGUARD HUB";
  mk("text", { x: NATX, y: 52, class: "lanehead", "text-anchor": "middle" }, gz).textContent = "EDGE / NAT";
  mk("text", { x: EPX, y: 52, class: "lanehead" }, gz).textContent = "REMOTE ENDPOINTS";
  mk("text", { x: BANDX, y: 52, class: "lanehead" }, gz).textContent = "ROUTED NETWORKS";
  // Exactly two zone labels: the hub zone here, the far zones with their rows.
  mk("rect", { x: 40, y: 90, width: NATX - 90, height: H - 140, rx: 12, class: "zone" }, gz);
  mk("text", { x: 56, y: 114, class: "zlab" }, gz).textContent = zoneKey(hub.dc);
  mk("line", { x1: NATX, y1: 100, x2: NATX, y2: H - 60, class: "nat" }, gz);
  mk("text", { x: NATX, y: 90, class: "natlab", "text-anchor": "middle" }, gz).textContent = "NAT / WAN";
}

// The hub site's own networks: inventory /24s as bands on a grey bus into the
// hub, plus the reverse-reach overlay. That overlay deliberately traces the same
// path as the grey bus — it is route state on that wire, not second cabling.
function drawLocalFabric({ gg, gn, gd, gt, grp }, { HUBX, HUBY }, topo, N, hub, spokes) {
  const aggm = new Map();
  // A network the hub reaches over a tunnel is not the hub's own fabric,
  // however its hosts happen to be labelled.
  //
  // This lane used to be "inventory aggregates whose dc is in the hub's zone",
  // which trusts an operator-typed label to answer a question the wire already
  // answers. One host in Seoul tagged incheon-vm was enough to draw Seoul's
  // 192.168.201.0/24 as an Incheon-local range — beside the wg0 tunnel that
  // exists precisely because it is not local. The label was corrected, but the
  // next mislabelled host would have redrawn it.
  //
  // The dc still decides which site a range belongs to. What it no longer does
  // is override the tunnel that says the range is on the far side.
  const remote = reachedOverATunnel(topo, hub);
  for (const a of (topo.aggs || [])) if (zoneKey(a.dc) === zoneKey(hub.dc) && !remote.has(a.cidr)) {
    const c = aggm.get(a.cidr) || { cidr: a.cidr, count: 0 }; c.count += a.count; aggm.set(a.cidr, c);
  }
  let ly = 150; const localBand = new Map();
  const laggs = [...aggm.values()].sort((a, b) => b.count - a.count).slice(0, 6);
  for (const a of laggs) {
    const gb = grp(gn, null, { eids: [] });
    gb.dataset.cidr = a.cidr;
    const r = mk("rect", { x: 64, y: ly, width: 180, height: 42, rx: 8, class: "nbox band k-net" }, gb);
    mk("text", { x: 78, y: ly + 18, class: "btit" }, gb).textContent = a.cidr;
    mk("text", { x: 78, y: ly + 32, class: "bsub" }, gb).textContent = `inventory ×${a.count}`;
    hot(r, () => [a.cidr, `hub-site local range · ${a.count} hosts`]);
    mk("path", { d: `M244,${ly + 21} H272`, class: "grey" }, gg);
    mk("circle", { cx: 244, cy: ly + 21, r: 3, class: "jdot" }, gd);
    localBand.set(a.cidr, { x: 244, y: ly + 21, ref: 0, group: gb, eids: new Set() });
    ly += 54;
  }
  if (laggs.length) {
    mk("path", { d: `M272,171 V${ly - 33}`, class: "grey" }, gg);
    mk("path", { d: `M272,${HUBY + 40} H${HUBX}`, class: "grey" }, gg);
    mk("circle", { cx: HUBX, cy: HUBY + 40, r: 3, class: "jdot" }, gd);
  }
  for (const s of spokes) for (const b of (s.back || [])) for (const c of cidrs(b.allowed)) {
    const lb = localBand.get(c); if (!lb) continue;
    const col = ifColor(s.iface);
    const g2 = grp(gt, s.iface, { eids: [s.e.id, b.id] }), g2d = grp(gd, s.iface, { eids: [s.e.id, b.id] });
    lb.eids.add(s.e.id); lb.eids.add(b.id); lb.group.dataset.eids = JSON.stringify([...lb.eids]);
    const d = `M${HUBX},${HUBY + 40} H272 V${lb.y} H244`;
    const pth = mk("path", { d, class: "reach", stroke: col }, g2);
    pth.dataset.overlay = "local-bus"; pth.dataset.cidr = c;
    pth.dataset.eids = JSON.stringify([s.e.id, b.id]);
    mk("circle", { cx: 244, cy: lb.y, r: 4, fill: col, class: "sdot" }, g2d);
    hot(pth, () => [`${s.iface} → ${c}`, `reverse reachability — AllowedIPs on ${(N.get(s.oid) || {}).label || ""} · click to focus`]);
    clickFocus(pth, s.iface);
  }
}

// The hub box and one listen port per remote interface. Returns where each port
// sits so the tunnel phases can start their elbows exactly on it. The box is
// marked keep so a focus never dims the thing everything else hangs off.
function drawHub({ gn, gd, grp }, { HUBX, HUBW, HUBY, hubH, remoteIf }, hub) {
  const ghub = mk("g", {}, gn); ghub.dataset.keep = "1";
  nodeCard(ghub, { x: HUBX, y: HUBY, w: HUBW, h: hubH, node: hub, sub: hub.ip || "", cls: "hub" });
  const hubPort = new Map();
  remoteIf.forEach((ifc, i) => {
    const y = HUBY + 56 + i * 38, col = ifColor(ifc), port = (hub.ifaces || []).find(x => x.name === ifc);
    const g2 = grp(gd, ifc, { hubif: ifc });
    const d = mk("circle", { cx: HUBX + HUBW, cy: y, r: 5.5, fill: col, class: "pdot hot" }, g2);
    hot(d, () => [`${ifc} :${port ? port.port : "?"}`, "hub listen port · click to focus"]); clickFocus(d, ifc);
    const t = mk("text", { x: HUBX + HUBW - 10, y: y + 3.5, class: "plab", "text-anchor": "end" }, g2);
    t.textContent = ifc; t.setAttribute("fill", col);
    hubPort.set(ifc, { x: HUBX + HUBW, y });
  });
  return hubPort;
}

// Mesh interfaces collapse into one stacked box each: a /32 fan-out is a count,
// not N separate boxes. Returns each stack's right-edge anchor (a DNAT VIP wire
// lands there) and endY, the vertical cursor the hop chips continue from — the
// left column is one running flow, so that hand-off has to be explicit.
function drawMeshStacks({ gn, gd, gt, grp }, { HUBX, HUBY, hubH }, N, hub, { meshIf, mesh }) {
  let my = HUBY + hubH + 84; let meshIdx = 0; const meshGeo = new Map();
  for (const ifc of meshIf) {
    const list = mesh.filter(s => s.iface === ifc);
    const labels = list.map(s => {
      const n = N.get(s.oid), parent = physicalHostOf(N, n);
      return (parent ? physicalHostLabel(parent) + " · " : "") + ((n || {}).label || s.oid);
    });
    const mw = Math.min(280, Math.max(200, Math.max(0, ...labels.map(l => l.length)) * 6.6 + 52));
    const col = ifColor(ifc), rowStep = 28, bh = 48 + list.length * rowStep;
    const meshEids = list.map(s => s.e.id), meshNodes = list.map(s => s.oid);
    const g2 = grp(gn, ifc, { nodes: meshNodes, eids: meshEids }), g2d = grp(gd, ifc, { nodes: meshNodes, eids: meshEids }),
      g2t = grp(gt, ifc, { eids: meshEids });
    const rset = [...new Set(list.flatMap(x => (x.back || []).flatMap(b => cidrs(b.allowed))))];
    const box = mk("rect", { x: 64, y: my, width: mw, height: bh, rx: 9, class: "nbox" }, g2);
    mk("text", { x: 76, y: my + 13, class: "nkind" }, g2).textContent = "LOCAL MESH";
    mk("text", { x: 76, y: my + 28, class: "ntit" }, g2).textContent = `${ifc} mesh ×${list.length}`;
    const port = (hub.ifaces || []).find(x => x.name === ifc);
    mk("text", { x: 76, y: my + 42, class: "nsub" }, g2).textContent = ":" + (port ? port.port : "?");
    hot(box, () => [`${ifc} mesh`, `hub ↔ local peers, ${list.length} × /32 fan-out` +
      (rset.length ? ` · peer-side AllowedIPs: ${rset.join(", ")}` : "") + " · click to focus"]); clickFocus(box, ifc);
    const pdx = HUBX + 28 + meshIdx * 22, pdy = HUBY + hubH; meshIdx++;
    const pd = mk("circle", { cx: pdx, cy: pdy, r: 5.5, fill: col, class: "pdot hot" }, g2d);
    hot(pd, () => [`${ifc} :${port ? port.port : "?"}`, "hub mesh port"]); clickFocus(pd, ifc);
    const pl = mk("text", { x: pdx + 10, y: pdy - 8, class: "plab" }, g2d); pl.textContent = ifc; pl.setAttribute("fill", col);
    list.sort((a, b) => slash32(a.e.allowed).localeCompare(slash32(b.e.allowed), undefined, { numeric: true }));
    const dotX = 64 + mw - 14, lane = 64 + mw + 14;
    list.forEach((s, i) => {
      const n = N.get(s.oid), parent = physicalHostOf(N, n), y = my + 48 + i * rowStep;
      // The stack is one visual card but each row is a different tunnel. Tag
      // rows individually so selecting the far-side interface on six of nine
      // peers does not light the other three merely because their parent stack
      // contains at least one selected edge.
      const rowD = mk("g", {}, g2d), rowT = mk("g", {}, g2t);
      rowD.dataset.ifc = ifc; rowD.dataset.nodes = JSON.stringify([s.oid]); rowD.dataset.eids = JSON.stringify([s.e.id]);
      rowT.dataset.ifc = ifc; rowT.dataset.eids = JSON.stringify([s.e.id]);
      if (parent) {
        mk("text", { x: dotX - 12, y: y - 6, class: "htit", "text-anchor": "end" }, rowD).textContent = physicalHostLabel(parent);
      }
      const lbl = mk("text", { x: dotX - 12, y: y + (parent ? 7 : 3), class: "bsub", "text-anchor": "end" }, rowD);
      lbl.textContent = (n ? n.label : s.oid) || "";
      statusDot(rowD, {
        cx: dotX, cy: y, r: 4.5, cls: "sdot", eid: s.e.id, col,
        title: (n ? n.label : s.oid), prefix: slash32(s.e.allowed) + " · "
      });
      mk("path", { d: `M${dotX + 5},${y} H${lane}`, class: "tun", stroke: col, "stroke-width": 1.6 }, rowT);
    });
    const trunk = `M${lane},${my + 48 + (list.length - 1) * rowStep} V${my + 20} H${pdx} V${pdy + 6}`;
    const p = mk("path", { d: trunk, class: "tun", stroke: col, "stroke-width": 2 }, g2t);
    hot(p, () => [`${ifc} · mesh ×${list.length}`, "hub ↔ local peer /32 fan-out · click to focus"]); clickFocus(p, ifc);
    meshGeo.set(ifc, { x: 64 + mw, y: my + bh / 2 });
    my += bh + 44;
  }
  return { meshGeo, endY: my };
}

// Spokes that live in the hub's own zone sit as a row of chips above the far
// zones — a roaming admin client dialling into its own site, not a remote sub-
// network. Returns their anchors so a chip-to-chip hop leg can find them.
function drawTopChips({ gn, gd, gt, gf, grp }, { EPX, HUBX, HUBW, remoteIf }, N, hub, topSpokes, hubPort) {
  const topPos = new Map();
  topSpokes.forEach((s, i) => {
    const n = N.get(s.oid); if (!n) return;
    const col = ifColor(s.iface), cw = Math.max(200, n.label.length * 7 + 26);
    const cx0 = EPX + i * (cw + 24), cy = 96;
    const g2 = grp(gn, s.iface, { nodes: s.oid }), g2d = grp(gd, s.iface, { nodes: s.oid, eids: s.e.id }),
      g2t = grp(gt, s.iface, { eids: s.e.id }), g2f = grp(gf, s.iface, { eids: s.e.id });
    const parent = physicalHostOf(N, n);
    if (parent) {
      mk("rect", { x: cx0 - 10, y: cy - 26, width: cw + 20, height: 86, rx: 10, class: "hbox k-host" }, g2);
      mk("text", { x: cx0 + 2, y: cy - 10, class: "htit" }, g2).textContent = physicalHostLabel(parent);
    }
    const box = nodeCard(g2, { x: cx0, y: cy, w: cw, h: 50, node: n });
    hot(box, () => [n.label, `${n.kind} · ${hub.dc ? zoneKey(hub.dc) : ""} (dials in to the hub site)`]); clickFocus(box, s.iface);
    topPos.set(s.oid, { x: cx0, y: cy, k: 1 });
    statusDot(g2d, { cx: cx0, cy: cy + 25, eid: s.e.id, col, title: `${s.iface} · ${n.label}` });
    const port = hubPort.get(s.iface);
    if (port) {
      const lane = HUBX + HUBW + 26 + remoteIf.indexOf(s.iface) * 16;
      const d = `M${port.x + 6},${port.y} H${lane} V${cy + 25} H${cx0 - 6}`;
      tunnelRun(g2t, g2f, { d, col, edge: s.e, iface: s.iface, title: `${s.iface} → ${n.label}` });
    }
  });
  return topPos;
}

// Each far zone: a box, its endpoint rows (VMs nested in their physical host),
// the DNAT VIP stacks, and the reachable-CIDR bands on the right. Bands get a
// grey underlay bus per endpoint lane with the per-tunnel colour dashed on top,
// so one wire can carry several routes without drawing several wires. Returns
// the endpoint anchors and band positions the hop phase attaches to.
function drawZones({ gz, gg, gn, gd, gt, gf, grp }, geo, N, { vipsBy, meshGeo, hubPort }) {
  const { EPX, EPW, ZONE_R, BANDX, BANDW, LANE0, NATX, HUBX, HUBW, ROWH, HOSTPAD, remoteIf, zoneGeo, rowH, clH } = geo;
  const epPos = new Map(), bandPos = new Map();
  for (const zg of zoneGeo) {
    const bands = { list: [], by: new Map() };
    mk("rect", { x: EPX - 24, y: zg.y, width: ZONE_R - (EPX - 24) - 16, height: zg.h, rx: 12, class: "zone" }, gz);
    mk("text", { x: EPX - 8, y: zg.y + 22, class: "zlab" }, gz).textContent = zg.zk;
    mk("text", { x: BANDX, y: zg.y + 22, class: "zsub" }, gz).textContent = "reachable ranges";
    let ry = zg.y + 40, epIdx = 0;
    for (const cl of zg.clusters) {
      const parent = cl.parent;
      if (parent) {
        const gp = mk("g", {}, gn); gp.dataset.ifs = cl.items.map(x => x.iface || "").filter(Boolean).join("|");
        gp.dataset.nodes = JSON.stringify(cl.items.map(x => x.oid));
        mk("rect", { x: EPX - 10, y: ry, width: EPW + 20, height: clH(cl), rx: 10, class: "hbox k-host" }, gp);
        mk("text", { x: EPX + 2, y: ry + 16, class: "htit" }, gp).textContent = physicalHostLabel(parent);
      }
      let inY = parent ? ry + HOSTPAD - 6 : ry;
      for (const s of cl.items) {
        const n = N.get(s.oid); if (!n) continue;
        const g2 = grp(gn, s.iface || undefined, { nodes: s.oid }),
          g2d = grp(gd, s.iface || undefined, { nodes: s.oid, eids: s.e && s.e.id });
        let by = inY;
        const vips = vipsBy.get(s.oid) || [], vh = vips.length ? 28 + vips.length * 17 : 0;
        const box = nodeCard(g2, { x: EPX, y: by, w: EPW, h: ROWH - 10 + vh, node: n, cls: n.kind === "vm" ? "vmb" : "" });
        if (n.warnings && n.warnings.length) mk("text", { x: EPX + EPW - 12, y: by + 46, class: "warnb", "text-anchor": "end" }, g2).textContent = "WARNING";
        hot(box, () => [n.label, `${n.kind}${n.dc ? " · " + n.dc : ""}${n.observed ? " · observed " + n.observed : ""}${n.warnings ? " · " + n.warnings.join("; ") : ""}`]);
        if (s.iface) clickFocus(box, s.iface);
        if (vips.length) { // ledger DNAT VIPs stacked vertically, beads on a wire
          const vifc = vips[0].iface || s.iface, vcol = ifColor(vifc);
          const gv = grp(gd, vifc), gvt = grp(gt, vifc);
          const t = mk("text", { x: EPX + 12, y: by + 54, class: "bsub" }, gv);
          t.textContent = `DNAT VIP ×${vips.length}${vifc ? " · " + vifc : ""}`; t.setAttribute("fill", vcol);
          vips.forEach((v, i) => {
            const vy = by + 68 + i * 17;
            // A guessed owner is drawn hollow. The attachment is an inference from
            // label text, and a filled bead would present it as recorded fact.
            const dd = mk("circle", {
              cx: EPX + 20, cy: vy, r: 4.5,
              fill: v.guessed ? "none" : vcol, stroke: vcol, "stroke-width": v.guessed ? 1.6 : 0,
              class: "sdot hot"
            }, gv);
            hot(dd, () => [v.ip, `${v.label}${v.note ? " · " + v.note : ""} (IPAM ledger)` +
              (v.guessed ? " · owner GUESSED from label text — set ip_allocations.owner_public_key" : " · owner recorded")]);
            clickFocus(dd, vifc);
            mk("text", { x: EPX + 32, y: vy + 3, class: "bsub" }, gv).textContent = v.ip + (v.guessed ? " ?" : "");
          });
          const wire = mk("path", { d: `M${EPX + 20},${by + 68 + (vips.length - 1) * 17} V${by + 58}`, class: "tun", stroke: vcol, "stroke-width": 1.6 }, gvt);
          hot(wire, () => [`DNAT VIP ×${vips.length}`, "recorded in the IPAM ledger (ip_allocations) — outside WG collection · click to focus"]);
          clickFocus(wire, vifc);
          const mg = meshGeo.get(vifc);
          if (mg) { // DNAT destination = that iface's mesh; the parent tunnel carries it
            const d2 = `M${EPX - 6},${by + 62} H${NATX - 44} V${mg.y} H${mg.x + 6}`;
            const lp = mk("path", { d: d2, class: "reach", stroke: vcol }, gvt);
            hot(lp, () => [`DNAT → ${vifc} mesh`, "carried by the parent tunnel to the hub, then fanned out over the mesh (individual mappings live in sre-lb iptables)"]);
            clickFocus(lp, vifc);
            mk("circle", { cx: EPX - 6, cy: by + 62, r: 4, fill: vcol, class: "sdot" }, gv);
          }
        }
        const cy = by + (ROWH - 10) / 2;
        epPos.set(s.oid, { inX: EPX, outX: EPX + EPW, rowY: cy });
        if (s.iface && s.e) {
          const col = ifColor(s.iface), port = hubPort.get(s.iface);
          const din = statusDot(g2d, {
            cx: EPX, cy, eid: s.e.id, col, title: `${s.iface} · ${n.label}`,
            detail: s.back.length ? " · reverse " + cidrs(s.back[0].allowed).join(",") : ""
          });
          clickFocus(din, s.iface);
          if (port) {
            const g2t = grp(gt, s.iface, { eids: s.e.id }), g2f = grp(gf, s.iface, { eids: s.e.id });
            const lane = HUBX + HUBW + 26 + remoteIf.indexOf(s.iface) * 16;
            const d = `M${port.x + 6},${port.y} H${lane} V${cy} H${EPX - 6}`;
            tunnelRun(g2t, g2f, { d, col, edge: s.e, iface: s.iface, title: `${s.iface} → ${n.label}` });
          }
          const cs = cidrs(s.e.allowed);
          if (cs.length) {
            mk("circle", { cx: EPX + EPW, cy: cy, r: 5.5, fill: col, class: "pdot" }, g2d);
            for (const c of cs) {
              let b = bands.by.get(c);
              if (!b) { b = { cidr: c, refs: [] }; bands.by.set(c, b); bands.list.push(b); }
              b.refs.push({ iface: s.iface, eid: s.e.id, fromX: EPX + EPW, fromY: cy, lane: LANE0 + epIdx * 16 });
            }
          }
          epIdx++;
        }
        inY += rowH(s) + 10;
      }
      ry += clH(cl) + 14;
    }
    // bands: grey underlay bus per endpoint + dashed per-tunnel colour into each dot
    let byy = zg.y + 40;
    for (const b of bands.list) {
      const hgt = Math.max(44, 20 + b.refs.length * 17);
      const gb = mk("g", {}, gn); gb.dataset.ifs = b.refs.map(r => r.iface).join("|");
      gb.dataset.eids = JSON.stringify(b.refs.map(r => r.eid));
      gb.dataset.cidr = b.cidr;
      const r = mk("rect", { x: BANDX, y: byy, width: BANDW, height: hgt, rx: 8, class: "nbox band k-net" }, gb);
      mk("text", { x: BANDX + 14, y: byy + 20, class: "btit" }, gb).textContent = b.cidr;
      hot(r, () => [b.cidr, "reachable via: " + b.refs.map(x => x.iface).join(", ")]);
      if (!bandPos.has(b.cidr)) bandPos.set(b.cidr, []);
      bandPos.get(b.cidr).push({
        y: byy, n: b.refs.length, zoneY: zg.y, zoneH: zg.h, group: gb,
        eids: new Set(b.refs.map(r => r.eid))
      });
      b.refs.forEach((rf, i) => {
        const dy = byy + 15 + i * 17, col = ifColor(rf.iface);
        const g2 = grp(gt, rf.iface, { eids: rf.eid }), g2d = grp(gd, rf.iface, { eids: rf.eid });
        mk("circle", { cx: BANDX - 12, cy: dy, r: 5, fill: col, class: "pdot hot" }, g2d);
        // grey bus (underlay, one solid line per endpoint lane)
        mk("path", { d: `M${rf.fromX + 6},${rf.fromY} H${rf.lane} V${dy} H${BANDX - 18}`, class: "grey" }, gg);
        // per-tunnel dashed colour on top
        const p = mk("path", { d: `M${rf.fromX + 6},${rf.fromY} H${rf.lane} V${dy} H${BANDX - 18}`, class: "reach", stroke: col }, g2);
        hot(p, () => {
          const st = reading.stats[rf.eid] || {};
          return [`${rf.iface} → ${b.cidr}`, `${hsLabel(st.hs)} · rx ${fmtRate(st.rx)} tx ${fmtRate(st.tx)} · click to focus`]
        });
        clickFocus(p, rf.iface);
      });
      byy += hgt + 12;
    }
  }

  return { epPos, bandPos };
}

// Edges that never touch the hub. Grouped per far node because a pair can be
// collected from both sides, then drawn as chips continuing down the left column
// from where the mesh stacks ended. A hop's reach CIDR lands on the matching zone
// band when one was drawn, otherwise it gets its own chip underneath. The last
// pass handles legs whose both ends are chips (a personal VM to a roaming client).
function drawHops({ gn, gd, gt, gf, grp }, geo, N, hub, { hops, startY, epPos, bandPos, topPos }) {
  const { EPX, NATX, BANDX, EXTX, LANE0, zoneGeo } = geo;
  let hy = startY + 8;
  const hopBy = new Map(), extHops = [], rest = [], leftPos = new Map();
  for (const e of hops) {
    const sp = epPos.get(e.source) || epPos.get(e.target);
    const other = epPos.get(e.source) ? e.target : e.source;
    const tn = N.get(other);
    if (!sp || !tn) { rest.push(e); continue; }
    if (tn.kind === "external") { extHops.push({ e, sp, tn }); continue; }
    if (zoneKey(tn.dc) !== zoneKey(hub.dc)) continue;
    if (!hopBy.has(other)) hopBy.set(other, { tn, sp, edges: [] });
    hopBy.get(other).edges.push(e);
  }
  let extIdx = 0;
  for (const { e, sp, tn } of extHops) {
    const col = ifColor(e.iface), fk = hopKey(e, hub);
    const g2 = grp(gn, fk, { nodes: tn.id, eids: e.id }), g2t = grp(gt, fk, { eids: e.id });
    const zg = zoneGeo.find(z => sp.rowY >= z.y && sp.rowY <= z.y + z.h) || zoneGeo[0];
    const cy = zg.y + 52 + extIdx * 44; extIdx++;
    const r = mk("rect", { x: EXTX, y: cy - 15, width: 188, height: 32, rx: 8, class: "nbox ext" }, g2);
    mk("text", { x: EXTX + 10, y: cy - 1, class: "bsub" }, g2).textContent = tn.label.slice(0, 26);
    mk("text", { x: EXTX, y: zg.y + 22, class: "zsub" }, g2).textContent = extIdx === 1 ? "external / unknown" : "";
    hot(r, () => [tn.label, `external endpoint (observed during collection) · allowed ${e.allowed}`]);
    mk("circle", { cx: EXTX, cy: cy, r: 4.5, fill: col, class: "sdot" }, g2);
    const base = mk("path", { d: `M${sp.outX + 6},${sp.rowY} H${LANE0 + 126} V${cy} H${EXTX - 6}`, class: "tun dash", stroke: col, "stroke-width": 1.7 }, g2t);
    hot(base, () => {
      const st = reading.stats[e.id] || {};
      return [`${e.iface} → ${tn.label}`, `allowed ${e.allowed} · ${hsLabel(st.hs)} · undocumented terminus · click to focus`]
    });
    clickFocus(base, fk);
  }
  for (const [oid, { tn, sp, edges }] of hopBy) {
    const parent = physicalHostOf(N, tn);
    const parentNeed = parent ? physicalHostLabel(parent).length * 6.2 + 24 : 0;
    const bw2 = Math.max(200, tn.label.length * 7 + 26, parentNeed);
    const g2 = mk("g", {}, gn); g2.dataset.ifs = edges.map(e => hopKey(e, hub)).join("|");
    g2.dataset.nodes = JSON.stringify([oid]); g2.dataset.eids = JSON.stringify(edges.map(e => e.id));
    if (parent) {
      mk("rect", { x: 54, y: hy - 26, width: bw2 + 20, height: 88, rx: 10, class: "hbox k-host" }, g2);
      mk("text", { x: 66, y: hy - 10, class: "htit" }, g2).textContent = physicalHostLabel(parent);
    }
    const bx2 = nodeCard(g2, { x: 64, y: hy, w: bw2, h: 52, node: tn, cls: tn.kind === "vm" ? "vmb" : "" });
    hot(bx2, () => [tn.label, `${tn.kind}${tn.dc ? " · " + tn.dc : ""}`]);
    leftPos.set(oid, { x: 64, y: hy, w: bw2, k: edges.length });
    const chipR = 64 + bw2;
    let below = 0;
    edges.forEach((e, k) => {
      const col = ifColor(e.iface), hk = hopKey(e, hub), cy2 = hy + 18 + k * 16;
      const g2d = grp(gd, hk, { nodes: [oid], eids: e.id }), g2t = grp(gt, hk, { eids: e.id }),
        g2f = grp(gf, hk, { eids: e.id });
      const dd = statusDot(g2d, { cx: chipR, cy: cy2, eid: e.id, col, title: `${e.iface} · ${tn.label}` });
      clickFocus(dd, hk);
      mk("circle", { cx: sp.inX, cy: sp.rowY + 16 + k * 12, r: 5, fill: col, class: "pdot" }, g2d);
      const d = `M${chipR + 6},${cy2} H${EPX - 38 - k * 10} V${sp.rowY + 16 + k * 12} H${sp.inX - 6}`;
      tunnelRun(g2t, g2f, { d, col, edge: e, iface: hk, title: `${e.iface} ↔ ${tn.label}` });
      // reach: onto an existing zone band when drawn there, else a chip below
      cidrs(e.allowed).forEach(c => {
        const positions = bandPos.get(c) || [];
        const bp = positions.find(p => sp.rowY >= p.zoneY && sp.rowY <= p.zoneY + p.zoneH) || positions[0];
        if (bp) { // e.g. personal → seoul 201/110/130: dot on the seoul band itself
          bp.eids.add(e.id); bp.group.dataset.eids = JSON.stringify([...bp.eids]);
          const dy = bp.y + 15 + bp.n * 17; bp.n++;
          mk("circle", { cx: BANDX - 12, cy: dy, r: 5, fill: col, class: "pdot" }, g2d);
          const rp = mk("path", { d: `M${chipR + 6},${hy + 40} H${NATX - 96 - k * 8} V${dy} H${BANDX - 18}`, class: "reach", stroke: col }, g2t);
          hot(rp, () => [`${e.iface} → ${c}`, `reachable via ${tn.label} (peer-side AllowedIPs) · click to focus`]);
          clickFocus(rp, hk);
        } else {
          const byy = hy + 64 + below * 48; below++;
          const rb = mk("rect", { x: 94, y: byy, width: bw2 - 30, height: 40, rx: 8, class: "nbox band k-net" }, g2);
          mk("text", { x: 106, y: byy + 18, class: "btit" }, g2).textContent = c;
          mk("text", { x: 106, y: byy + 32, class: "bsub" }, g2).textContent = `reachable via ${e.iface}`;
          hot(rb, () => [c, `ranges the ${e.iface} tunnel carries behind ${tn.label}`]);
          mk("path", { d: `M80,${hy + 52} V${byy + 20} H88`, class: "reach", stroke: col }, g2t);
          mk("circle", { cx: 94, cy: byy + 20, r: 4, fill: col, class: "sdot" }, g2d);
        }
      });
    });
    hy += 66 + below * 48;
  }
  // chip-to-chip legs (both ends are chips, e.g. personal VM ↔ roaming client)
  for (const e of rest) {
    const a = leftPos.get(e.source) || leftPos.get(e.target);
    const bId = leftPos.get(e.source) ? e.target : e.source;
    const b = topPos.get(bId); if (!a || !b) continue;
    const col = ifColor(e.iface);
    const g2d = grp(gd, e.iface, { nodes: [e.source, e.target], eids: e.id }), g2t = grp(gt, e.iface, { eids: e.id }),
      g2f = grp(gf, e.iface, { eids: e.id });
    const ay = a.y + 18 + a.k * 16; a.k++;
    const byy = b.y + 25 + b.k * 12; b.k++;
    statusDot(g2d, {
      cx: a.x + a.w, cy: ay, eid: e.id, col,
      title: `${e.iface} · ${(N.get(bId) || {}).label || ""}`
    });
    mk("circle", { cx: b.x, cy: byy, r: 5, fill: col, class: "pdot" }, g2d);
    const d = `M${a.x + a.w + 6},${ay} H${b.x - 34} V${byy} H${b.x - 6}`;
    tunnelRun(g2t, g2f, {
      d, col, edge: e, iface: e.iface,
      title: `${e.iface} · ${(N.get(e.source) || {}).label || e.source} ↔ ${(N.get(e.target) || {}).label || e.target}`
    });
  }
}

// ---------- render ----------
function render(topo) {
  curTopo = topo; svg.innerHTML = ""; tunnels = []; statusDots = new Map(); vipFocusNodes = new Map();
  const { N, E, hub } = prep(topo);
  const gz = mk("g", {}, svg), gg = mk("g", {}, svg), gt = mk("g", {}, svg), gf = mk("g", {}, svg), gn = mk("g", {}, svg), gd = mk("g", {}, svg);
  if (!hub) {
    svg.setAttribute("viewBox", "0 0 800 200"); svg.setAttribute("width", 800); svg.setAttribute("height", 200);
    mk("text", { x: 40, y: 60, class: "ntit" }, gn).textContent = "no gateways — run `vctl wg sync` first"; return;
  }
  const grp = (parent, ifc, meta = {}) => {
    const g = mk("g", {}, parent);
    if (ifc) g.dataset.ifc = ifc;
    if (meta.nodes) g.dataset.nodes = JSON.stringify([].concat(meta.nodes).filter(Boolean));
    if (meta.eids) g.dataset.eids = JSON.stringify([].concat(meta.eids).filter(Boolean));
    if (meta.hubif) g.dataset.hubif = meta.hubif;
    return g;
  };
  // Paint targets, in z-order: zone chrome, grey bus, tunnels, flow animation,
  // node boxes, dots. Each drawing phase appends to these, so their creation
  // order here is what fixes what covers what.
  const L = { gz, gg, gt, gf, gn, gd, grp };

  // Measure first, then draw. Each phase below returns the anchors the later ones
  // need — hub ports, mesh anchors, endpoint rows, band slots — so the couplings
  // between them are the arguments rather than a shared pool of locals.
  const model = wiringModel(N, E, hub);
  const { spokes, mesh, hops, topSpokes, farSpokes } = model;
  const zmap = zoneBuckets(N, hub, { farSpokes, spokes, mesh, hops });
  const attached = attachVips(topo, N, spokes);
  const vipsBy = attached.vipsBy; vipFocusNodes = attached.vipFocusNodes;
  const geo = wiringGeometry(topo, N, hub, model, zmap, vipsBy);
  const { H, W, drawW } = geo;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  sizeCanvas(drawW, Math.round(drawW * H / W));

  drawChrome(L, geo, hub);
  drawLocalFabric(L, geo, topo, N, hub, spokes);
  const hubPort = drawHub(L, geo, hub);
  const { meshGeo, endY: meshEndY } = drawMeshStacks(L, geo, N, hub, model);
  const topPos = drawTopChips(L, geo, N, hub, topSpokes, hubPort);
  const { epPos, bandPos } = drawZones(L, geo, N, { vipsBy, meshGeo, hubPort });
  drawHops(L, geo, N, hub, { hops, startY: meshEndY, epPos, bandPos, topPos });

  buildLegend(); buildKindKey(); applyStats(); setFocus(focusIf);
  try {
    const bb = svg.getBBox(); const H2 = Math.min(H, bb.y + bb.height + 30);
    svg.setAttribute("viewBox", `0 0 ${W} ${H2}`);
    sizeCanvas(drawW, Math.round(drawW * H2 / W));
    if (drawW > canvas.clientWidth - 44) requestAnimationFrame(fitCanvas);
  } catch (_) { }
}

// ---------- focus ----------
// The walk. Every rule about what a tag means lives in focusPass; this is the
// recursion and the class toggle, which is all that needs a document.
function applyFocus(el, focused, inherited) {
  const { matched, dim } = focusPass(
    { data: el.dataset || {}, classes: el.classList, leaf: el.children.length === 0 },
    inherited, focus, focused);
  el.classList.toggle("dim", dim);
  // Keep traffic as data and presentation as state. A filtered-out path must
  // not retain the same `on` class as a visible, actively flowing tunnel; when
  // focus is cleared, the last sampled traffic state restores it immediately.
  if (el.classList.contains("flow")) {
    el.classList.toggle("on", el.dataset.flowing === "1" && !dim);
  }
  for (const c of el.children) applyFocus(c, focused, matched);
}

function setFocus(f) {
  focusIf = f;
  focus = focusClosure(f, curTopo, vipFocusNodes);
  for (const c of svg.children) applyFocus(c, f, false);
  document.querySelectorAll("#legend .i[data-if]").forEach(ch => {
    ch.classList.toggle("on", ch.dataset.if === f);
  });
  const all = document.querySelector("#legend .i[data-all]");
  if (all) all.classList.toggle("on", !f);
  const sel = document.getElementById("selection");
  sel.classList.toggle("on", !!f);
  sel.querySelector("b").textContent = f || "";
}

// ---------- legends and stats ----------
function buildKindKey() {
  const on = new Set();
  for (const el of svg.querySelectorAll("rect.nbox"))
    for (const c of el.classList) if (c.startsWith("k-")) on.add(c);
  document.getElementById("kind-key").innerHTML = kindKeyHTML(on);
}

function buildLegend() {
  // Build from the drawn canvas, not from every topology edge. The wiring layout
  // only draws hub-adjacent geometry, so an interface whose tunnels never reach
  // the hub has nothing to highlight — offering it a chip would dim the whole
  // diagram and light nothing. Runs after render(), so the geometry is in place.
  const ifs = new Set();
  for (const el of svg.querySelectorAll("[data-ifc],[data-ifs]")) {
    if (el.dataset.ifc) ifs.add(el.dataset.ifc);
    for (const i of (el.dataset.ifs || "").split("|")) if (i) ifs.add(i);
  }
  const el = document.getElementById("legend");
  const keys = [...ifs].sort(ifCmp);
  el.innerHTML = `<button type="button" class="i on" data-all>all</button>` + keys.map(i =>
    `<button type="button" class="i" data-if="${esc(i)}" title="${esc(i)}">` +
    `<span class="dt" style="background:${ifColor(i)}"></span>${esc(ifLabel(i, keys))}</button>`).join("");
  el.querySelector("[data-all]").addEventListener("click", () => setFocus(null));
  el.querySelectorAll(".i[data-if]").forEach(ch => ch.addEventListener("click", () => setFocus(focusIf === ch.dataset.if ? null : ch.dataset.if)));
}

function applyStats() {
  for (const t of tunnels) {
    const st = reading.stats[t.id];
    const flowing = !!(st && (st.rx > 0 || st.tx > 0));
    t.fl.dataset.flowing = flowing ? "1" : "0";
    if (flowing) {
      const r = st.rx + st.tx;
      t.fl.classList.toggle("on", !t.fl.classList.contains("dim"));
      t.fl.style.animationDuration = Math.max(.5, 2.6 - Math.log10(r + 1) * .38) + "s";
      t.base.setAttribute("stroke-width", Math.min(4.6, 2 + Math.log10(r + 1) * .5));
    } else t.fl.classList.remove("on");
  }
  const stateOf = new Map();
  for (const e of ((curTopo && curTopo.edges) || [])) stateOf.set(e.id, tunnelState(e, reading));
  for (const [eid, dot] of statusDots) {
    // Draw every dot, including tunnels nothing reported. Skipping them left the
    // previous frame's colour on screen, so an unobserved tunnel kept whatever
    // it last looked like — which is the opposite of saying "we do not know".
    const c = cssv("--" + (STATE_CLS[stateOf.get(eid) || "unknown"] || "muted"));
    dot.setAttribute("stroke", c);
    // The colour as a variable, the glow as a class rule.
    //
    // This used to write the drop-shadow into style.filter, and an inline style
    // beats a class — so .dim could take a bead's opacity to 6% and the glow
    // went on burning through at full strength. Every two seconds this ran and
    // relit them. Filtering read as "a few dots changed colour" because that is
    // literally what was left on screen: measured, 16 of 50 beads glowing while
    // dimmed, and the effect only existed live, which is why a replay harness
    // with no stats never showed it. scripts/wg-dashboard-check.mjs now injects
    // stats for exactly this reason.
    dot.style.setProperty("--glow", c);
  }
  const edges = (curTopo && curTopo.edges) || [];
  const n = countStates(edges, reading);
  document.getElementById("state-key").innerHTML = stateKeyHTML(n);

  const s = liveSummary(n, edges.length);
  const live = document.getElementById("live-summary");
  live.className = s.cls;
  live.querySelector("span").textContent = s.text;
  live.title = s.title;
}

function renderDrift(list) {
  document.getElementById("drift").textContent = driftText(list);
}

function updateMeta(topo, at) {
  const zones = new Set(topo.nodes.filter(n => n.dc).map(n => zoneKey(n.dc)));
  document.getElementById("site-count").textContent = zones.size;
  document.getElementById("gateway-count").textContent = topo.nodes.filter(n => n.kind === "gateway").length;
  document.getElementById("tunnel-count").textContent = topo.edges.length;
  document.getElementById("updated-at").textContent = new Date(at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const el = document.getElementById("topology-at");
  const c = topologyClock(topo.collectedAt, Date.now());
  el.textContent = c.text;
  el.title = c.title;
  el.className = c.stale ? "stale" : "";
}

// ---------- theme ----------
// The palette is resolved from CSS variables and then written onto SVG
// attributes, so a theme switch is not a repaint — the interface colours are
// already baked into the drawn elements. The cache is dropped and the diagram
// redrawn from the topology that is already in hand, which is also why the
// current focus and zoom are restored around it: a reader who switched themes
// asked about the light, not about which interface they had selected.
function applyTheme(name) {
  document.documentElement.setAttribute("data-theme", name);
  document.getElementById("theme-toggle").textContent = name.toUpperCase();
  try { localStorage.setItem("vctl-wg-theme", name); } catch (e) { }
  if (!lastTopo) return;
  const keepFocus = focusIf, keepZoom = zoom;
  ifColMap.clear();
  render(lastTopo);
  setZoom(keepZoom);
  if (keepFocus) setFocus(keepFocus);
  applyStats();
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("vctl-wg-theme"); } catch (e) { }
  // No stored answer means follow the desktop, the way the rest of the tooling
  // does. An explicit choice outranks it and survives a reload.
  const want = saved || (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", want);
  document.getElementById("theme-toggle").textContent = want.toUpperCase();
}

// ---------- boot: injected BOOT replay (demo) or live fetch + SSE ----------
function boot() {
  svg = document.getElementById("net");
  tip = document.getElementById("tip");
  canvas = document.getElementById("canvas");

  initTheme();
  svg.addEventListener("click", e => { if (e.target === svg || e.target.classList.contains("zone")) setFocus(null); });
  document.getElementById("theme-toggle").addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light"));
  document.getElementById("zoom-in").addEventListener("click", () => setZoom(zoom + .15));
  document.getElementById("zoom-out").addEventListener("click", () => setZoom(zoom - .15));
  document.getElementById("zoom-fit").addEventListener("click", fitCanvas);
  document.querySelector("#selection button").addEventListener("click", () => setFocus(null));
  document.addEventListener("keydown", ev => {
    if (ev.key === "Escape") setFocus(null);
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "=") { ev.preventDefault(); setZoom(zoom + .15); }
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "-") { ev.preventDefault(); setZoom(zoom - .15); }
    if ((ev.ctrlKey || ev.metaKey) && ev.key === "0") { ev.preventDefault(); fitCanvas(); }
  });

  const BOOT = window.WG_BOOT || null;
  if (BOOT) {
    lastTopo = BOOT.topology;
    render(BOOT.topology);
    const frames = BOOT.frames || []; let fi = 0;
    const ap = () => {
      // A replay frame is an /events payload. It used to be only the stats map,
      // with pollErrors forced to {} and the clock forced to now — so the replay
      // could not reach three of the six tunnel states, and the two that depend
      // on the clock could not be reproduced at all. Those were exactly the
      // states that had to be re-staged by hand every time. A bare stats map is
      // still accepted, because the older fixture dumps are that shape.
      const f = frames.length ? frames[fi % frames.length] : {};
      const d = f && f.edges ? f : { edges: f };
      reading = { stats: d.edges || {}, pollErrors: d.errors || {}, at: d.at || Date.now() / 1000 };
      updateMeta(BOOT.topology, reading.at); applyStats(); renderDrift(d.drift || []); fi++;
    };
    ap(); if (frames.length > 1) setInterval(ap, 2000);
    document.getElementById("health").textContent = "demo replay";
    return;
  }
  fetch("topology").then(r => r.json()).then(topo => {
    lastTopo = topo;
    render(topo);
    const es = new EventSource("events");
    es.onmessage = ev => {
      // Errors and the frame time are inputs to tunnelState, so they have to be
      // in place before applyStats runs — otherwise a failed gateway's tunnels
      // keep rendering their last sample as if it were current. They travel as
      // one `reading` for that reason.
      const d = JSON.parse(ev.data);
      reading = { stats: d.edges || {}, pollErrors: d.errors || {}, at: d.at || 0 };
      updateMeta(topo, d.at); applyStats();
      const errN = Object.keys(d.errors || {}).length, h = document.getElementById("health");
      h.className = "health " + (errN ? "fail" : "ok");
      h.textContent = errN ? `${errN} poll failures` : "live polling ok";
      document.getElementById("errs").textContent = Object.entries(d.errors || {}).map(([k, v]) => `! ${k}: ${v}`).join("\n");
      renderDrift(d.drift || []);
    };
  }).catch(err => {
    const h = document.getElementById("health");
    h.className = "health fail"; h.textContent = "topology connection failed";
    document.getElementById("errs").textContent = `! topology: ${err.message}`;
  });
}

// Only when there is a page to draw on. Requiring this file under Node — which
// nothing does, the model is what tests import — must not reach for a document.
if (typeof document !== "undefined" && document.getElementById("net")) boot();
