// wg_layers.js — the layered architecture view: underlay under overlay.
//
// Everything drawn here comes out of the topology. Sites, farms, hosts and
// networks are nodes with a `layer`; placement and membership are links; the
// derived block says which tunnel carries which network, how, and where it is
// masqueraded. No site, farm, host or network is named in this file. A new farm
// is a row in the database and a box here in the same deploy — that is the
// whole reason the declared topology exists.
//
// The hub view (wg_view.js) stays the default; this is `?view=layers`. The two
// share the SVG helpers and the tooltip, which the caller hands in, so this
// file can also be laid out under Node with fakes for a smoke test.

const LAYERS_METHOD_VAR = { direct: "--c2", proxy: "--c6", dnat: "--c7" };
const LAYERS_METHOD_WORD = { direct: "direct · IP kept", proxy: "proxy · TCP terminated", dnat: "dnat · 1:1 mapped" };
const LM = {
  margin: 28, siteGap: 40, sitePad: 14, siteHead: 30,
  chipW: 150, chipH: 22, chipGap: 8,
  farmPad: 12, farmHead: 24, farmGap: 14,
  hostW: 210, hostHead: 24, row: 19, hostPad: 8, hostGap: 12, hostCols: 3,
  netRow: 20, trayRow: 20, trayCols: 4, trayW: 150,
};

// layersIndex turns the topology into the lookups the layout walks: node by
// id, links by endpoint, and the two relations that place things.
function layersIndex(topo) {
  const N = new Map((topo.nodes || []).map(n => [n.id, n]));
  const out = new Map(), inn = new Map();
  for (const l of topo.links || []) {
    if (!out.has(l.source)) out.set(l.source, []);
    if (!inn.has(l.target)) inn.set(l.target, []);
    out.get(l.source).push(l); inn.get(l.target).push(l);
  }
  const kindOf = id => (N.get(id) || {}).kind || "";
  const memberOf = (id, kind) => {
    for (const l of out.get(id) || []) if (l.kind === "member-of" && kindOf(l.target) === kind) return l.target;
    return null;
  };
  const parentOf = id => {
    const n = N.get(id);
    if (n && n.parent && N.has(n.parent)) return n.parent;
    for (const l of out.get(id) || []) if (l.kind === "placed-on") return l.target;
    return null;
  };
  // A declared tunnel names its machine in attrs; when a declared VM carries
  // that name it is the machine, otherwise the name may be a node id itself.
  const machineOf = id => {
    const n = N.get(id);
    if (!n) return null;
    if (n.kind !== "tunnel") return id;
    const h = n.attrs && n.attrs.host;
    if (!h) return null;
    if (N.has("vm/" + h)) return "vm/" + h;
    if (N.has(h)) return h;
    return null;
  };
  // A machine is a physical host, or anything with no parent that the operator
  // placed straight in a farm or site — a load balancer that is also a tunnel
  // endpoint is drawn by the sync as a gateway, and it is still a box.
  const INFRA = new Set(["site", "farm", "network", "edge", "egress"]);
  const isMachine = id => {
    const n = N.get(id);
    if (!n || INFRA.has(n.kind)) return false;
    if (n.kind === "physical-host") return true;
    return !parentOf(id) && !!(memberOf(id, "farm") || memberOf(id, "site"));
  };
  return { N, out, inn, kindOf, memberOf, parentOf, machineOf, isMachine };
}

// layersLayout assigns every node to a site column and a slot inside it, and
// returns geometry only — nothing here touches the document, so it can be
// checked under Node against a real /topology dump.
function layersLayout(topo) {
  const X = layersIndex(topo);
  const { N, kindOf, memberOf, parentOf, machineOf, isMachine } = X;
  const nodes = topo.nodes || [];

  // Sites are declared nodes; a graph without any falls back to the collected
  // `dc` prefix so the view still has columns.
  let siteIds = nodes.filter(n => n.kind === "site").map(n => n.id);
  const synthetic = siteIds.length === 0;
  const siteByZone = new Map();
  if (synthetic) {
    for (const n of nodes) { const z = zoneKey(n.dc); if (z && !siteByZone.has(z)) siteByZone.set(z, "site/" + z); }
    siteIds = [...siteByZone.values()];
  } else {
    for (const id of siteIds) siteByZone.set(id.replace(/^site\//, ""), id);
  }
  const zoneSite = dc => { const z = zoneKey(dc); return siteByZone.get(z) || null; };

  const siteOf = new Map();
  // Where a machine is: its farm's site, else the site it is a member of, else
  // the collected dc.
  const placeOf = (id, n) => { const f = memberOf(id, "farm"); return f ? resolveSite(f) : (memberOf(id, "site") || zoneSite(n.dc)); };
  const resolveSite = id => {
    if (siteOf.has(id)) return siteOf.get(id);
    const n = N.get(id); let s = null;
    if (n) {
      switch (n.kind) {
        case "site": s = id; break;
        case "farm": s = memberOf(id, "site") || zoneSite(n.dc); break;
        case "physical-host": s = placeOf(id, n); break;
        case "network": {
          const seg = id.split("/")[1];
          if (seg === "overlay") s = "overlay";
          else if (N.has("farm/" + seg)) s = resolveSite("farm/" + seg);
          else if (siteByZone.has(seg)) s = siteByZone.get(seg);
          else s = zoneSite(n.dc);
          break;
        }
        case "edge": case "egress": s = memberOf(id, "site") || zoneSite(n.dc); break;
        case "tunnel": { const m = machineOf(id); s = m ? resolveSite(m) : zoneSite(n.dc); break; }
        default: {
          if (isMachine(id)) { s = placeOf(id, n); break; }
          const p = parentOf(id); s = p ? resolveSite(p) : zoneSite(n.dc);
        }
      }
    }
    siteOf.set(id, s || "unplaced");
    return siteOf.get(id);
  };
  for (const n of nodes) resolveSite(n.id);

  // Farm of a network by its id key, else nothing — networks with no farm are
  // drawn at site level.
  const farmOfNet = id => { const seg = id.split("/")[1]; return N.has("farm/" + seg) ? "farm/" + seg : null; };

  // Placement rows: what sits inside each host box. Collected placement
  // (parent), declared placement (placed-on), and unsynced tunnels through the
  // VM they name all land in the same list.
  const placed = new Map();
  const addPlaced = (host, id) => { if (!placed.has(host)) placed.set(host, []); if (!placed.get(host).includes(id)) placed.get(host).push(id); };
  for (const n of nodes) {
    if (n.kind === "tunnel") { const m = machineOf(n.id); const p = m && parentOf(m); if (p) addPlaced(p, n.id); continue; }
    const p = parentOf(n.id); if (p && isMachine(p)) addPlaced(p, n.id);
  }
  for (const [, list] of placed) list.sort((a, b) => a.localeCompare(b));
  const isPlaced = new Set([...placed.values()].flat());

  const columns = [];
  const order = [...siteIds];
  if (nodes.some(n => siteOf.get(n.id) === "overlay")) order.push("overlay");
  if (nodes.some(n => siteOf.get(n.id) === "unplaced")) order.push("unplaced");

  const pos = new Map(); // node id → {x,y,w,h,kind,anchorL,anchorR}
  const hostBoxH = host => LM.hostHead + Math.max(1, (placed.get(host) || []).length) * LM.row + LM.hostPad;

  // Every column is measured before anything is placed, so total width is known
  // before the first x.
  const measured = order.map(site => {
    const inSite = nodes.filter(n => siteOf.get(n.id) === site);
    const farms = inSite.filter(n => n.kind === "farm").sort((a, b) => a.id.localeCompare(b.id));
    const hostsOf = f => inSite.filter(n => isMachine(n.id) && memberOf(n.id, "farm") === f).sort((a, b) => a.id.localeCompare(b.id));
    const netsOf = f => inSite.filter(n => n.kind === "network" && farmOfNet(n.id) === f).sort((a, b) => a.id.localeCompare(b.id));
    const looseHosts = inSite.filter(n => isMachine(n.id) && !memberOf(n.id, "farm")).sort((a, b) => a.id.localeCompare(b.id));
    const looseNets = inSite.filter(n => n.kind === "network" && !farmOfNet(n.id)).sort((a, b) => a.id.localeCompare(b.id));
    const chips = inSite.filter(n => n.kind === "edge" || n.kind === "egress").sort((a, b) => a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id));
    // The tray holds endpoints that are in this site but on no host: clients,
    // external peers, VMs nobody placed. Tunnels need somewhere to land.
    const tray = inSite.filter(n => !isPlaced.has(n.id) && !isMachine(n.id) && !["site", "farm", "network", "edge", "egress"].includes(n.kind)).sort((a, b) => a.id.localeCompare(b.id));

    const gridW = cols => cols * LM.hostW + (cols - 1) * LM.hostGap;
    const farmW = f => Math.max(gridW(Math.min(LM.hostCols, Math.max(1, hostsOf(f.id).length))), 3 * (LM.chipW + LM.chipGap)) + 2 * LM.farmPad;
    const innerW = Math.max(
      ...farms.map(farmW),
      gridW(Math.min(LM.hostCols, Math.max(1, looseHosts.length))),
      Math.min(LM.trayCols, Math.max(1, tray.length)) * (LM.trayW + LM.chipGap),
      3 * (LM.chipW + LM.chipGap), 380);
    const w = innerW + 2 * LM.sitePad;
    return { site, inSite, farms, hostsOf, netsOf, looseHosts, looseNets, chips, tray, w, innerW };
  });

  let x = LM.margin, maxH = 0;
  for (const m of measured) {
    const { site, farms, hostsOf, netsOf, looseHosts, looseNets, chips, tray, w, innerW } = m;
    let y = LM.margin + LM.siteHead;
    const x0 = x + LM.sitePad;
    const col = { site, label: (N.get(site) || {}).label || site.replace(/^site\//, ""), x, y: LM.margin, w, farms: [], hostBoxes: [], netRows: [], chips: [], tray: [] };

    // Perimeter: edges and egress, the underlay the tunnels transit.
    if (chips.length) {
      chips.forEach((c, i) => {
        const cx = x0 + (i % 3) * (LM.chipW + LM.chipGap), cy = y + Math.floor(i / 3) * (LM.chipH + LM.chipGap);
        const p = { x: cx, y: cy, w: LM.chipW, h: LM.chipH, kind: c.kind };
        pos.set(c.id, p); col.chips.push(c.id);
      });
      y += Math.ceil(chips.length / 3) * (LM.chipH + LM.chipGap) + LM.farmGap;
    }

    const layHosts = (hosts, x1, y1, width) => {
      const cols = Math.max(1, Math.min(LM.hostCols, Math.floor((width + LM.hostGap) / (LM.hostW + LM.hostGap))));
      let rowY = y1, rowH = 0;
      hosts.forEach((h, i) => {
        if (i && i % cols === 0) { rowY += rowH + LM.hostGap; rowH = 0; }
        const hh = hostBoxH(h.id);
        const hx = x1 + (i % cols) * (LM.hostW + LM.hostGap);
        pos.set(h.id, { x: hx, y: rowY, w: LM.hostW, h: hh, kind: "physical-host", machine: true });
        col.hostBoxes.push(h.id);
        (placed.get(h.id) || []).forEach((id, r) => {
          const ry = rowY + LM.hostHead + r * LM.row;
          pos.set(id, { x: hx + 6, y: ry, w: LM.hostW - 12, h: LM.row - 3, kind: kindOf(id), inHost: h.id });
        });
        rowH = Math.max(rowH, hh);
      });
      return hosts.length ? rowY + rowH - y1 : 0;
    };
    const layNets = (nets, x1, y1, width) => {
      nets.forEach((n, i) => {
        pos.set(n.id, { x: x1, y: y1 + i * LM.netRow, w: width, h: LM.netRow - 4, kind: "network" });
        col.netRows.push(n.id);
      });
      return nets.length * LM.netRow;
    };

    for (const f of farms) {
      const hosts = hostsOf(f.id), nets = netsOf(f.id);
      const fx = x0, fy = y, fw = innerW;
      let iy = fy + LM.farmHead;
      iy += layHosts(hosts, fx + LM.farmPad, iy, fw - 2 * LM.farmPad);
      if (hosts.length) iy += LM.farmGap;
      iy += layNets(nets, fx + LM.farmPad, iy, fw - 2 * LM.farmPad);
      const fh = Math.max(iy - fy + LM.farmPad, LM.farmHead + LM.row);
      pos.set(f.id, { x: fx, y: fy, w: fw, h: fh, kind: "farm" });
      col.farms.push(f.id);
      y = fy + fh + LM.farmGap;
    }
    if (looseHosts.length) { y += layHosts(looseHosts, x0, y, innerW) + LM.farmGap; }
    if (looseNets.length) { y += layNets(looseNets, x0, y, innerW) + LM.farmGap; }
    if (tray.length) {
      const cols = Math.max(1, Math.min(LM.trayCols, Math.floor((innerW + LM.chipGap) / (LM.trayW + LM.chipGap))));
      tray.forEach((t, i) => {
        const tx = x0 + (i % cols) * (LM.trayW + LM.chipGap), ty = y + Math.floor(i / cols) * (LM.trayRow + 4);
        pos.set(t.id, { x: tx, y: ty, w: LM.trayW, h: LM.trayRow, kind: t.kind, tray: true });
        col.tray.push(t.id);
      });
      y += Math.ceil(tray.length / cols) * (LM.trayRow + 4) + LM.farmGap;
    }
    col.h = Math.max(y - LM.margin, LM.siteHead + LM.row * 2);
    columns.push(col);
    maxH = Math.max(maxH, col.h);
    x += w + LM.siteGap;
  }
  const W = x - LM.siteGap + LM.margin, H = maxH + 2 * LM.margin;
  for (const c of columns) c.h = maxH;
  return { X, columns, pos, W, H, placed, siteOf };
}

// anchor returns the point a line should meet a laid-out box at, on the side
// facing `towardX`.
function layersAnchor(p, towardX) {
  const right = towardX > p.x + p.w / 2;
  return { x: right ? p.x + p.w : p.x, y: p.y + p.h / 2, right };
}

function layersCurve(a, b) {
  const dx = Math.max(40, Math.abs(b.x - a.x) / 2);
  const c1 = a.right ? a.x + dx : a.x - dx, c2 = b.right ? b.x + dx : b.x - dx;
  return `M${a.x},${a.y} C${c1},${a.y} ${c2},${b.y} ${b.x},${b.y}`;
}

// renderLayers draws the layout into `svg` and the derived summary into the
// `aside`. H is the helper bag from wg_view.js: mk, hot, esc, cssv, ifColor,
// sizeCanvas, kindLabel.
function renderLayers(svg, aside, topo, H) {
  const { mk, hot, esc, cssv, ifColor, sizeCanvas, kindLabel } = H;
  const L = layersLayout(topo);
  const { X, columns, pos, W } = L;
  const { N } = X;
  const d = topo.derived || { failure_domains: [], paths: [], snat: [], gaps: [] };
  svg.innerHTML = "";
  const gz = mk("g", { class: "ly-zones" }, svg), gl = mk("g", { class: "ly-links" }, svg), gt = mk("g", { class: "ly-tunnels" }, svg), gn = mk("g", { class: "ly-nodes" }, svg);

  if (!columns.length) {
    svg.setAttribute("viewBox", "0 0 800 200"); sizeCanvas(800, 200);
    mk("text", { x: 40, y: 60, class: "ntit" }, gn).textContent = "nothing declared — seed net_entities (vctl wg entity set …)";
    return;
  }

  const text = (p, x, y, cls, s) => { const t = mk("text", { x, y, class: cls }, p); t.textContent = s; return t; };
  // hot() takes a thunk returning [title, meta] and escapes both; meta lines
  // are newline-joined and the tooltip renders them pre-line.
  const attrsLines = a => Object.entries(a || {}).filter(([k]) => k !== "inventory").map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
  const tipFor = (n, extra = []) => () => [n.label || n.id,
    [kindLabel(n.kind) + (n.layer ? " · " + n.layer : ""), ...(n.ip ? ["ip: " + n.ip] : []), ...(n.tunnelIp ? ["tunnel: " + n.tunnelIp] : []), ...attrsLines(n.attrs), ...extra].join("\n")];

  // Site columns, then farms inside them.
  for (const c of columns) {
    mk("rect", { x: c.x, y: c.y, width: c.w, height: c.h, rx: 12, class: "ly-site" }, gz);
    text(gz, c.x + LM.sitePad, c.y + 19, "ly-sitelab", (c.site === "overlay" ? "OVERLAY" : c.site === "unplaced" ? "UNPLACED" : "SITE") + " · " + c.label);
    for (const fid of c.farms) {
      const p = pos.get(fid), n = N.get(fid);
      const r = mk("rect", { x: p.x, y: p.y, width: p.w, height: p.h, rx: 9, class: "ly-farm" }, gz);
      text(gz, p.x + LM.farmPad, p.y + 16, "ly-farmlab", "FARM · " + (n.label || fid));
      hot(r, tipFor(n));
    }
  }

  // Perimeter chips and unplaced tray share one chip shape.
  const chip = (id, cls) => {
    const p = pos.get(id), n = N.get(id);
    const g = mk("g", { class: "ly-chip " + cls }, gn);
    mk("rect", { x: p.x, y: p.y, width: p.w, height: p.h, rx: 5 }, g);
    text(g, p.x + 8, p.y + p.h / 2 + 3.5, "ly-chiplab", (n.label || id).slice(0, 22));
    hot(g, tipFor(n));
  };
  for (const c of columns) { for (const id of c.chips) chip(id, "ly-" + N.get(id).kind); for (const id of c.tray) chip(id, "ly-tray ly-" + N.get(id).kind); }

  // Hosts with their placement rows.
  for (const c of columns) for (const hid of c.hostBoxes) {
    const p = pos.get(hid), n = N.get(hid);
    const g = mk("g", { class: "ly-host" }, gn);
    mk("rect", { x: p.x, y: p.y, width: p.w, height: p.h, rx: 7 }, g);
    // The title is the machine's name, never the operator's label: a box that
    // reads "A compute" four times over says nothing. The label is in the tip.
    const name = hid.startsWith("host|") ? hid.slice(5) : (n.label || hid);
    text(g, p.x + 8, p.y + 16, "ly-hostlab", name.slice(0, 30));
    const own = (n.ifaces || []).map(i => i.name || i.iface || i).filter(Boolean);
    const side = own.length ? own.join(" ") : (n.ip || "");
    if (side) text(g, p.x + p.w - 8, p.y + 16, own.length ? "ly-rowtag" : "ly-hostip", side).setAttribute("text-anchor", "end");
    hot(g.firstChild, tipFor(n, n.label && n.label !== name ? ["label: " + n.label] : []));
    for (const id of L.placed.get(hid) || []) {
      const q = pos.get(id), m = N.get(id);
      const gr = mk("g", { class: "ly-row ly-" + m.kind + (m.kind === "tunnel" ? " ly-unsynced" : "") }, gn);
      mk("rect", { x: q.x, y: q.y, width: q.w, height: q.h, rx: 4 }, gr);
      const ifs = (m.ifaces || []).map(i => i.name || i.iface || i).filter(Boolean);
      const tag = m.kind === "tunnel" ? "declared · unsynced" : ifs.length ? ifs.join(" ") : kindLabel(m.kind);
      text(gr, q.x + 6, q.y + 12, "ly-rowlab", (m.label || id).slice(0, 26));
      text(gr, q.x + q.w - 6, q.y + 12, "ly-rowtag", tag).setAttribute("text-anchor", "end");
      hot(gr, tipFor(m));
    }
  }

  // Networks as buses.
  for (const c of columns) for (const nid of c.netRows) {
    const p = pos.get(nid), n = N.get(nid);
    const g = mk("g", { class: "ly-net" }, gn);
    mk("line", { x1: p.x, y1: p.y + p.h / 2, x2: p.x + p.w, y2: p.y + p.h / 2 }, g);
    const cidr = n.attrs && n.attrs.cidr ? " · " + n.attrs.cidr : "";
    const lab = text(g, p.x + 10, p.y + p.h / 2 - 4, "ly-netlab", (n.label || nid.split("/").slice(2).join("/")) + cidr);
    lab.setAttribute("class", "ly-netlab");
    hot(g, tipFor(n, d.paths.filter(pt => pt.network === nid).map(pt => `carried by ${pt.tunnel} (${pt.method}${pt.snat_at ? ", snat@" + pt.snat_at : ""})`)));
  }

  // Overlay: collected tunnels between endpoints, coloured per interface like
  // the hub view so the two stay readable side by side.
  for (const e of topo.edges || []) {
    const a = pos.get(e.source), b = pos.get(e.target);
    if (!a || !b) continue;
    const pa = layersAnchor(a, b.x), pb = layersAnchor(b, a.x);
    const path = mk("path", { d: layersCurve(pa, pb), class: "ly-wire", stroke: ifColor(e.iface || "") }, gt);
    hot(path, () => [e.iface || "tunnel", `${e.source} ↔ ${e.target}` + (e.allowed ? "\nallowed: " + e.allowed : "")]);
  }

  // Declared patterns: carries (coloured by method, SNAT marked at the source)
  // and transits (thin, ordered), from the derived paths.
  for (const pt of d.paths) {
    const a = pos.get(pt.tunnel), b = pos.get(pt.network);
    if (!a || !b) continue;
    const pa = layersAnchor(a, b.x), pb = layersAnchor(b, a.x);
    const col = cssv(LAYERS_METHOD_VAR[pt.method] || "--c5");
    const g = mk("g", { class: "ly-carry ly-m-" + (pt.method || "unknown") + (pt.uncollected ? " ly-unsynced" : "") }, gl);
    mk("path", { d: layersCurve(pa, pb), stroke: col }, g);
    if (pt.snat_at) { mk("circle", { cx: pa.x + (pa.right ? 9 : -9), cy: pa.y, r: 4.5, class: "ly-snat", stroke: col }, g); }
    const link = (topo.links || []).find(l => l.kind === "carries" && l.source === pt.tunnel && l.target === pt.network) || {};
    hot(g, () => [LAYERS_METHOD_WORD[pt.method] || pt.method || "carries", [
      `${pt.tunnel} → ${pt.network}${pt.cidr ? " · " + pt.cidr : ""}`,
      pt.snat_at ? `SNAT at ${pt.snat_at}` : "", pt.uncollected ? "declared, never synced" : "",
      ...attrsLines(link.attrs).filter(s => !/^(method|snat_at):/.test(s)),
      `path: ${pt.hops.join(" → ")}`].filter(Boolean).join("\n")]);
  }
  for (const l of topo.links || []) {
    if (l.kind !== "transits") continue;
    const a = pos.get(l.source), b = pos.get(l.target);
    if (!a || !b) continue;
    const pa = layersAnchor(a, b.x), pb = layersAnchor(b, a.x);
    const path = mk("path", { d: layersCurve(pa, pb), class: "ly-transit" }, gl);
    hot(path, () => ["transits", `${l.source} → ${l.target}` + (l.attrs && l.attrs.order ? `\nhop ${l.attrs.order}` : "")]);
  }

  svg.setAttribute("viewBox", `0 0 ${W} ${L.H}`);
  sizeCanvas(W, L.H);
  renderDerivedAside(aside, topo, d, N, esc);
}

// renderDerivedAside lists what the layout cannot show as geometry: which host
// takes the most with it, and what nothing confirmed.
function renderDerivedAside(aside, topo, d, N, esc) {
  if (!aside) return;
  const lab = id => esc((N.get(id) || {}).label || id);
  const fds = d.failure_domains.filter(f => f.tunnels.length).slice(0, 8);
  const gaps = d.gaps || [];
  aside.innerHTML =
    `<h2>Failure domains <span>${d.failure_domains.length} hosts · ${d.paths.length} paths · ${d.snat.length} SNAT rules</span></h2>` +
    `<ol class="ly-fd">${fds.map(f => `<li><b>${lab(f.host)}</b><span class="tk">${esc(f.farm ? f.farm.replace(/^farm\//, "") : "")}${f.site ? " · " + esc(f.site) : ""}</span>` +
      `<div>${f.tunnels.length} endpoint${f.tunnels.length === 1 ? "" : "s"} · ${f.carries ?? 0} network${f.carries === 1 ? "" : "s"} carried</div>` +
      `<div class="tk">${f.tunnels.map(lab).join(", ")}</div></li>`).join("")}</ol>` +
    `<h2>Method <span>legend</span></h2><div class="ly-legend">${Object.keys(LAYERS_METHOD_VAR).map(m => `<i style="background:var(${LAYERS_METHOD_VAR[m]})"></i>${esc(LAYERS_METHOD_WORD[m])}`).join("")}<i class="ly-snat-key"></i>SNAT at source</div>` +
    (gaps.length ? `<h2>Gaps <span>${gaps.length}</span></h2><ul class="ly-gaps">${gaps.map(g => `<li><b>${esc(g.kind)}</b> ${lab(g.subject)}<div class="tk">${esc(g.detail || "")}</div></li>`).join("")}</ul>` : "");
}

// Under Node the layout is what gets exercised; the document never is.
if (typeof module !== "undefined") module.exports = { layersIndex, layersLayout, renderLayers, layersAnchor, layersCurve };
