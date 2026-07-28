// Standalone audit harness: replays the SHIPPED client layout + edge-label
// placement arithmetic from go-server/static/js/topology.js, using the solver's
// own estimateTextWidth as the measureText stand-in.
import { readFileSync } from 'node:fs';
import { estimateTextWidth } from './src/nodeMetrics.ts';

const DEG = Math.PI / 180;
const layouts = {
  desktop: JSON.parse(readFileSync(new URL('./output/desktop-layout.json', import.meta.url))),
};

const W = Number(process.env.AW || 1900);
const H = Number(process.env.AH || 1000);

const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));

const measure = (t, f) => estimateTextWidth(t, f);

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub) {
  const labelW = measure(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const sw = measure(l, fontSub); if (sw > subW) subW = sw; }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0)); }
  return { w, h, halfW: w / 2, halfH: h / 2 };
}

const SOURCES = [
  { id: 'root', label: 'Root / TLD', sub: 'IANA Root Zone\nTLD Registries', zone: 'source' },
  { id: 'rdap', label: 'RDAP / WHOIS', sub: 'Registration Data\nAccess Protocol', zone: 'source' },
  { id: 'ct', label: 'CT / Subdomains', sub: 'crt.sh · Certspotter\nTransparency Logs', zone: 'source' },
  { id: 'cisa', label: 'CISA / Threat', sub: 'BOD 19-02\nIP Scanner Detection', zone: 'source' },
  { id: 'probes', label: 'Probe Fleet', sub: 'SMTP · DANE · TLS\nNmap · testssl.sh', zone: 'source' },
].map(s => ({ ...s, radius: 30, shape: 'rect' }));
const HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', zone: 'hub', radius: 44, shape: 'hub' };
const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54, shape: 'circle' };
const CONFIDENCE = [
  { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker', radius: 36 },
  { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit', radius: 42 },
  { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit', radius: 42 },
  { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure', radius: 48 },
].map(c => ({ ...c, zone: 'confidence', shape: 'diamond' }));
const STORAGE = [
  { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics', radius: 36 },
  { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', radius: 34 },
  { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', radius: 32 },
].map(s => ({ ...s, zone: 'storage', shape: 'cylinder' }));
const PROTOCOLS = [
  ['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC'], ['dnssec', 'DNSSEC'], ['dane', 'DANE'],
  ['mtasts', 'MTA-STS'], ['tlsrpt', 'TLS-RPT'], ['bimi', 'BIMI'], ['caa', 'CAA'],
].map(([id, label]) => ({ id, label, sub: null, zone: 'protocol', radius: 36, shape: 'circle' }));
const OUTPUTS = [
  { id: 'reports', label: 'Reports', sub: 'Engineer · Executive\nRecon · Comparison' },
  { id: 'jsonapi', label: 'JSON API', sub: 'Analysis · Checksums\nSubdomains · Health' },
  { id: 'seo', label: 'Schema.org', sub: 'JSON-LD Structured Data\nGoogle · Rich Results' },
  { id: 'badges', label: 'SVG Badges', sub: 'Posture Indicators\nEmbeddable' },
].map(o => ({ ...o, zone: 'output', radius: 36, shape: 'hexagon' }));

const SHOW_OUTPUTS = false;
const all = [...SOURCES, HUB, ENGINE, ...CONFIDENCE, ...STORAGE, ...PROTOCOLS, ...OUTPUTS];
for (const n of all) {
  const b = computeNodeBox(n.shape, n.radius, n.label, n.sub, SCL, FONT_LABEL, FONT_SUB);
  n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH;
}

const titleSafe = Math.max(H * 0.07, 42);
const legendSafe = H * 0.95;
const usableH = legendSafe - titleSafe;
const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
const globeCx = W * 0.04 + globeR;
const pipeStart = globeCx + globeR + W * 0.02;
const consoleReserve = W >= 1000 ? 386 : 0;
const pipeEnd = W * 0.99 - consoleReserve;
const pipeTotal = pipeEnd - pipeStart;
const colGap = Math.max(4, pipeTotal * 0.01);
const srcNeed = Math.max(...SOURCES.map(n => n._boxW), HUB._boxW) + 26;
const confNeed = Math.max(...CONFIDENCE.map(n => n._boxW)) + 26;
const c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
const c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
const c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
const c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
const col1L = pipeStart, col1R = col1L + c1w;
const col2L = col1R + colGap, col2R = col2L + c2w;
const col3L = col2R + colGap, col3R = col3L + c3w;
const col4L = col3R + colGap, col4R = pipeEnd;

const zones = {
  source: { bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe } },
  hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 } },
  engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 } },
  confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 } },
  storage: { bounds: { x1: col2L - c2w * 0.3, x2: col2R + c2w * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe } },
  protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 } },
  output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } },
};
const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };

// ---- zone re-partition block (client lines ~1056-1140) ----
(function () {
  const byZone: any = {};
  for (const nd of all) { const zk = (nd as any).zone || nd.id; (byZone[zk] = byZone[zk] || []).push(nd); }
  function shelfNeed(members: any[], zw: number, pad: number) {
    let rowW = 0, rowH = 0, needH = 0, rows = 0;
    for (const nd of members) {
      const w = (nd._halfW || nd.radius) * 2, h = (nd._halfH || nd.radius) * 2;
      if (rowW > 0 && rowW + pad + w > zw) { needH += rowH; rows++; rowW = 0; rowH = 0; }
      rowW += rowW > 0 ? pad + w : w;
      if (h > rowH) rowH = h;
    }
    needH += rowH; rows++;
    return needH + pad * (rows - 1);
  }
  const keys = Object.keys(byZone).filter(k => (zones as any)[k] && (zones as any)[k].bounds).sort();
  const grouped: any = {};
  for (const ka of keys) {
    if (grouped[ka]) continue;
    const a = (zones as any)[ka].bounds; const stack = [ka];
    for (const kb of keys) {
      if (kb === ka || grouped[kb]) continue;
      const b = (zones as any)[kb].bounds;
      const xOver = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
      const minW = Math.min(a.x2 - a.x1, b.x2 - b.x1);
      const contains = (a.y1 <= b.y1 && a.y2 >= b.y2) || (b.y1 <= a.y1 && b.y2 >= a.y2);
      if (xOver > minW * 0.6 && !contains) stack.push(kb);
    }
    if (stack.length < 2) continue;
    stack.sort((x, y) => (zones as any)[x].bounds.y1 - (zones as any)[y].bounds.y1);
    const anyDeficit = stack.some(zk => { const zb = (zones as any)[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1; });
    if (!anyDeficit) continue;
    const top = (zones as any)[stack[0]].bounds.y1, bottom = (zones as any)[stack[stack.length - 1]].bounds.y2;
    let needs: number[] | null = null, usedPad = 0;
    for (const p of [14, 8, 4, 0]) {
      const n = stack.map(zk => { const zb = (zones as any)[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
      const total = n.reduce((s, v) => s + v, 0) + p * (stack.length - 1);
      if (total <= bottom - top) { needs = n; usedPad = p; break; }
    }
    if (!needs) continue;
    const leftover = (bottom - top) - needs.reduce((s, v) => s + v, 0) - usedPad * (stack.length - 1);
    const share = leftover / stack.length;
    let cursor = top;
    stack.forEach((zk, i) => { (zones as any)[zk].bounds.y1 = cursor; (zones as any)[zk].bounds.y2 = cursor + needs![i] + share; cursor = (zones as any)[zk].bounds.y2 + usedPad; grouped[zk] = true; });
  }
})();

// ---- solver remap for ALL nodes ----
const ref = layouts.desktop.canvas;
const usableW = W - consoleReserve;
const nc = layouts.desktop.nodeCenters;
for (const nd of all) {
  const pos = nc[nd.id]; if (!pos) continue;
  nd.targetX = (pos.x / ref.width) * usableW;
  nd.targetY = titleSafe + (pos.y / ref.height) * (legendSafe - titleSafe);
  const z = (zones as any)[(nd as any).zone || nd.id];
  if (z && z.bounds) {
    const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
    const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
    if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
    if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
  }
  nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
  nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
}
const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
const minPX = Math.min(...pxs), maxPX = Math.max(...pxs), minPY = Math.min(...pys), maxPY = Math.max(...pys);
const padX = 52 * SCL, padY = 44 * SCL;
const pz = zones.protocol.bounds;
const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
if (maxPX - minPX > 1 && tx2 - tx1 > 40) for (const p of PROTOCOLS) p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1);
if (maxPY - minPY > 1 && ty2 - ty1 > 40) for (const p of PROTOCOLS) p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1);

// ---- 40-iteration overlap pass ----
const overlapPad = 14;
for (let op = 0; op < 40; op++) {
  let any = false;
  for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) {
    const na: any = all[i], nb: any = all[j];
    const ohw = (na._halfW || na.radius) + (nb._halfW || nb.radius) + overlapPad;
    const ohh = (na._halfH || na.radius) + (nb._halfH || nb.radius) + overlapPad;
    const odx = Math.abs(nb.targetX - na.targetX), ody = Math.abs(nb.targetY - na.targetY);
    if (odx < ohw && ody < ohh) {
      const overX = ohw - odx, overY = ohh - ody, pushStr = 0.7;
      if (overX < overY) { const sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr; na.targetX -= sx; nb.targetX += sx; }
      else { const sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr; na.targetY -= sy; nb.targetY += sy; }
      any = true;
    }
  }
  if (!any) break;
  for (const nd of all as any[]) {
    const z = (zones as any)[nd.zone || nd.id];
    if (z && z.bounds) {
      const zHw = nd._halfW || nd.radius, zHh = nd._halfH || nd.radius;
      nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
      nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  }
}
for (const n of all as any[]) { n.x = n.targetX; n.y = n.targetY; }

console.log(`W=${W} H=${H} SCL=${SCL.toFixed(3)} FONT_LABEL=${FONT_LABEL} FONT_SUB=${FONT_SUB}`);
console.log(`col3=[${col3L.toFixed(1)},${col3R.toFixed(1)}] col4=[${col4L.toFixed(1)},${col4R.toFixed(1)}] protoXspan=${(maxPX-minPX).toFixed(1)} rescale=${maxPX-minPX>1 && tx2-tx1>40}`);
console.log('final centres:');
for (const p of all as any[]) console.log(`  ${p.id.padEnd(9)} ${p.shape.padEnd(8)} x=${p.x.toFixed(1)} y=${p.y.toFixed(1)} halfW=${p._halfW.toFixed(1)} halfH=${p._halfH.toFixed(1)}`);

// ---- edge label placement, verbatim from drawFlowEdge ----
const PROTO_EDGES = [
  { from: 'dmarc', to: 'spf', type: 'hard', label: 'alignment', labelT: 0.45 },
  { from: 'dmarc', to: 'dkim', type: 'hard', label: 'alignment', labelT: 0.45 },
  { from: 'dane', to: 'dnssec', type: 'hard', label: 'requires', labelT: 0.35 },
  { from: 'bimi', to: 'dmarc', type: 'hard', label: 'p=quarantine+', labelT: 0.5 },
  { from: 'tlsrpt', to: 'mtasts', type: 'soft', label: 'reports', labelT: 0.5 },
  { from: 'tlsrpt', to: 'dane', type: 'soft', label: 'reports', labelT: 0.4 },
  { from: 'caa', to: 'dnssec', type: 'soft', label: 'strengthens', labelT: 0.5 },
];
const byId = Object.fromEntries(all.map(n => [n.id, n]));
const PROTO_IDS = Object.fromEntries(PROTOCOLS.map(p => [p.id, true]));

function findEdgeCurveOffset(from, to, type) {
  if (type === 'flow') return null;
  if (!PROTO_IDS[from.id] || !PROTO_IDS[to.id]) return null;
  const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
  const edx = to.x - from.x, edy = to.y - from.y;
  const elen = Math.hypot(edx, edy) || 1;
  const perpX = -edy / elen, perpY = edx / elen;
  let bestOffset = 0, closestDist = Infinity;
  for (const pn of PROTOCOLS) {
    if (pn.id === from.id || pn.id === to.id) continue;
    const d = Math.hypot(pn.x - mx, pn.y - my);
    if (d < pn.radius + 50 && d < closestDist) {
      closestDist = d;
      const side = (pn.x - mx) * perpX + (pn.y - my) * perpY;
      bestOffset = (side > 0 ? -1 : 1) * Math.max(40, pn.radius + 20);
    }
  }
  if (bestOffset === 0) return null;
  return { cx: mx + perpX * bestOffset, cy: my + perpY * bestOffset };
}

const edgeFontSize = Math.max(8, FONT_SUB - 1);
const placed = [];
console.log('\nedge labels (verbatim placement replay):');
for (const e of PROTO_EDGES) {
  const from = byId[e.from], to = byId[e.to];
  const curve = findEdgeCurveOffset(from, to, e.type);
  const t = e.labelT || 0.5;
  let lx, ly;
  if (curve) {
    lx = (1 - t) ** 2 * from.x + 2 * (1 - t) * t * curve.cx + t * t * to.x;
    ly = (1 - t) ** 2 * from.y + 2 * (1 - t) * t * curve.cy + t * t * to.y;
  } else { lx = from.x + (to.x - from.x) * t; ly = from.y + (to.y - from.y) * t; }
  ly -= 8 * SCL;
  const anchor = { x: lx, y: ly };
  // which nodes contain the raw anchor?
  const inside = all.filter(nn => nn.shape === 'circle'
    ? Math.hypot(lx - nn.x, ly - nn.y) < nn.radius
    : (Math.abs(lx - nn.x) < nn._halfW && Math.abs(ly - nn.y) < nn._halfH)).map(n => n.id);

  for (const nn of all) {
    const nhw = (nn._halfW || nn._boxW / 2 || nn.radius) + 12;
    const nhh = (nn._halfH || nn._boxH / 2 || nn.radius) + 12;
    if (nn.shape === 'circle') {
      const ldx = lx - nn.x, ldy = ly - nn.y, ldist = Math.hypot(ldx, ldy);
      if (ldist < nn.radius + 24 && ldist > 0.1) { const k = (nn.radius + 28) / ldist; lx = nn.x + ldx * k; ly = nn.y + ldy * k; if (process.env.TRACE) console.log(`       escape circle ${nn.id}: ldist=${ldist.toFixed(2)} -> (${lx.toFixed(1)},${ly.toFixed(1)})`); }
      else if (ldist <= 0.1 && ldist < nn.radius + 24) { if (process.env.TRACE) console.log(`       SKIPPED escape on ${nn.id}: ldist=${ldist.toFixed(3)} (guard ldist>0.1 fails) -> label stays at node centre`); }
    } else {
      const ndx = lx - nn.x, ndy = ly - nn.y;
      if (Math.abs(ndx) < nhw && Math.abs(ndy) < nhh) {
        if (Math.abs(ndx) / nhw > Math.abs(ndy) / nhh) lx = nn.x + (ndx >= 0 ? 1 : -1) * (nhw + 6);
        else ly = nn.y + (ndy >= 0 ? 1 : -1) * (nhh + 6);
        if (process.env.TRACE) console.log(`       escape box ${nn.id} -> (${lx.toFixed(1)},${ly.toFixed(1)})`);
      }
    }
  }
  const afterNodes = { x: lx, y: ly };
  const tw = measure(e.label, edgeFontSize);
  const pw = tw + 10 * SCL, ph = edgeFontSize + 8 * SCL;
  for (let pass = 0; pass < 3; pass++) {
    let moved = false;
    for (const pl of placed) {
      const olx = Math.min(lx + pw / 2, pl.x + pl.w / 2) - Math.max(lx - pw / 2, pl.x - pl.w / 2);
      const oly = Math.min(ly + ph / 2, pl.y + pl.h / 2) - Math.max(ly - ph / 2, pl.y - pl.h / 2);
      if (olx > 0 && oly > 0) { if (olx < oly) lx += (lx >= pl.x ? 1 : -1) * (olx + 6); else ly += (ly >= pl.y ? 1 : -1) * (oly + 6); moved = true; }
    }
    if (!moved) break;
  }
  const afterLabels = { x: lx, y: ly };
  ly = Math.max(20, Math.min(H - 20, ly));
  lx = Math.max(30, Math.min(W - 30, lx));

  // FINAL overlap of the drawn pill vs every node body
  const hits = [];
  for (const nn of all) {
    if (nn.shape === 'circle') {
      const cx = Math.max(lx - pw / 2, Math.min(nn.x, lx + pw / 2));
      const cy = Math.max(ly - ph / 2, Math.min(nn.y, ly + ph / 2));
      const d = Math.hypot(cx - nn.x, cy - nn.y);
      if (d < nn.radius) hits.push(`${nn.id}(circle, pen ${(nn.radius - d).toFixed(1)}px)`);
    } else {
      const ox = Math.min(lx + pw / 2, nn.x + nn._halfW) - Math.max(lx - pw / 2, nn.x - nn._halfW);
      const oy = Math.min(ly + ph / 2, nn.y + nn._halfH) - Math.max(ly - ph / 2, nn.y - nn._halfH);
      if (ox > 0 && oy > 0) hits.push(`${nn.id}(box, ${ox.toFixed(1)}x${oy.toFixed(1)})`);
    }
  }
  const labHits = placed.filter(pl => (Math.min(lx + pw / 2, pl.x + pl.w / 2) - Math.max(lx - pw / 2, pl.x - pl.w / 2)) > 0 &&
    (Math.min(ly + ph / 2, pl.y + pl.h / 2) - Math.max(ly - ph / 2, pl.y - pl.h / 2)) > 0).map(p => p.label);
  console.log(`  "${e.label}" ${e.from}->${e.to} t=${t} curve=${curve ? 'yes' : 'no'}`);
  console.log(`     anchor=(${anchor.x.toFixed(1)},${anchor.y.toFixed(1)}) rawAnchorInsideNodes=[${inside.join(',')}]`);
  console.log(`     afterNodeEscape=(${afterNodes.x.toFixed(1)},${afterNodes.y.toFixed(1)}) afterLabelSep=(${afterLabels.x.toFixed(1)},${afterLabels.y.toFixed(1)}) final=(${lx.toFixed(1)},${ly.toFixed(1)}) pill=${pw.toFixed(1)}x${ph.toFixed(1)}`);
  console.log(`     FINAL pill overlaps nodes: [${hits.join(', ')}]  labels: [${labHits.join(', ')}]`);
  placed.push({ x: lx, y: ly, w: pw, h: ph, label: e.label });
}

console.log('\ntiming badge geometry (drawScanNodeLabel) + collision analysis:');
const badgeFont = Math.round(9 * SCL);
function effRadius2(n: any, hasDraw: boolean) {
  const hw = (hasDraw ? n._boxW : n.radius * 2.2) / 2;
  const hh = (hasDraw ? n._boxH : n.radius * 1.4) / 2;
  return Math.max(hw, hh, n.radius) + 6;
}
const badgeAnchors: [string, string][] = [['dns_records','hub'],['email_auth','spf'],['dnssec_dane','dnssec'],['ct_subdomains','ct'],['smtp_transport','probes'],['policy_records','mtasts'],['registrar_infra','root'],['analysis_engine','engine']];
const setsDraw = new Set(['root','rdap','ct','cisa','probes','hub','postgres','fixtures','wayback']);
const byId2: any = Object.fromEntries(all.map((n: any) => [n.id, n]));
// sample badge texts observed in the user's browser
const texts = ['47.8s','8.0s','11.1s','4.3s','2.8s','7.5s','12/12','\u2026'];
const bw = Math.max(...texts.map(t => measure(t, badgeFont)));
for (const [g, id] of badgeAnchors) {
  const n = byId2[id];
  const hasDraw = setsDraw.has(id);
  const er = effRadius2(n, hasDraw);
  const bTop = n.y + er + 9, bBot = bTop + badgeFont;
  const bx1 = n.x - bw / 2, bx2 = n.x + bw / 2;
  const hits: string[] = [];
  for (const m of all as any[]) {
    if (m.id === id) continue;
    const ox = Math.min(bx2, m.x + m._halfW) - Math.max(bx1, m.x - m._halfW);
    const oy = Math.min(bBot, m.y + m._halfH) - Math.max(bTop, m.y - m._halfH);
    if (ox > 0 && oy > 0) {
      // where does m draw its sub lines?
      const subs: number[] = [];
      if (m.sub) {
        const lines = m.sub.split('\n');
        for (let k = 0; k < lines.length; k++) {
          if (m.shape === 'rect' || m.shape === 'hub') subs.push(m.y + 6 * SCL + k * (FONT_SUB + 2));
          else if (m.shape === 'diamond') subs.push(m.y + 6 * SCL + k * (FONT_SUB + 2));
          else if (m.shape === 'cylinder') subs.push(m.y + m._halfH + 12 * SCL + k * (FONT_SUB + 2));
          else if (m.shape === 'hexagon') subs.push(m.y + 8 * SCL + k * (FONT_SUB + 2));
        }
      }
      const onSub = subs.filter(sy => sy > bTop - FONT_SUB / 2 && sy < bBot + FONT_SUB / 2);
      hits.push(`${m.id}(box ${ox.toFixed(1)}x${oy.toFixed(1)}${onSub.length ? ', ON SUB-TEXT y=' + onSub.map(v => v.toFixed(1)).join('/') : ''})`);
    }
  }
  const offCanvas = bBot > H ? ` OFF-CANVAS by ${(bBot - H).toFixed(1)}px` : '';
  console.log(`  ${g.padEnd(16)} ${id.padEnd(8)} ${n.shape.padEnd(8)} halfW=${n._halfW.toFixed(1)} halfH=${n._halfH.toFixed(1)} effR=${er.toFixed(1)} badgeY=[${bTop.toFixed(1)},${bBot.toFixed(1)}] gapBelowBox=${(er + 9 - n._halfH).toFixed(1)}${offCanvas}`);
  if (hits.length) console.log(`      COLLIDES: ${hits.join(', ')}`);
}
