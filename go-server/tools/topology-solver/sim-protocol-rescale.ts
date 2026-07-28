// Standalone replay of topology.js layoutAll() x-geometry.
// Uses the REAL solver text metric + the REAL shipped layout JSON.
import { estimateTextWidth } from './src/nodeMetrics.js';
import fs from 'node:fs';

const desktop = JSON.parse(fs.readFileSync(new URL('./output/desktop-layout.json', import.meta.url), 'utf8'));
const tablet = JSON.parse(fs.readFileSync(new URL('./output/tablet-layout.json', import.meta.url), 'utf8'));
const mobile = JSON.parse(fs.readFileSync(new URL('./output/mobile-layout.json', import.meta.url), 'utf8'));
const LAYOUTS: any = { desktop, tablet, mobile };

type N = {
  id: string; label: string; sub?: string | null; radius: number; shape: string; zone: string;
  targetX: number; targetY: number; _halfW?: number; _halfH?: number; _boxW?: number; _boxH?: number;
};

function mk(): N[] {
  const S = (id: string, label: string, sub: string) => ({ id, label, sub, radius: 30, shape: 'rect', zone: 'source', targetX: 0, targetY: 0 } as N);
  const SOURCES: N[] = [
    S('root', 'Root / TLD', 'IANA Root Zone\nTLD Registries'),
    S('rdap', 'RDAP / WHOIS', 'Registration Data\nAccess Protocol'),
    S('ct', 'CT / Subdomains', 'crt.sh · Certspotter\nTransparency Logs'),
    S('cisa', 'CISA / Threat', 'BOD 19-02\nIP Scanner Detection'),
    S('probes', 'Probe Fleet', 'SMTP · DANE · TLS\nNmap · testssl.sh'),
  ];
  const HUB: N = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', radius: 44, shape: 'hub', zone: 'hub', targetX: 0, targetY: 0 };
  const ENGINE: N = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', radius: 54, shape: 'rect', zone: 'engine', targetX: 0, targetY: 0 };
  const CONFIDENCE: N[] = [
    { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker', radius: 36, shape: 'rect', zone: 'confidence', targetX: 0, targetY: 0 },
    { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit', radius: 42, shape: 'diamond', zone: 'confidence', targetX: 0, targetY: 0 },
    { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit', radius: 42, shape: 'diamond', zone: 'confidence', targetX: 0, targetY: 0 },
    { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure', radius: 48, shape: 'diamond', zone: 'confidence', targetX: 0, targetY: 0 },
  ];
  const STORAGE: N[] = [
    { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics', radius: 36, shape: 'cylinder', zone: 'storage', targetX: 0, targetY: 0 },
    { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', radius: 34, shape: 'cylinder', zone: 'storage', targetX: 0, targetY: 0 },
    { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', radius: 32, shape: 'cylinder', zone: 'storage', targetX: 0, targetY: 0 },
  ];
  const P = (id: string, label: string) => ({ id, label, sub: null, radius: 36, shape: 'circle', zone: 'protocol', targetX: 0, targetY: 0 } as N);
  const PROTOCOLS: N[] = [P('spf', 'SPF'), P('dkim', 'DKIM'), P('dmarc', 'DMARC'), P('dnssec', 'DNSSEC'), P('dane', 'DANE'), P('mtasts', 'MTA-STS'), P('tlsrpt', 'TLS-RPT'), P('bimi', 'BIMI'), P('caa', 'CAA')];
  const O = (id: string, label: string, sub: string) => ({ id, label, sub, radius: 36, shape: 'hexagon', zone: 'output', targetX: 0, targetY: 0 } as N);
  const OUTPUTS: N[] = [
    O('reports', 'Reports', 'Engineer · Executive\nRecon · Comparison'),
    O('jsonapi', 'JSON API', 'Analysis · Checksums\nSubdomains · Health'),
    O('seo', 'Schema.org', 'JSON-LD Structured Data\nGoogle · Rich Results'),
    O('badges', 'SVG Badges', 'Posture Indicators\nEmbeddable'),
  ];
  return [...SOURCES, HUB, ENGINE, ...CONFIDENCE, ...STORAGE, ...PROTOCOLS, ...OUTPUTS];
}

// exact port of topology.js computeNodeBox
function box(n: N, SCL: number, FL: number, FS: number, k: number) {
  const m = (t: string, f: number) => estimateTextWidth(t, f) * k;
  const labelW = m(n.label, FL);
  let subW = 0, subLineCount = 0;
  if (n.sub) {
    const lines = n.sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const s = m(l, FS); if (s > subW) subW = s; }
  }
  const contentW = Math.max(labelW, subW) + 24 * SCL;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (FS + 2) : 0;
  let w: number, h: number;
  const r = n.radius;
  if (n.shape === 'circle') { w = Math.max(r * 2, contentW); h = r * 2; }
  else if (n.shape === 'diamond') { w = Math.max(r * 1.7, contentW + 8); h = r * 1.7 + subExtra; }
  else if (n.shape === 'hexagon') { w = Math.max(r * 2, contentW); h = r * 2 + subExtra; }
  else if (n.shape === 'cylinder') { w = Math.max(r * 2.4, contentW); h = r * 1.5 + 16 + subExtra; }
  else if (n.shape === 'hub' || n.shape === 'roundRect') { w = Math.max(r * 2.4, contentW); h = Math.max(r * 1.4, 40 * SCL); }
  else { w = Math.max(r * 2.4, contentW); h = Math.max(r * 1.3, 40 * SCL + (subLineCount > 1 ? (subLineCount - 1) * (FS + 2) : 0)); }
  n._boxW = w; n._boxH = h; n._halfW = w / 2; n._halfH = h / 2;
}

export function layout(W: number, H: number, opts: { fix?: boolean; k?: number; SHOW_OUTPUTS?: boolean } = {}) {
  const k = opts.k ?? 1;
  const SHOW_OUTPUTS = opts.SHOW_OUTPUTS ?? false;
  const nodes = mk();
  const by: Record<string, N> = {}; nodes.forEach(n => by[n.id] = n);
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));

  const titleSafe = Math.max(H * 0.07, 42);
  const legendSafe = H * 0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const globeCx = W * 0.04 + globeR;
  const globeCy = titleSafe + usableH * 0.42;
  const pipeStart = globeCx + globeR + W * 0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W * 0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal * 0.01);

  nodes.forEach(n => box(n, SCL, FONT_LABEL, FONT_SUB, k));
  const SOURCES = nodes.filter(n => n.zone === 'source');
  const CONFIDENCE = nodes.filter(n => n.zone === 'confidence');
  const STORAGE = nodes.filter(n => n.zone === 'storage');
  const PROTOCOLS = nodes.filter(n => n.zone === 'protocol');
  const OUTPUTS = nodes.filter(n => n.zone === 'output');

  const srcNeed = Math.max(...SOURCES.map(n => n._boxW!), by.hub._boxW!) + 26;
  const confNeed = Math.max(...CONFIDENCE.map(n => n._boxW!)) + 26;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
  const c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
  const c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
  const col1L = pipeStart, col1R = col1L + c1w;
  const col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w;
  const col4L = col3R + colGap, col4R = pipeEnd;
  const c2wReal = c2w;

  const srcCx = (col1L + col1R) / 2;
  const procCx = (col2L + col2R) / 2;
  const outCx = (col4L + col4R) / 2;
  const protoCx = (col3L + col3R) / 2, protoCy = titleSafe + usableH * 0.42;
  const confY = titleSafe + usableH * 0.42;
  const storeY = titleSafe + usableH * 0.78;

  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  const zones: any = {
    source: { bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe } },
    hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 } },
    engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 } },
    confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 } },
    storage: { bounds: { x1: col2L - c2wReal * 0.3, x2: col2R + c2wReal * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe } },
    protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 } },
    output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } },
  };

  // ---- zone re-partition block (lines 1069-1151) — y only
  (function () {
    const byZone: Record<string, N[]> = {};
    nodes.forEach(nd => { const zk = nd.zone; (byZone[zk] = byZone[zk] || []).push(nd); });
    function shelfNeed(members: N[], zw: number, pad: number) {
      let rowW = 0, rowH = 0, needH = 0, rows = 0;
      members.forEach(nd => {
        const w = nd._halfW! * 2, h = nd._halfH! * 2;
        if (rowW > 0 && rowW + pad + w > zw) { needH += rowH; rows++; rowW = 0; rowH = 0; }
        rowW += rowW > 0 ? pad + w : w;
        if (h > rowH) rowH = h;
      });
      needH += rowH; rows++;
      return needH + pad * (rows - 1);
    }
    const keys: string[] = [];
    for (const zk in byZone) if (zones[zk] && zones[zk].bounds) keys.push(zk);
    keys.sort();
    const grouped: Record<string, boolean> = {};
    keys.forEach(ka => {
      if (grouped[ka]) return;
      const a = zones[ka].bounds; const stack = [ka];
      keys.forEach(kb => {
        if (kb === ka || grouped[kb]) return;
        const b = zones[kb].bounds;
        const xOver = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
        const minW = Math.min(a.x2 - a.x1, b.x2 - b.x1);
        const contains = (a.y1 <= b.y1 && a.y2 >= b.y2) || (b.y1 <= a.y1 && b.y2 >= a.y2);
        if (xOver > minW * 0.6 && !contains) stack.push(kb);
      });
      if (stack.length < 2) return;
      stack.sort((x, y) => zones[x].bounds.y1 - zones[y].bounds.y1);
      const anyDeficit = stack.some(zk => {
        const zb = zones[zk].bounds;
        return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1;
      });
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1;
      const bottom = zones[stack[stack.length - 1]].bounds.y2;
      let needs: number[] | null = null, usedPad = 0;
      for (const p of [14, 8, 4, 0]) {
        const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
        const total = n.reduce((s, v) => s + v, 0) + p * (stack.length - 1);
        if (total <= bottom - top) { needs = n; usedPad = p; break; }
      }
      if (!needs) return;
      const leftover = (bottom - top) - needs.reduce((s, v) => s + v, 0) - usedPad * (stack.length - 1);
      const share = leftover / stack.length;
      let cursor = top;
      stack.forEach((zk, i) => {
        zones[zk].bounds.y1 = cursor;
        zones[zk].bounds.y2 = cursor + needs![i] + share;
        cursor = zones[zk].bounds.y2 + usedPad;
        grouped[zk] = true;
      });
    });
  })();

  // ---- solver remap
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const solverData = LAYOUTS[profile].nodeCenters;
  const ref = { w: LAYOUTS[profile].canvas.width, h: LAYOUTS[profile].canvas.height };
  const usableW = W - consoleReserve;
  const raw: Record<string, number> = {};
  nodes.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    raw[nd.id] = nd.targetX;
    const z = zones[nd.zone];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  });

  // ---- protocol rescale
  const pxs = opts.fix ? PROTOCOLS.map(p => raw[p.id]) : PROTOCOLS.map(p => p.targetX);
  const pys = PROTOCOLS.map(p => p.targetY);
  const minPX = Math.min(...pxs), maxPX = Math.max(...pxs);
  const minPY = Math.min(...pys), maxPY = Math.max(...pys);
  const pz = zones.protocol.bounds;
  const padX = 52 * SCL, padY = 44 * SCL;
  const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX;
  const ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
  const guardX = (maxPX - minPX > 1 && tx2 - tx1 > 40);
  if (guardX) PROTOCOLS.forEach((p, i) => { p.targetX = tx1 + ((pxs[i] - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
  if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });

  const afterRescale = PROTOCOLS.map(p => ({ id: p.id, x: p.targetX, y: p.targetY }));

  // ---- overlap pass
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters = op + 1;
    let any = false;
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const na = nodes[i], nb = nodes[j];
      const ohw = na._halfW! + nb._halfW! + overlapPad;
      const ohh = na._halfH! + nb._halfH! + overlapPad;
      const odx = Math.abs(nb.targetX - na.targetX), ody = Math.abs(nb.targetY - na.targetY);
      if (odx < ohw && ody < ohh) {
        const overX = ohw - odx, overY = ohh - ody, pushStr = 0.7;
        if (overX < overY) { const sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr; na.targetX -= sx; nb.targetX += sx; }
        else { const sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr; na.targetY -= sy; nb.targetY += sy; }
        any = true;
      }
    }
    if (!any) break;
    nodes.forEach(nd => {
      const z = zones[nd.zone];
      if (z && z.bounds) {
        nd.targetX = Math.max(z.bounds.x1 + nd._halfW!, Math.min(z.bounds.x2 - nd._halfW!, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1 + nd._halfH!, Math.min(z.bounds.y2 - nd._halfH!, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    });
  }

  // count residual AABB overlaps among the 9 protocol circles (drawn geometry)
  let protoOverlaps = 0;
  for (let i = 0; i < PROTOCOLS.length; i++) for (let j = i + 1; j < PROTOCOLS.length; j++) {
    const a = PROTOCOLS[i], b = PROTOCOLS[j];
    const ox = Math.min(a.targetX + a._halfW!, b.targetX + b._halfW!) - Math.max(a.targetX - a._halfW!, b.targetX - b._halfW!);
    const oy = Math.min(a.targetY + a._halfH!, b.targetY + b._halfH!) - Math.max(a.targetY - a._halfH!, b.targetY - b._halfH!);
    if (ox > 0 && oy > 0) protoOverlaps++;
  }
  const fxs = PROTOCOLS.map(p => p.targetX);
  const fys = PROTOCOLS.map(p => p.targetY);

  return {
    W, H, SCL, consoleReserve, usableW, pipeStart, pipeEnd, pipeTotal, colGap,
    srcNeed, confNeed, c1w, c2w, c3w, col1L, col2L, col2R, col3L, col3R,
    zpxProto: Math.min(30, (pz.x2 - pz.x1) * 0.15),
    clampLo: pz.x1 + Math.min(30, (pz.x2 - pz.x1) * 0.15),
    clampHi: pz.x2 - Math.min(30, (pz.x2 - pz.x1) * 0.15),
    rawProto: PROTOCOLS.map(p => ({ id: p.id, raw: raw[p.id] })),
    minPX, maxPX, guardX, tx1, tx2, padX,
    afterRescale,
    finalX: PROTOCOLS.map((p, i) => ({ id: p.id, x: fxs[i], y: fys[i], hw: p._halfW })),
    finalSpanX: Math.max(...fxs) - Math.min(...fxs),
    finalSpanY: Math.max(...fys) - Math.min(...fys),
    protoOverlaps, iters,
  };
}

const widths = process.argv.slice(2).map(Number).filter(n => !isNaN(n));
const list = widths.length ? widths : [800, 1001, 1100, 1233, 1280, 1366, 1400, 1420, 1500, 1600, 1750, 1900, 1950, 2200];
console.log('W\tSCL\tcol3L\tcol3R\tzpx\tclampLo\tclampHi\trawMin\trawMax\trawSpan\tminPX\tmaxPX\tguard\tfinalSpanX\tprotoOvl');
for (const W of list) {
  const r = layout(W, 900);
  const rawv = r.rawProto.map(p => p.raw);
  const f = (x: number) => x.toFixed(1);
  console.log([W, r.SCL.toFixed(3), f(r.col3L), f(r.col3R), f(r.zpxProto), f(r.clampLo), f(r.clampHi),
    f(Math.min(...rawv)), f(Math.max(...rawv)), f(Math.max(...rawv) - Math.min(...rawv)),
    f(r.minPX), f(r.maxPX), r.guardX, f(r.finalSpanX), r.protoOverlaps].join('\t'));
}
