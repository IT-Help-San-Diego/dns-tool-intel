// Faithful Node replay of topology.js layoutAll() lines 910-1272.
// Text width uses the solver's estimateTextWidth (the client uses real
// canvas measureText; a WIDTHFUDGE multiplier probes sensitivity).
import fs from 'fs';
import path from 'path';

const DIR = path.dirname(new URL(import.meta.url).pathname);
const DEG = Math.PI / 180;

const FUDGE = Number(process.env.FUDGE || 1);
function estimateTextWidth(text, fontSize) {
  let total = 0;
  for (const ch of text) {
    if (ch === ' ') total += 0.28;
    else if (/[mwMW]/.test(ch)) total += 0.82;
    else if (/[iltfr!|'.,:;]/.test(ch)) total += 0.32;
    else if (/[A-Z]/.test(ch)) total += 0.72;
    else if (/[a-z]/.test(ch)) total += 0.52;
    else if (/\d/.test(ch)) total += 0.56;
    else total += 0.56;
  }
  return total * fontSize * FUDGE;
}

let SCL = 1, FONT_LABEL = 13, FONT_SUB = 10;

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, measureFn) {
  let labelW = measureFn(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    let lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const sw = measureFn(l, fontSub); if (sw > subW) subW = sw; }
  }
  let contentW = Math.max(labelW, subW) + 24 * scale;
  let subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0)); }
  return { w, h, halfW: w / 2, halfH: h / 2, contentW, subLineCount };
}
function measureNodeBox(n) {
  const b = computeNodeBox(n.shape, n.radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB, estimateTextWidth);
  n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH; return b;
}

function mkNodes() {
  const SOURCES = [
    { id: 'root', label: 'Root / TLD', sub: 'IANA Root Zone\nTLD Registries', zone: 'source' },
    { id: 'rdap', label: 'RDAP / WHOIS', sub: 'Registration Data\nAccess Protocol', zone: 'source' },
    { id: 'ct', label: 'CT / Subdomains', sub: 'crt.sh · Certspotter\nTransparency Logs', zone: 'source' },
    { id: 'cisa', label: 'CISA / Threat', sub: 'BOD 19-02\nIP Scanner Detection', zone: 'source' },
    { id: 'probes', label: 'Probe Fleet', sub: 'SMTP · DANE · TLS\nNmap · testssl.sh', zone: 'source' },
  ];
  SOURCES.forEach(s => { s.radius = 30; s.shape = 'rect'; });
  const HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', zone: 'hub', radius: 44, shape: 'hub' };
  const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54 };
  const CONFIDENCE = [
    { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker', zone: 'confidence' },
    { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit', zone: 'confidence' },
    { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit', zone: 'confidence' },
    { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure', zone: 'confidence' },
  ];
  CONFIDENCE.forEach(c => { c.radius = (c.id === 'ede') ? 48 : (c.id === 'ietf') ? 36 : 42; c.shape = (c.id === 'ietf') ? 'rect' : 'diamond'; });
  const STORAGE = [
    { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics', zone: 'storage' },
    { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', zone: 'storage' },
    { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', zone: 'storage' },
  ];
  STORAGE.forEach(s => { s.radius = (s.id === 'postgres') ? 36 : (s.id === 'wayback') ? 32 : 34; s.shape = 'cylinder'; });
  const PROTOCOLS = ['SPF', 'DKIM', 'DMARC', 'DNSSEC', 'DANE', 'MTA-STS', 'TLS-RPT', 'BIMI', 'CAA']
    .map((lab, i) => ({ id: ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'][i], label: lab, radius: 36, shape: 'circle', zone: 'protocol' }));
  const OUTPUTS = [
    { id: 'reports', label: 'Reports', sub: 'Engineer · Executive\nRecon · Comparison', zone: 'output' },
    { id: 'jsonapi', label: 'JSON API', sub: 'Analysis · Checksums\nSubdomains · Health', zone: 'output' },
    { id: 'seo', label: 'Schema.org', sub: 'JSON-LD Structured Data\nGoogle · Rich Results', zone: 'output' },
    { id: 'badges', label: 'SVG Badges', sub: 'Posture Indicators\nEmbeddable', zone: 'output' },
  ];
  OUTPUTS.forEach(o => { o.radius = 36; o.shape = 'hexagon'; });
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

const LAYOUTS = {
  desktop: JSON.parse(fs.readFileSync(path.join(DIR, 'output/desktop-layout.json'), 'utf8')),
  tablet: JSON.parse(fs.readFileSync(path.join(DIR, 'output/tablet-layout.json'), 'utf8')),
  mobile: JSON.parse(fs.readFileSync(path.join(DIR, 'output/mobile-layout.json'), 'utf8')),
};

export function layoutAll(W, H, opts = {}) {
  const SHOW_OUTPUTS = opts.showOutputs === undefined ? false : opts.showOutputs;
  const perZoneFix = opts.perZoneFix;
  SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));

  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = mkNodes();

  let titleSafe = Math.max(H * 0.07, 42);
  let legendSafe = H * 0.95;
  let usableH = legendSafe - titleSafe;
  let globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const globe = { R: globeR, cx: W * 0.04 + globeR, cy: titleSafe + usableH * 0.42 };
  let pipeStart = globe.cx + globeR + W * 0.02;
  let consoleReserve = W >= 1000 ? 386 : 0;
  let pipeEnd = W * 0.99 - consoleReserve;
  let pipeTotal = pipeEnd - pipeStart;
  let colGap = Math.max(4, pipeTotal * 0.01);
  SOURCES.forEach(measureNodeBox); measureNodeBox(HUB); CONFIDENCE.forEach(measureNodeBox);
  let srcNeed = Math.max(...SOURCES.map(n => n._boxW), HUB._boxW) + 26;
  let confNeed = Math.max(...CONFIDENCE.map(n => n._boxW)) + 26;
  let c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
  let c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
  let c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
  let c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
  let col1L = pipeStart, col1R = col1L + c1w;
  let col2L = col1R + colGap, col2R = col2L + c2w;
  let col3L = col2R + colGap, col3R = col3L + c3w;
  let col4L = col3R + colGap, col4R = pipeEnd;

  let srcCx = (col1L + col1R) / 2;
  let srcSpacing = usableH / (SOURCES.length + 1);
  SOURCES.forEach((s, i) => { s.targetX = srcCx; s.targetY = titleSafe + (i + 1) * srcSpacing; });
  HUB.targetX = srcCx; HUB.targetY = globe.cy;
  let procCx = (col2L + col2R) / 2;
  ENGINE.targetX = procCx; ENGINE.targetY = titleSafe + usableH * 0.15;
  let confSpread = Math.max(40, (col2R - col2L) * 0.32);
  let confY = titleSafe + usableH * 0.42;
  CONFIDENCE[0].targetX = procCx; CONFIDENCE[0].targetY = confY - usableH * 0.06;
  CONFIDENCE[1].targetX = procCx - confSpread * 0.5; CONFIDENCE[1].targetY = confY + usableH * 0.06;
  CONFIDENCE[2].targetX = procCx + confSpread * 0.5; CONFIDENCE[2].targetY = confY + usableH * 0.06;
  CONFIDENCE[3].targetX = procCx; CONFIDENCE[3].targetY = confY + usableH * 0.18;
  let storeY = titleSafe + usableH * 0.78;
  let storeSpread = Math.max(confSpread * 0.8, 60);
  STORAGE[0].targetX = procCx; STORAGE[0].targetY = storeY;
  STORAGE[1].targetX = procCx - storeSpread; STORAGE[1].targetY = storeY + usableH * 0.10;
  STORAGE[2].targetX = procCx + storeSpread; STORAGE[2].targetY = storeY + usableH * 0.10;
  let protoCx = (col3L + col3R) / 2, protoCy = titleSafe + usableH * 0.42;
  let protoRx = (col3R - col3L) * 0.38, protoRy = usableH * 0.28;
  const angleMap = [-130, -90, -50, -10, 30, 70, 110, 150, 190];
  PROTOCOLS.forEach((p, i) => { const a = angleMap[i] * DEG; p.targetX = protoCx + protoRx * Math.cos(a); p.targetY = protoCy + protoRy * Math.sin(a); });
  let outCx = (col4L + col4R) / 2, outSpacing = usableH / (OUTPUTS.length + 1);
  OUTPUTS.forEach((o, i) => { o.targetX = outCx; o.targetY = titleSafe + (i + 1) * outSpacing; });

  let globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  let zones = {
    source: { bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe } },
    hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 } },
    engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 } },
    confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 } },
    storage: { bounds: { x1: col2L - c2w * 0.3, x2: col2R + c2w * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe } },
    protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 } },
    output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } },
  };

  const allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  allLayoutNodes.forEach(measureNodeBox);

  // ---- shelf re-partition block (1069-1151) ----
  (function () {
    let byZone = {};
    allLayoutNodes.forEach(nd => { const zk = nd.zone || nd.id; (byZone[zk] = byZone[zk] || []).push(nd); });
    function shelfNeed(members, zw, pad) {
      let rowW = 0, rowH = 0, needH = 0, rows = 0;
      members.forEach(nd => {
        const w = (nd._halfW || nd.radius) * 2, h = (nd._halfH || nd.radius) * 2;
        if (rowW > 0 && rowW + pad + w > zw) { needH += rowH; rows++; rowW = 0; rowH = 0; }
        rowW += rowW > 0 ? pad + w : w;
        if (h > rowH) rowH = h;
      });
      needH += rowH; rows++;
      return needH + pad * (rows - 1);
    }
    let keys = [];
    for (const zk in byZone) if (zones[zk] && zones[zk].bounds) keys.push(zk);
    keys.sort();
    let grouped = {};
    keys.forEach(ka => {
      if (grouped[ka]) return;
      const a = zones[ka].bounds;
      let stack = [ka];
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
      const anyDeficit = stack.some(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1; });
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1, bottom = zones[stack[stack.length - 1]].bounds.y2;
      let needs = null, usedPad = 0;
      for (const p of [14, 8, 4, 0]) {
        const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
        const total = n.reduce((s, v) => s + v, 0) + p * (stack.length - 1);
        if (total <= bottom - top) { needs = n; usedPad = p; break; }
      }
      if (!needs) return;
      const leftover = (bottom - top) - needs.reduce((s, v) => s + v, 0) - usedPad * (stack.length - 1);
      const share = leftover / stack.length;
      let cursor = top;
      stack.forEach((zk, i) => { zones[zk].bounds.y1 = cursor; zones[zk].bounds.y2 = cursor + needs[i] + share; cursor = zones[zk].bounds.y2 + usedPad; grouped[zk] = true; });
    });
  })();

  const solverProfile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const layout = LAYOUTS[solverProfile];
  const solverData = layout && layout.nodeCenters;
  const tmpl = JSON.parse(fs.readFileSync(path.join(DIR, 'fixtures/dns-topology-production.json'), 'utf8')).viewportProfiles[solverProfile].zoneTemplates;

  let ref = { w: layout.canvas.width, h: layout.canvas.height };
  let usableW = W - consoleReserve;
  const clampedX = [], clampedY = [], preClamp = {};
  allLayoutNodes.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) return;
    const t = tmpl[nd.zone || nd.id], z0 = zones[nd.zone || nd.id];
    const fixX = perZoneFix === true || perZoneFix === 'x';
    const fixY = perZoneFix === true || perZoneFix === 'y';
    nd.targetX = fixX
      ? z0.bounds.x1 + ((pos.x - t.x1) / (t.x2 - t.x1)) * (z0.bounds.x2 - z0.bounds.x1)
      : (pos.x / ref.w) * usableW;
    nd.targetY = fixY
      ? z0.bounds.y1 + ((pos.y - t.y1) / (t.y2 - t.y1)) * (z0.bounds.y2 - z0.bounds.y1)
      : titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    preClamp[nd.id] = { x: nd.targetX, y: nd.targetY };
    const z = zones[nd.zone || nd.id];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) {
        const nx = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
        if (Math.abs(nx - nd.targetX) > 1e-9) clampedX.push(nd.id);
        nd.targetX = nx;
      }
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) {
        const ny = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
        if (Math.abs(ny - nd.targetY) > 1e-9) clampedY.push(nd.id);
        nd.targetY = ny;
      }
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  });

  // protocol ellipse rescale (1205-1226)
  const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
  const minPX = Math.min(...pxs), maxPX = Math.max(...pxs);
  const minPY = Math.min(...pys), maxPY = Math.max(...pys);
  const pz = zones.protocol.bounds;
  const padX = 52 * SCL, padY = 44 * SCL;
  const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
  const rescaleX = (maxPX - minPX > 1 && tx2 - tx1 > 40);
  const rescaleY = (maxPY - minPY > 1 && ty2 - ty1 > 40);
  if (rescaleX) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
  if (rescaleY) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });

  const afterSolver = allLayoutNodes.map(n => ({ id: n.id, zone: n.zone, x: n.targetX, y: n.targetY }));

  // overlap pass (1233-1272)
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters++;
    let anyOverlap = false;
    for (let oi = 0; oi < allLayoutNodes.length; oi++) {
      for (let oj = oi + 1; oj < allLayoutNodes.length; oj++) {
        const na = allLayoutNodes[oi], nb = allLayoutNodes[oj];
        const ohw = (na._halfW || na.radius) + (nb._halfW || nb.radius) + overlapPad;
        const ohh = (na._halfH || na.radius) + (nb._halfH || nb.radius) + overlapPad;
        const odx = Math.abs(nb.targetX - na.targetX), ody = Math.abs(nb.targetY - na.targetY);
        if (odx < ohw && ody < ohh) {
          const overX = ohw - odx, overY = ohh - ody, pushStr = 0.7;
          if (overX < overY) { const sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr; na.targetX -= sx; nb.targetX += sx; }
          else { const sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr; na.targetY -= sy; nb.targetY += sy; }
          anyOverlap = true;
        }
      }
    }
    if (!anyOverlap) break;
    allLayoutNodes.forEach(nd => {
      const z = zones[nd.zone || nd.id];
      if (z && z.bounds) {
        const zHw = nd._halfW || nd.radius, zHh = nd._halfH || nd.radius;
        nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    });
  }

  // count residual visible-node overlaps (AABB of drawn ink approximated by box)
  const visible = allLayoutNodes.filter(n => SHOW_OUTPUTS ? true : n.zone !== 'output');
  let residual = [];
  for (let i = 0; i < visible.length; i++) for (let j = i + 1; j < visible.length; j++) {
    const a = visible[i], b = visible[j];
    const ox = (a._halfW + b._halfW) - Math.abs(a.targetX - b.targetX);
    const oy = (a._halfH + b._halfH) - Math.abs(a.targetY - b.targetY);
    if (ox > 0 && oy > 0) residual.push([a.id, b.id, +ox.toFixed(1), +oy.toFixed(1)]);
  }

  return {
    W, H, SCL, profile: solverProfile, consoleReserve, usableW, globeR, globe,
    pipeStart, pipeEnd, pipeTotal, colGap, srcNeed, confNeed, c1w, c2w, c3w, c4w,
    cols: { col1L, col1R, col2L, col2R, col3L, col3R, col4L, col4R },
    zones: Object.fromEntries(Object.entries(zones).map(([k, v]) => [k, v.bounds])),
    ref, preClamp, clampedX, clampedY, rescaleX, rescaleY,
    protoSpreadPreRescale: { minPX, maxPX, minPY, maxPY },
    afterSolver, iters, residual,
    nodes: allLayoutNodes.map(n => ({ id: n.id, zone: n.zone, x: n.targetX, y: n.targetY, hw: n._halfW, hh: n._halfH })),
  };
}
