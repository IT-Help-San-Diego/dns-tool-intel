// Full-pipeline replay of topology.js layoutAll() for the line-1266 claim.
// Ports, in order: computeScaling(668), computeNodeBox(677), column setup
// (910-1051), the shelf re-partition (1069-1151), the solver remap (1183-1226),
// and the overlap pass (1233-1272). Three clamp variants are compared.
//
// Text widths use the solver's estimateTextWidth. Conclusions that rest on a
// shape's radius floor (ENGINE w >= 54*2.4 = 129.6) are text-independent.

import fs from 'node:fs';

const DESKTOP = JSON.parse(fs.readFileSync(new URL('./output/desktop-layout.json', import.meta.url)));
const TABLET = JSON.parse(fs.readFileSync(new URL('./output/tablet-layout.json', import.meta.url)));
const MOBILE = JSON.parse(fs.readFileSync(new URL('./output/mobile-layout.json', import.meta.url)));
const SOLVER = { desktop: DESKTOP, tablet: TABLET, mobile: MOBILE };

function estimateTextWidth(text, fontSize) {
  let t = 0;
  for (const ch of text) {
    if (ch === ' ') t += 0.28;
    else if (/[mwMW]/.test(ch)) t += 0.82;
    else if (/[iltfr!|'.,:;]/.test(ch)) t += 0.32;
    else if (/[A-Z]/.test(ch)) t += 0.72;
    else if (/[a-z]/.test(ch)) t += 0.52;
    else if (/\d/.test(ch)) t += 0.56;
    else t += 0.56;
  }
  return t * fontSize;
}
function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, m) {
  const labelW = m(label, fontLabel);
  let subW = 0, n = 0;
  if (sub) { const L = sub.split('\n'); n = L.length; for (const l of L) subW = Math.max(subW, m(l, fontSub)); }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = n > 1 ? (n - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + subExtra); }
  return { w, h, halfW: w / 2, halfH: h / 2 };
}
function mkNodes() {
  const SOURCES = [
    ['root', 'Root / TLD', 'IANA Root Zone\nTLD Registries'],
    ['rdap', 'RDAP / WHOIS', 'Registration Data\nAccess Protocol'],
    ['ct', 'CT / Subdomains', 'crt.sh · Certspotter\nTransparency Logs'],
    ['cisa', 'CISA / Threat', 'BOD 19-02\nIP Scanner Detection'],
    ['probes', 'Probe Fleet', 'SMTP · DANE · TLS\nNmap · testssl.sh'],
  ].map(([id, label, sub]) => ({ id, label, sub, zone: 'source', radius: 30, shape: 'rect' }));
  const HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', zone: 'hub', radius: 44, shape: 'hub' };
  const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54, shape: undefined };
  const CONFIDENCE = [
    ['ietf', 'IETF Metadata', 'RFC Status · Errata\nDraft Tracker'],
    ['icae', 'ICAE', 'Accuracy Audit'],
    ['icuae', 'ICuAE', 'Currency Audit'],
    ['ede', 'EDE', 'Epistemic\nDisclosure'],
  ].map(([id, label, sub]) => ({ id, label, sub, zone: 'confidence', radius: id === 'ede' ? 48 : id === 'ietf' ? 36 : 42, shape: id === 'ietf' ? 'rect' : 'diamond' }));
  const STORAGE = [
    ['postgres', 'PostgreSQL', 'Scan Results · History\nDrift · Analytics', 36],
    ['fixtures', 'Golden Fixtures', 'Known-Good Baselines\nRFC Compliance Seeds', 34],
    ['wayback', 'Internet Archive', 'Wayback Machine\nPermanent Record', 32],
  ].map(([id, label, sub, radius]) => ({ id, label, sub, zone: 'storage', radius, shape: 'cylinder' }));
  const PROTOCOLS = ['SPF', 'DKIM', 'DMARC', 'DNSSEC', 'DANE', 'MTA-STS', 'TLS-RPT', 'BIMI', 'CAA']
    .map(l => ({ id: l.toLowerCase().replace(/-/g, ''), label: l, sub: null, zone: 'protocol', radius: 36, shape: 'circle' }));
  const OUTPUTS = [
    ['reports', 'Reports', 'Engineer · Executive\nRecon · Comparison'],
    ['jsonapi', 'JSON API', 'Analysis · Checksums\nSubdomains · Health'],
    ['seo', 'Schema.org', 'JSON-LD Structured Data\nGoogle · Rich Results'],
    ['badges', 'SVG Badges', 'Posture Indicators\nEmbeddable'],
  ].map(([id, label, sub]) => ({ id, label, sub, zone: 'output', radius: 36, shape: 'hexagon' }));
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

// clampMode: 'current' | 'center' (the claim's proposed fix) | 'skip' (mirror of line 1194)
function run(W, H, clampMode, SHOW_OUTPUTS = false) {
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FS = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = mkNodes();
  const all = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  all.forEach(n => { const b = computeNodeBox(n.shape, n.radius, n.label, n.sub, SCL, FL, FS, estimateTextWidth); Object.assign(n, { _boxW: b.w, _boxH: b.h, _halfW: b.halfW, _halfH: b.halfH }); });

  const titleSafe = Math.max(H * 0.07, 42), legendSafe = H * 0.95, usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const globeCx = W * 0.04 + globeR, globeCy = titleSafe + usableH * 0.42;
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
  const col1L = pipeStart, col1R = col1L + c1w, col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w, col4L = col3R + colGap, col4R = pipeEnd;

  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  const zones = {
    source: { bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe } },
    hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 } },
    engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 } },
    confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 } },
    storage: { bounds: { x1: col2L - c2w * 0.3, x2: col2R + c2w * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe } },
    protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 } },
    output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } },
  };

  // ---- shelf re-partition block (topology.js 1069-1151) ----
  const byZone = {};
  all.forEach(n => { (byZone[n.zone] = byZone[n.zone] || []).push(n); });
  function shelfNeed(members, zw, pad) {
    let rowW = 0, rowH = 0, needH = 0, rows = 0;
    members.forEach(nd => {
      const w = nd._halfW * 2, h = nd._halfH * 2;
      if (rowW > 0 && rowW + pad + w > zw) { needH += rowH; rows++; rowW = 0; rowH = 0; }
      rowW += rowW > 0 ? pad + w : w;
      if (h > rowH) rowH = h;
    });
    needH += rowH; rows++;
    return needH + pad * (rows - 1);
  }
  const keys = Object.keys(byZone).filter(k => zones[k]).sort();
  const grouped = {};
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

  // ---- solver remap (1183-1226) ----
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const solverData = SOLVER[profile].nodeCenters;
  const ref = { w: SOLVER[profile].canvas.width, h: SOLVER[profile].canvas.height };
  const usableW = W - consoleReserve;
  all.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) { nd._nosolver = true; return; }
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    const z = zones[nd.zone];
    if (z) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  });
  const missing = all.filter(n => n._nosolver).map(n => n.id);
  // protocol ellipse rescale
  const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
  const minPX = Math.min(...pxs), maxPX = Math.max(...pxs), minPY = Math.min(...pys), maxPY = Math.max(...pys);
  const pz = zones.protocol.bounds, padX = 52 * SCL, padY = 44 * SCL;
  const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
  if (maxPX - minPX > 1 && tx2 - tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
  if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });

  // ---- overlap pass (1233-1272) ----
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters = op + 1;
    let any = false;
    for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) {
      const a = all[i], b = all[j];
      const ohw = a._halfW + b._halfW + overlapPad, ohh = a._halfH + b._halfH + overlapPad;
      const odx = Math.abs(b.targetX - a.targetX), ody = Math.abs(b.targetY - a.targetY);
      if (odx < ohw && ody < ohh) {
        const overX = ohw - odx, overY = ohh - ody, s = 0.7;
        if (overX < overY) { const sx = (b.targetX >= a.targetX ? 1 : -1) * overX * s; a.targetX -= sx; b.targetX += sx; }
        else { const sy = (b.targetY >= a.targetY ? 1 : -1) * overY * s; a.targetY -= sy; b.targetY += sy; }
        any = true;
      }
    }
    if (!any) break;
    all.forEach(nd => {
      const z = zones[nd.zone];
      if (z) {
        const hw = nd._halfW, hh = nd._halfH, B = z.bounds;
        if (clampMode === 'current') {
          nd.targetX = Math.max(B.x1 + hw, Math.min(B.x2 - hw, nd.targetX));
          nd.targetY = Math.max(B.y1 + hh, Math.min(B.y2 - hh, nd.targetY));
        } else if (clampMode === 'center') {
          if (B.x1 + hw <= B.x2 - hw) nd.targetX = Math.max(B.x1 + hw, Math.min(B.x2 - hw, nd.targetX)); else nd.targetX = (B.x1 + B.x2) / 2;
          if (B.y1 + hh <= B.y2 - hh) nd.targetY = Math.max(B.y1 + hh, Math.min(B.y2 - hh, nd.targetY)); else nd.targetY = (B.y1 + B.y2) / 2;
        } else { // 'skip' — true mirror of line 1194
          if (B.x1 + hw < B.x2 - hw) nd.targetX = Math.max(B.x1 + hw, Math.min(B.x2 - hw, nd.targetX));
          if (B.y1 + hh < B.y2 - hh) nd.targetY = Math.max(B.y1 + hh, Math.min(B.y2 - hh, nd.targetY));
        }
      }
      nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    });
  }

  // residual AABB overlaps between VISIBLE nodes (outputs hidden when !SHOW_OUTPUTS)
  const vis = all.filter(n => SHOW_OUTPUTS || n.zone !== 'output');
  let pairs = 0, worst = 0, worstPair = '';
  for (let i = 0; i < vis.length; i++) for (let j = i + 1; j < vis.length; j++) {
    const a = vis[i], b = vis[j];
    const ox = (a._halfW + b._halfW) - Math.abs(b.targetX - a.targetX);
    const oy = (a._halfH + b._halfH) - Math.abs(b.targetY - a.targetY);
    if (ox > 0 && oy > 0) { pairs++; const area = ox * oy; if (area > worst) { worst = area; worstPair = a.id + '/' + b.id; } }
  }
  return { W, H, SCL, pipeTotal, colGap, c1w, c2w, c3w, c4w, col2L, col2R, col3L, col3R, col4L, col4R, pipeEnd,
           zones, all, iters, pairs, worst, worstPair, missing, globalBounds, titleSafe, legendSafe };
}

function fmt(n) { return (Math.round(n * 10) / 10).toFixed(1); }

for (const [W, H] of [[1950, 900], [1600, 900], [1400, 900], [1233, 750], [1024, 768], [800, 600]]) {
  const cur = run(W, H, 'current');
  const ctr = run(W, H, 'center');
  const skp = run(W, H, 'skip');
  console.log(`\n================ W=${W} H=${H} (SHOW_OUTPUTS=false, as shipped) ================`);
  console.log(` output band: [${fmt(cur.col4L)}, ${fmt(cur.col4R)}]  width=${fmt(cur.col4R - cur.col4L)}  (INVERTED)`);
  console.log(` engine band: [${fmt(cur.col2L)}, ${fmt(cur.col2R)}]  width=${fmt(cur.c2w)}   engine box w=${fmt(cur.all.find(n => n.id === 'engine')._boxW)}`);
  console.log(` solver ids missing: ${cur.missing.length ? cur.missing.join(',') : 'none'}`);
  console.log(` iters current=${cur.iters} center=${ctr.iters} skip=${skp.iters} | residual visible overlap pairs: current=${cur.pairs} center=${ctr.pairs} skip=${skp.pairs} (worst ${cur.worstPair})`);
  const rows = [];
  cur.all.forEach(n => {
    const c = ctr.all.find(m => m.id === n.id), s = skp.all.find(m => m.id === n.id);
    const dC = Math.hypot(c.targetX - n.targetX, c.targetY - n.targetY);
    const dS = Math.hypot(s.targetX - n.targetX, s.targetY - n.targetY);
    if (dC > 0.05 || dS > 0.05) rows.push(` ${n.id.padEnd(9)} cur=(${fmt(n.targetX)},${fmt(n.targetY)})  Δcenter=${fmt(dC)}  Δskip=${fmt(dS)}`);
  });
  console.log(rows.length ? ' moved nodes:\n' + rows.join('\n') : ' moved nodes: NONE — both proposed fixes are no-ops here');
  const outs = ['reports', 'jsonapi', 'seo', 'badges'];
  console.log(' phantom output x:  current=' + outs.map(o => fmt(cur.all.find(n => n.id === o).targetX)).join(',') +
              '  | center=' + outs.map(o => fmt(ctr.all.find(n => n.id === o).targetX)).join(',') +
              '  | skip=' + outs.map(o => fmt(skp.all.find(n => n.id === o).targetX)).join(','));
  const protos = ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'];
  const px = protos.map(p => cur.all.find(n => n.id === p)).filter(Boolean);
  if (px.length) {
    const sx = px.map(p => p.targetX);
    console.log(` protocol x spread (current): min=${fmt(Math.min(...sx))} max=${fmt(Math.max(...sx))} span=${fmt(Math.max(...sx) - Math.min(...sx))}  zone=[${fmt(cur.col3L)},${fmt(cur.col3R)}]`);
    const sk = protos.map(p => skp.all.find(n => n.id === p)).filter(Boolean).map(p => p.targetX);
    console.log(` protocol x spread (skip):    min=${fmt(Math.min(...sk))} max=${fmt(Math.max(...sk))} span=${fmt(Math.max(...sk) - Math.min(...sk))}`);
  }
  // y-degeneracy after re-partition
  const ydeg = cur.all.filter(n => cur.zones[n.zone] && (2 * n._halfH > cur.zones[n.zone].bounds.y2 - cur.zones[n.zone].bounds.y1));
  console.log(' y-degenerate after shelf re-partition: ' + (ydeg.length ? ydeg.map(n => `${n.id}(h=${fmt(2 * n._halfH)} band=${fmt(cur.zones[n.zone].bounds.y2 - cur.zones[n.zone].bounds.y1)})`).join(' ') : 'none'));
}
