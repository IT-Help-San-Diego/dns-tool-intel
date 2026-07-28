// Standalone replay of the client layout path in go-server/static/js/topology.js
// Purpose: verify the "ENGINE.shape is never assigned" claim's arithmetic.
// Text widths use the solver's own estimateTextWidth (nodeMetrics.ts) as a
// stand-in for canvas measureText; a --textk multiplier lets us stress the
// sensitivity of every conclusion to that approximation.

const TEXTK = Number(process.env.TEXTK || 1);

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
  return total * fontSize * TEXTK;
}

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, measureFn) {
  let labelW = measureFn(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    let lines = sub.split('\n');
    subLineCount = lines.length;
    for (let i = 0; i < lines.length; i++) {
      let sw = measureFn(lines[i], fontSub);
      if (sw > subW) subW = sw;
    }
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

function makeNodes(engineShape) {
  const SOURCES = [
    { id: 'root', label: 'Root / TLD', sub: 'IANA Root Zone\nTLD Registries' },
    { id: 'rdap', label: 'RDAP / WHOIS', sub: 'Registration Data\nAccess Protocol' },
    { id: 'ct', label: 'CT / Subdomains', sub: 'crt.sh · Certspotter\nTransparency Logs' },
    { id: 'cisa', label: 'CISA / Threat', sub: 'BOD 19-02\nIP Scanner Detection' },
    { id: 'probes', label: 'Probe Fleet', sub: 'SMTP · DANE · TLS\nNmap · testssl.sh' },
  ].map(s => ({ ...s, radius: 30, shape: 'rect', zone: 'source' }));

  const HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', zone: 'hub', radius: 44, shape: 'hub' };
  const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54 };
  if (engineShape) ENGINE.shape = engineShape;

  const CONFIDENCE = [
    { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker' },
    { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit' },
    { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit' },
    { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure' },
  ].map(c => ({ ...c, zone: 'confidence',
    radius: c.id === 'ede' ? 48 : c.id === 'ietf' ? 36 : 42,
    shape: c.id === 'ietf' ? 'rect' : 'diamond' }));

  const STORAGE = [
    { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics' },
    { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds' },
    { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record' },
  ].map(s => ({ ...s, zone: 'storage', shape: 'cylinder',
    radius: s.id === 'postgres' ? 36 : s.id === 'wayback' ? 32 : 34 }));

  const PROTOCOLS = ['SPF|spf', 'DKIM|dkim', 'DMARC|dmarc', 'DNSSEC|dnssec', 'DANE|dane',
    'MTA-STS|mtasts', 'TLS-RPT|tlsrpt', 'BIMI|bimi', 'CAA|caa']
    .map(s => { const [label, id] = s.split('|'); return { id, label, sub: null, radius: 36, shape: 'circle', zone: 'protocol' }; });

  const OUTPUTS = [
    { id: 'reports', label: 'Reports', sub: 'Engineer · Executive\nRecon · Comparison' },
    { id: 'jsonapi', label: 'JSON API', sub: 'Analysis · Checksums\nSubdomains · Health' },
    { id: 'seo', label: 'Schema.org', sub: 'JSON-LD Structured Data\nGoogle · Rich Results' },
    { id: 'badges', label: 'SVG Badges', sub: 'Posture Indicators\nEmbeddable' },
  ].map(o => ({ ...o, zone: 'output', radius: 36, shape: 'hexagon' }));

  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

import { readFileSync } from 'fs';
const SOLVER = JSON.parse(readFileSync(new URL('./output/desktop-layout.json', import.meta.url), 'utf8'));

function layout(W, H, engineShape, opts = {}) {
  const N = makeNodes(engineShape);
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = N;
  const SHOW_OUTPUTS = false;

  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const measure = estimateTextWidth;

  function measureNodeBox(n) {
    const b = computeNodeBox(n.shape, n.radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB, measure);
    n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH;
    return b;
  }

  const titleSafe = Math.max(H * 0.07, 42);
  const legendSafe = H * 0.95;
  const usableH = legendSafe - titleSafe;

  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const globe = { R: globeR, cx: W * 0.04 + globeR, cy: titleSafe + usableH * 0.42 };

  const pipeStart = globe.cx + globeR + W * 0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W * 0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal * 0.01);

  SOURCES.forEach(measureNodeBox); measureNodeBox(HUB); CONFIDENCE.forEach(measureNodeBox);
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

  const procCx = (col2L + col2R) / 2;
  const confY = titleSafe + usableH * 0.42;
  const storeY = titleSafe + usableH * 0.78;

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

  const bandsBefore = JSON.parse(JSON.stringify({
    engine: zones.engine.bounds, confidence: zones.confidence.bounds, storage: zones.storage.bounds }));

  const allLayoutNodes = [...SOURCES, HUB, ENGINE, ...CONFIDENCE, ...STORAGE, ...PROTOCOLS, ...OUTPUTS];
  allLayoutNodes.forEach(measureNodeBox);

  // ---- re-partition block (lines 1069-1151) ----
  let repartitioned = false;
  if (!opts.skipRepartition) (function () {
    const byZone = {};
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
    const keys = [];
    for (const zk in byZone) if (zones[zk] && zones[zk].bounds) keys.push(zk);
    keys.sort();
    const grouped = {};
    keys.forEach(ka => {
      if (grouped[ka]) return;
      const a = zones[ka].bounds;
      const stack = [ka];
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
      const deficits = stack.map(zk => {
        const zb = zones[zk].bounds;
        return { zk, need: shelfNeed(byZone[zk], zb.x2 - zb.x1, 0), band: zb.y2 - zb.y1 };
      });
      const anyDeficit = deficits.some(d => d.need > d.band);
      if (opts.log) console.log('  stack', stack.join(','), 'pad0 needs/bands:',
        deficits.map(d => `${d.zk} ${d.need.toFixed(1)}/${d.band.toFixed(1)}`).join('  '), '=> deficit', anyDeficit);
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1;
      const bottom = zones[stack[stack.length - 1]].bounds.y2;
      let needs = null, usedPad = 0;
      for (const p of [14, 8, 4, 0]) {
        const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
        const total = n.reduce((s, v) => s + v, 0) + p * (stack.length - 1);
        if (total <= bottom - top) { needs = n; usedPad = p; break; }
      }
      if (!needs) return;
      repartitioned = true;
      const leftover = (bottom - top) - needs.reduce((s, v) => s + v, 0) - usedPad * (stack.length - 1);
      const share = leftover / stack.length;
      let cursor = top;
      stack.forEach((zk, i) => {
        zones[zk].bounds.y1 = cursor;
        zones[zk].bounds.y2 = cursor + needs[i] + share;
        cursor = zones[zk].bounds.y2 + usedPad;
        grouped[zk] = true;
      });
    });
  })();

  // ---- solver remap ----
  const solverData = SOLVER.nodeCenters;
  const ref = { w: SOLVER.canvas.width, h: SOLVER.canvas.height };
  const usableW = W - consoleReserve;
  allLayoutNodes.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    nd._rawY = nd.targetY;
    const z = zones[nd.zone || nd.id];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  });
  // protocol ellipse rescale
  {
    const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
    const minPX = Math.min(...pxs), maxPX = Math.max(...pxs), minPY = Math.min(...pys), maxPY = Math.max(...pys);
    const pz = zones.protocol.bounds;
    const padX = 52 * SCL, padY = 44 * SCL;
    const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
    if (maxPX - minPX > 1 && tx2 - tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
    if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });
  }

  // ---- overlap pass ----
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    let any = false;
    for (let i = 0; i < allLayoutNodes.length; i++) for (let j = i + 1; j < allLayoutNodes.length; j++) {
      const na = allLayoutNodes[i], nb = allLayoutNodes[j];
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
    iters = op + 1;
    allLayoutNodes.forEach(nd => {
      const z = zones[nd.zone || nd.id];
      if (z && z.bounds) {
        const hw = nd._halfW || nd.radius, hh = nd._halfH || nd.radius;
        nd.targetX = Math.max(z.bounds.x1 + hw, Math.min(z.bounds.x2 - hw, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1 + hh, Math.min(z.bounds.y2 - hh, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    });
  }

  return { W, H, SCL, titleSafe, legendSafe, usableH, consoleReserve, c2w, col2L, col2R,
    zones, bandsBefore, repartitioned, iters, ENGINE, CONFIDENCE, STORAGE, allLayoutNodes };
}

function report(W, H) {
  console.log(`\n=== W=${W} H=${H}  (TEXTK=${TEXTK}) ===`);
  for (const shape of [undefined, 'circle']) {
    const r = layout(W, H, shape, { log: shape === undefined });
    const eb = r.zones.engine.bounds, cb = r.zones.confidence.bounds, sb = r.zones.storage.bounds;
    const e = r.ENGINE;
    console.log(` engineShape=${shape || 'undefined(->rect default)'}  SCL=${r.SCL.toFixed(3)} titleSafe=${r.titleSafe.toFixed(1)} usableH=${r.usableH.toFixed(1)}`);
    console.log(`   ENGINE box: halfW=${e._halfW.toFixed(1)} halfH=${e._halfH.toFixed(1)} (h=${e._boxH.toFixed(1)})`);
    console.log(`   bands BEFORE: engine ${r.bandsBefore.engine.y1.toFixed(1)}..${r.bandsBefore.engine.y2.toFixed(1)} (h=${(r.bandsBefore.engine.y2 - r.bandsBefore.engine.y1).toFixed(1)})`);
    console.log(`   bands AFTER : engine ${eb.y1.toFixed(1)}..${eb.y2.toFixed(1)} (h=${(eb.y2 - eb.y1).toFixed(1)})  conf ${cb.y1.toFixed(1)}..${cb.y2.toFixed(1)}  stor ${sb.y1.toFixed(1)}..${sb.y2.toFixed(1)}  repart=${r.repartitioned}`);
    console.log(`   ENGINE final target y=${e.targetY.toFixed(1)} x=${e.targetX.toFixed(1)}  drawn circle (r=54+-3) spans y ${(e.targetY - 57).toFixed(1)}..${(e.targetY + 57).toFixed(1)}; titleSafe=${r.titleSafe.toFixed(1)}`);
    const above = r.titleSafe - (e.targetY - 57);
    console.log(`   circle pokes ${above.toFixed(1)}px above titleSafe; overlap-pass iters=${r.iters}`);
    // nearest neighbour in drawn-ink terms (engine circle r=57 vs neighbours' halfH)
    let worst = null;
    r.allLayoutNodes.forEach(nd => {
      if (nd === e || nd.zone === 'output') return;
      const dx = Math.abs(nd.targetX - e.targetX), dy = Math.abs(nd.targetY - e.targetY);
      const ox = 57 + (nd._halfW || nd.radius) - dx, oy = 57 + (nd._halfH || nd.radius) - dy;
      if (ox > 0 && oy > 0) { const m = Math.min(ox, oy); if (!worst || m > worst.m) worst = { id: nd.id, m, ox, oy }; }
    });
    console.log(`   drawn-ink overlap vs neighbours: ${worst ? worst.id + ' by ' + worst.m.toFixed(1) + 'px' : 'none'}`);
  }
}


for (const [w, h] of [[1950, 750], [1233, 750], [1024, 768], [800, 750], [1918, 750], [1950, 1000]]) report(w, h);

console.log('\n\n########## COUNTERFACTUAL: repartition skipped (pre-ba815061b band behaviour) ##########');
for (const [w, h] of [[1950, 750], [1233, 750]]) {
  for (const shape of [undefined, 'circle']) {
    const r = layout(w, h, shape, { skipRepartition: true });
    const e = r.ENGINE;
    console.log(` W=${w} H=${h} shape=${shape||'undef'}  band ${r.zones.engine.bounds.y1.toFixed(1)}..${r.zones.engine.bounds.y2.toFixed(1)}  engine y=${e.targetY.toFixed(1)}  circle ${(e.targetY-57).toFixed(1)}..${(e.targetY+57).toFixed(1)}  titleSafe=${r.titleSafe.toFixed(1)}`);
  }
}

console.log('\n########## neighbour positions at W=1950 H=750 ##########');
for (const shape of [undefined, 'circle']) {
  const r = layout(1950, 750, shape);
  const e = r.ENGINE;
  console.log(` shape=${shape||'undef'} engine (${e.targetX.toFixed(1)}, ${e.targetY.toFixed(1)}) halfH=${e._halfH.toFixed(1)}`);
  r.allLayoutNodes.filter(n => ['ietf','icae','icuae','dkim','spf'].includes(n.id)).forEach(n => {
    const dx = Math.abs(n.targetX-e.targetX), dy = Math.abs(n.targetY-e.targetY);
    console.log(`   ${n.id.padEnd(7)} (${n.targetX.toFixed(1)}, ${n.targetY.toFixed(1)}) halfW=${n._halfW.toFixed(1)} halfH=${n._halfH.toFixed(1)}  gapX=${(dx-57-n._halfW).toFixed(1)} gapY=${(dy-57-n._halfH).toFixed(1)} (neg both = drawn circle overlaps its box)`);
  });
}
