// Faithful replica of layoutAll() from go-server/static/js/topology.js
// for auditing the 'storage zone overhang' claim at line 1039.
// Text widths use the solver's own estimateTextWidth (same one the shipped
// layout JSON was solved with) since canvas measureText is unavailable.
import { readFileSync } from 'node:fs';

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
  return total * fontSize;
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
  const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54, shape: undefined };
  const CONFIDENCE = [
    { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker', zone: 'confidence' },
    { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit', zone: 'confidence' },
    { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit', zone: 'confidence' },
    { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure', zone: 'confidence' },
  ];
  CONFIDENCE.forEach(c => {
    c.radius = c.id === 'ede' ? 48 : c.id === 'ietf' ? 36 : 42;
    c.shape = c.id === 'ietf' ? 'rect' : 'diamond';
  });
  const STORAGE = [
    { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics', zone: 'storage' },
    { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', zone: 'storage' },
    { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', zone: 'storage' },
  ];
  STORAGE.forEach(s => {
    s.radius = s.id === 'postgres' ? 36 : s.id === 'wayback' ? 32 : 34;
    s.shape = 'cylinder';
  });
  const PROTOCOLS = [
    { id: 'spf', label: 'SPF' }, { id: 'dkim', label: 'DKIM' }, { id: 'dmarc', label: 'DMARC' },
    { id: 'dnssec', label: 'DNSSEC' }, { id: 'dane', label: 'DANE' }, { id: 'mtasts', label: 'MTA-STS' },
    { id: 'tlsrpt', label: 'TLS-RPT' }, { id: 'bimi', label: 'BIMI' }, { id: 'caa', label: 'CAA' },
  ];
  PROTOCOLS.forEach(p => { p.radius = 36; p.shape = 'circle'; p.zone = 'protocol'; p.sub = null; });
  const OUTPUTS = [
    { id: 'reports', label: 'Reports', sub: 'Engineer · Executive\nRecon · Comparison', zone: 'output' },
    { id: 'jsonapi', label: 'JSON API', sub: 'Analysis · Checksums\nSubdomains · Health', zone: 'output' },
    { id: 'seo', label: 'Schema.org', sub: 'JSON-LD Structured Data\nGoogle · Rich Results', zone: 'output' },
    { id: 'badges', label: 'SVG Badges', sub: 'Posture Indicators\nEmbeddable', zone: 'output' },
  ];
  OUTPUTS.forEach(o => { o.radius = 36; o.shape = 'hexagon'; });
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

const SHOW_OUTPUTS = false; // topology.js line 2117

function run(W, H, opts = {}) {
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = mkNodes();
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));

  function measure(n) {
    const labelW = estimateTextWidth(n.label, FONT_LABEL);
    let subW = 0, subLineCount = 0;
    if (n.sub) {
      const lines = n.sub.split('\n');
      subLineCount = lines.length;
      for (const l of lines) subW = Math.max(subW, estimateTextWidth(l, FONT_SUB));
    }
    const contentW = Math.max(labelW, subW) + 24 * SCL;
    const subExtra = subLineCount > 1 ? (subLineCount - 1) * (FONT_SUB + 2) : 0;
    let w, h;
    if (n.shape === 'circle') { w = Math.max(n.radius * 2, contentW); h = n.radius * 2; }
    else if (n.shape === 'diamond') { w = Math.max(n.radius * 1.7, contentW + 8); h = n.radius * 1.7 + subExtra; }
    else if (n.shape === 'hexagon') { w = Math.max(n.radius * 2, contentW); h = n.radius * 2 + subExtra; }
    else if (n.shape === 'cylinder') { w = Math.max(n.radius * 2.4, contentW); h = n.radius * 1.5 + 16 + subExtra; }
    else if (n.shape === 'hub' || n.shape === 'roundRect') { w = Math.max(n.radius * 2.4, contentW); h = Math.max(n.radius * 1.4, 40 * SCL); }
    else { w = Math.max(n.radius * 2.4, contentW); h = Math.max(n.radius * 1.3, 40 * SCL + (subLineCount > 1 ? (subLineCount - 1) * (FONT_SUB + 2) : 0)); }
    n._boxW = w; n._boxH = h; n._halfW = w / 2; n._halfH = h / 2;
  }

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

  [...SOURCES, HUB, ...CONFIDENCE].forEach(measure);
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

  const srcCx = (col1L + col1R) / 2;
  const procCx = (col2L + col2R) / 2;
  const protoCx = (col3L + col3R) / 2;
  const outCx = (col4L + col4R) / 2;
  const confY = titleSafe + usableH * 0.42;
  const storeY = titleSafe + usableH * 0.78;
  const protoCy = titleSafe + usableH * 0.42;

  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  const over = opts.noOverhang ? 0 : c2w * 0.3;

  const zones = {
    source: { bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe } },
    hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 } },
    engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 } },
    confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 } },
    storage: { bounds: { x1: col2L - over, x2: col2R + over, y1: titleSafe + usableH * 0.68, y2: legendSafe } },
    protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 } },
    output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } },
  };

  const allLayoutNodes = [...SOURCES, HUB, ENGINE, ...CONFIDENCE, ...STORAGE, ...PROTOCOLS, ...OUTPUTS];
  allLayoutNodes.forEach(measure);

  // --- re-partition block (lines 1069-1151) ---
  const repartLog = [];
  (function () {
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
      const anyDeficit = stack.some(zk => {
        const zb = zones[zk].bounds;
        return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1;
      });
      repartLog.push({ stack: stack.slice(), anyDeficit });
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1;
      const bottom = zones[stack[stack.length - 1]].bounds.y2;
      let needs = null, usedPad = 0;
      for (const p of [14, 8, 4, 0]) {
        const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
        const total = n.reduce((s, v) => s + v, 0) + p * (stack.length - 1);
        if (total <= bottom - top) { needs = n; usedPad = p; break; }
      }
      if (!needs) { repartLog[repartLog.length - 1].result = 'infeasible-keep'; return; }
      const leftover = (bottom - top) - needs.reduce((s, v) => s + v, 0) - usedPad * (stack.length - 1);
      const share = leftover / stack.length;
      let cursor = top;
      stack.forEach((zk, i) => {
        zones[zk].bounds.y1 = cursor;
        zones[zk].bounds.y2 = cursor + needs[i] + share;
        cursor = zones[zk].bounds.y2 + usedPad;
        grouped[zk] = true;
      });
      repartLog[repartLog.length - 1].result = 'repartitioned';
    });
  })();

  // --- solver remap ---
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const data = JSON.parse(readFileSync(new URL(`./output/${profile}-layout.json`, import.meta.url)));
  const ref = { w: data.canvas.width, h: data.canvas.height };
  const solverData = data.nodeCenters;
  const usableW = W - consoleReserve;
  const preRescale = {};
  allLayoutNodes.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    const raw = { x: nd.targetX, y: nd.targetY };
    const z = zones[nd.zone || nd.id];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    preRescale[nd.id] = { raw, clamped: { x: nd.targetX, y: nd.targetY }, clampedX: Math.abs(raw.x - nd.targetX) > 0.01 };
  });

  // protocol ellipse rescale
  const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
  const minPX = Math.min(...pxs), maxPX = Math.max(...pxs);
  const minPY = Math.min(...pys), maxPY = Math.max(...pys);
  const pz = zones.protocol.bounds;
  const padX = 52 * SCL, padY = 44 * SCL;
  const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
  if (maxPX - minPX > 1 && tx2 - tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
  if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });

  const entering = {};
  allLayoutNodes.forEach(n => { entering[n.id] = { x: n.targetX, y: n.targetY, hw: n._halfW, hh: n._halfH }; });

  // --- live overlap pass ---
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters++;
    let any = false;
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
          any = true;
        }
      }
    }
    if (!any) break;
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

  // final drawn-ink AABB overlaps
  const inkOverlaps = [];
  for (let i = 0; i < allLayoutNodes.length; i++) {
    for (let j = i + 1; j < allLayoutNodes.length; j++) {
      const a = allLayoutNodes[i], b = allLayoutNodes[j];
      if (!SHOW_OUTPUTS && (a.zone === 'output' || b.zone === 'output')) continue;
      const ox = (a._halfW + b._halfW) - Math.abs(a.targetX - b.targetX);
      const oy = (a._halfH + b._halfH) - Math.abs(a.targetY - b.targetY);
      if (ox > 0 && oy > 0) inkOverlaps.push({ a: a.id, b: b.id, ox: +ox.toFixed(1), oy: +oy.toFixed(1), cross: (a.zone || a.id) !== (b.zone || b.id) });
    }
  }

  return {
    W, H, SCL, consoleReserve, pipeStart: +pipeStart.toFixed(2), pipeEnd: +pipeEnd.toFixed(2),
    pipeTotal: +pipeTotal.toFixed(2), colGap: +colGap.toFixed(3),
    srcNeed: +srcNeed.toFixed(2), confNeed: +confNeed.toFixed(2),
    c1w: +c1w.toFixed(2), c2w: +c2w.toFixed(2), c3w: +c3w.toFixed(2),
    cols: { col1L: +col1L.toFixed(2), col1R: +col1R.toFixed(2), col2L: +col2L.toFixed(2), col2R: +col2R.toFixed(2), col3L: +col3L.toFixed(2), col3R: +col3R.toFixed(2) },
    storageZone: { x1: +zones.storage.bounds.x1.toFixed(2), x2: +zones.storage.bounds.x2.toFixed(2), y1: +zones.storage.bounds.y1.toFixed(2), y2: +zones.storage.bounds.y2.toFixed(2) },
    overhangEachSide: +(over - colGap).toFixed(2),
    repartLog,
    entering: Object.fromEntries(['postgres', 'fixtures', 'wayback', 'bimi', 'dkim', 'mtasts'].map(id => [id, { x: +entering[id].x.toFixed(1), y: +entering[id].y.toFixed(1), hw: +entering[id].hw.toFixed(1), hh: +entering[id].hh.toFixed(1) }])),
    storageClampedInX: ['postgres', 'fixtures', 'wayback'].map(id => ({ id, rawX: +preRescale[id].raw.x.toFixed(1), clampedX: +preRescale[id].clamped.x.toFixed(1), wasClamped: preRescale[id].clampedX })),
    passIters: iters,
    final: Object.fromEntries(allLayoutNodes.filter(n => ['postgres', 'fixtures', 'wayback', 'bimi', 'dkim', 'mtasts', 'ede', 'icuae'].includes(n.id)).map(n => [n.id, { x: +n.targetX.toFixed(1), y: +n.targetY.toFixed(1) }])),
    inkOverlaps,
  };
}

export { run };

if (process.env.SWEEP === '1') {
  const S = ['postgres', 'fixtures', 'wayback'];
  const P = ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'];
  const isSP = o => (S.includes(o.a) && P.includes(o.b)) || (S.includes(o.b) && P.includes(o.a));
  let better = 0, worse = 0, same = 0;
  const hits = [], hitsFixed = [], worseRows = [], collapse = [];
  for (let W = 1000; W <= 2300; W += 25) {
    for (let H = 650; H <= 1300; H += 25) {
      const a = run(W, H), b = run(W, H, { noOverhang: true });
      if (a.inkOverlaps.some(isSP)) hits.push([W, H, JSON.stringify(a.inkOverlaps.filter(isSP))]);
      if (b.inkOverlaps.some(isSP)) hitsFixed.push([W, H]);
      if (a.inkOverlaps.length > b.inkOverlaps.length) better++;
      else if (a.inkOverlaps.length < b.inkOverlaps.length) { worse++; worseRows.push([W, H, a.inkOverlaps.length, b.inkOverlaps.length]); }
      else same++;
      const protoCross = a.inkOverlaps.filter(o => P.includes(o.a) && P.includes(o.b));
      if (protoCross.length >= 5) collapse.push([W, H, protoCross.length, b.inkOverlaps.filter(o => P.includes(o.a) && P.includes(o.b)).length]);
    }
  }
  console.log('sweep W 1000..2300 x H 650..1300 (step 25), n =', better + worse + same);
  console.log('  overhang produces MORE final ink overlaps than the fix (fix helps):', better);
  console.log('  fix produces MORE final ink overlaps than overhang (fix hurts):', worse, worseRows.slice(0, 10));
  console.log('  identical:', same);
  console.log('  storage<->protocol INK overlaps WITH overhang:', hits.length, hits.slice(0, 6));
  console.log('  storage<->protocol INK overlaps WITHOUT overhang:', hitsFixed.length);
  console.log('  viewports with >=5 protocol-protocol ink overlaps (the reported column collapse):', collapse.length);
  console.log('    with overhang vs without (count,count) first 8:', collapse.slice(0, 8));
  console.log('    of those, count differs when overhang removed:', collapse.filter(c => c[2] !== c[3]).length);
  process.exit(0);
}

for (const [W, H] of [[1950, 900], [1950, 1100], [1233, 750], [800, 900], [1600, 900]]) {
  const base = run(W, H);
  const fixed = run(W, H, { noOverhang: true });
  console.log('='.repeat(78));
  console.log(`W=${W} H=${H}  SCL=${base.SCL.toFixed(3)} reserve=${base.consoleReserve}`);
  console.log(` pipeTotal=${base.pipeTotal} colGap=${base.colGap} c1w=${base.c1w} c2w=${base.c2w} c3w=${base.c3w}`);
  console.log(` cols`, base.cols);
  console.log(` storage zone`, base.storageZone, ' overhang past neighbour column each side =', base.overhangEachSide);
  console.log(` repartition:`, JSON.stringify(base.repartLog));
  console.log(` storage solver x clamp:`, JSON.stringify(base.storageClampedInX));
  console.log(` entering overlap pass:`, JSON.stringify(base.entering));
  console.log(` pass iterations: ${base.passIters}`);
  console.log(` final:`, JSON.stringify(base.final));
  console.log(` DRAWN-INK overlaps WITH overhang   (${base.inkOverlaps.length}):`, JSON.stringify(base.inkOverlaps));
  console.log(` DRAWN-INK overlaps WITHOUT overhang(${fixed.inkOverlaps.length}):`, JSON.stringify(fixed.inkOverlaps));
  console.log(` fixed pass iterations: ${fixed.passIters}  fixed final:`, JSON.stringify(fixed.final));
}
