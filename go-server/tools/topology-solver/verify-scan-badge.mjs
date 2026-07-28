// Independent replication of topology.js layoutAll() (SOLVER_ACTIVE path) plus
// the exact geometry of drawScanNodeLabel(), to test the claim that per-phase
// timing badges are unmeasured and collide with neighbouring nodes.
//
// Differences from ring-audit.mjs (deliberate, for fidelity):
//   * OUTPUTS ARE included in `all` — the client puts them in allLayoutNodes
//     unconditionally (line 1053), even though SHOW_OUTPUTS is false, so they
//     participate in the overlap pass and can shove protocol circles.
//   * _drawW/_drawH are modelled exactly: only drawNodeTag (rect), drawHubNode
//     and drawStorageNode assign them. drawProtocolNode and drawEngineNode do
//     not, so effRadius() falls back to radius*1.1 for those.
import fs from 'fs';

const AFM = {
  ' ':278,'!':278,'"':355,'#':556,'$':556,'%':889,'&':667,"'":191,'(':333,')':333,
  '*':389,'+':584,',':278,'-':333,'.':278,'/':278,
  '0':556,'1':556,'2':556,'3':556,'4':556,'5':556,'6':556,'7':556,'8':556,'9':556,
  ':':278,';':278,'<':584,'=':584,'>':584,'?':556,'@':1015,
  'A':667,'B':667,'C':722,'D':722,'E':667,'F':611,'G':778,'H':722,'I':278,'J':500,
  'K':667,'L':556,'M':833,'N':722,'O':778,'P':667,'Q':778,'R':722,'S':667,'T':611,
  'U':722,'V':667,'W':944,'X':667,'Y':667,'Z':611,
  '[':278,'\\':278,']':278,'^':469,'_':556,'`':333,
  'a':556,'b':556,'c':500,'d':556,'e':556,'f':278,'g':556,'h':556,'i':222,'j':222,
  'k':500,'l':222,'m':833,'n':556,'o':556,'p':556,'q':556,'r':333,'s':500,'t':278,
  'u':722,'v':500,'w':722,'x':500,'y':500,'z':500,
  '{':334,'|':260,'}':334,'~':584,'·':278
};
AFM['u'] = 556;
function measureText(text, fontSize) {
  let u = 0;
  for (const ch of String(text)) u += (AFM[ch] !== undefined ? AFM[ch] : 556);
  return u / 1000 * fontSize;
}

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub) {
  const labelW = measureText(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const sw = measureText(l, fontSub); if (sw > subW) subW = sw; }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle')        { w = Math.max(radius * 2, contentW);       h = radius * 2; }
  else if (shape === 'diamond')  { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon')  { w = Math.max(radius * 2, contentW);       h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW);     h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + subExtra); }
  return { w, h, halfW: w / 2, halfH: h / 2, subLineCount };
}

function buildNodes() {
  const SOURCES = [
    { id:'root',  label:'Root / TLD',      sub:'IANA Root Zone\nTLD Registries',          zone:'source' },
    { id:'rdap',  label:'RDAP / WHOIS',    sub:'Registration Data\nAccess Protocol',      zone:'source' },
    { id:'ct',    label:'CT / Subdomains', sub:'crt.sh · Certspotter\nTransparency Logs', zone:'source' },
    { id:'cisa',  label:'CISA / Threat',   sub:'BOD 19-02\nIP Scanner Detection',         zone:'source' },
    { id:'probes',label:'Probe Fleet',     sub:'SMTP · DANE · TLS\nNmap · testssl.sh', zone:'source' }
  ];
  SOURCES.forEach(s => { s.radius = 30; s.shape = 'rect'; });
  const HUB = { id:'hub', label:'DNS Resolvers', sub:'Signal Aggregation', zone:'hub', radius:44, shape:'hub' };
  const ENGINE = { id:'engine', label:'ICIE', sub:'Analysis Engine', zone:'engine', radius:54 }; // NO shape
  const CONFIDENCE = [
    { id:'ietf',  label:'IETF Metadata', sub:'RFC Status · Errata\nDraft Tracker', zone:'confidence' },
    { id:'icae',  label:'ICAE',  sub:'Accuracy Audit',   zone:'confidence' },
    { id:'icuae', label:'ICuAE', sub:'Currency Audit',   zone:'confidence' },
    { id:'ede',   label:'EDE',   sub:'Epistemic\nDisclosure', zone:'confidence' }
  ];
  CONFIDENCE.forEach(c => { c.radius = c.id === 'ede' ? 48 : c.id === 'ietf' ? 36 : 42; c.shape = c.id === 'ietf' ? 'rect' : 'diamond'; });
  const STORAGE = [
    { id:'postgres', label:'PostgreSQL',       sub:'Scan Results · History\nDrift · Analytics', zone:'storage' },
    { id:'fixtures', label:'Golden Fixtures',  sub:'Known-Good Baselines\nRFC Compliance Seeds', zone:'storage' },
    { id:'wayback',  label:'Internet Archive', sub:'Wayback Machine\nPermanent Record',  zone:'storage' }
  ];
  STORAGE.forEach(s => { s.radius = s.id === 'postgres' ? 36 : s.id === 'wayback' ? 32 : 34; s.shape = 'cylinder'; });
  const PROTOCOLS = ['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'].map((id, i) => ({
    id, label:['SPF','DKIM','DMARC','DNSSEC','DANE','MTA-STS','TLS-RPT','BIMI','CAA'][i],
    radius:36, shape:'circle', zone:'protocol'
  }));
  const OUTPUTS = [
    { id:'reports', label:'Reports',   sub:'Engineer · Executive\nRecon · Comparison', zone:'output' },
    { id:'jsonapi', label:'JSON API',  sub:'Analysis · Checksums\nSubdomains · Health', zone:'output' },
    { id:'seo',     label:'Schema.org',sub:'JSON-LD Structured Data\nGoogle · Rich Results', zone:'output' },
    { id:'badges',  label:'SVG Badges',sub:'Posture Indicators\nEmbeddable', zone:'output' }
  ];
  OUTPUTS.forEach(o => { o.radius = 36; o.shape = 'hexagon'; });
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

function layout(W, H, solverLayouts) {
  const N = buildNodes();
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = N;
  const SHOW_OUTPUTS = false;

  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));

  const all = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  const measure = n => {
    const b = computeNodeBox(n.shape, n.radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB);
    n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH; n._subLines = b.subLineCount;
  };
  all.forEach(measure);

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
  const outCx = (col4L + col4R) / 2;
  const confY = titleSafe + usableH * 0.42;
  const storeY = titleSafe + usableH * 0.78;
  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };

  const zones = {
    source:     { bounds:{ x1:col1L, x2:col1R, y1:titleSafe, y2:legendSafe } },
    hub:        { bounds:{ x1:col1L, x2:col1R, y1:titleSafe + usableH*0.20, y2:titleSafe + usableH*0.70 } },
    engine:     { bounds:{ x1:col2L, x2:col2R, y1:titleSafe, y2:titleSafe + usableH*0.30 } },
    confidence: { bounds:{ x1:col2L, x2:col2R, y1:titleSafe + usableH*0.25, y2:titleSafe + usableH*0.75 } },
    storage:    { bounds:{ x1:col2L - c2w*0.3, x2:col2R + c2w*0.3, y1:titleSafe + usableH*0.68, y2:legendSafe } },
    protocol:   { bounds:{ x1:col3L, x2:col3R, y1:titleSafe, y2:titleSafe + usableH*0.88 } },
    output:     { bounds:{ x1:col4L, x2:col4R, y1:titleSafe, y2:legendSafe } }
  };

  // --- stacked-band re-partition (ba815061b) ---
  (function () {
    const byZone = {};
    all.forEach(nd => { const zk = nd.zone || nd.id; (byZone[zk] = byZone[zk] || []).push(nd); });
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
    const keys = Object.keys(byZone).filter(zk => zones[zk] && zones[zk].bounds).sort();
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
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1;
      const bottom = zones[stack[stack.length - 1]].bounds.y2;
      let needs = null, usedPad = 0;
      for (const p of [14, 8, 4, 0]) {
        const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
        if (n.reduce((s, v) => s + v, 0) + p * (stack.length - 1) <= bottom - top) { needs = n; usedPad = p; break; }
      }
      if (!needs) return;
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

  // --- solver remap ---
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const L = solverLayouts[profile];
  const ref = { w: L.canvas.width, h: L.canvas.height };
  const usableW = W - consoleReserve;
  all.forEach(nd => {
    const pos = L.nodeCenters[nd.id];
    if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
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

  // --- protocol ellipse rescale ---
  {
    const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
    const minPX = Math.min(...pxs), maxPX = Math.max(...pxs);
    const minPY = Math.min(...pys), maxPY = Math.max(...pys);
    const pz = zones.protocol.bounds;
    const padX = 52 * SCL, padY = 44 * SCL;
    const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX;
    const ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
    if (maxPX - minPX > 1 && tx2 - tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
    if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });
  }

  // --- 40-iteration overlap pass ---
  const overlapPad = 14;
  for (let op = 0; op < 40; op++) {
    let anyOverlap = false;
    for (let oi = 0; oi < all.length; oi++) {
      for (let oj = oi + 1; oj < all.length; oj++) {
        const na = all[oi], nb = all[oj];
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
    all.forEach(nd => {
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
  all.forEach(nd => { nd.x = nd.targetX; nd.y = nd.targetY; });
  return { all, byId: Object.fromEntries(all.map(n => [n.id, n])), SCL, FONT_LABEL, FONT_SUB, zones, H, W, legendSafe };
}

// --- exact draw-time state ---
// _drawW/_drawH are set ONLY by drawNodeTag (rect), drawHubNode (hub) and
// drawStorageNode (cylinder). Confidence diamonds go through drawConfidenceNode
// which only delegates to drawNodeTag for shape 'rect' (ietf).
function applyDrawDims(all) {
  all.forEach(n => {
    if (n.shape === 'rect' || n.shape === 'hub' || n.shape === 'cylinder') {
      n._drawW = n._boxW; n._drawH = n._boxH;
    }
  });
}
function effRadius(n) {
  const hw = (n._drawW || n.radius * 2.2) / 2;
  const hh = (n._drawH || n.radius * 1.4) / 2;
  return Math.max(hw, hh, n.radius) + 6;
}

const GROUP_ANCHORS = ['hub','spf','dnssec','ct','probes','mtasts','root','engine'];
// SFMono / Menlo are fixed-advance at 0.6 em.
function monoWidth(text, fs) { return String(text).length * 0.6 * fs; }

const SOLVER = {};
for (const p of ['desktop','tablet','mobile']) {
  SOLVER[p] = JSON.parse(fs.readFileSync(new URL('./output/' + p + '-layout.json', import.meta.url), 'utf8'));
}

function badgeRect(n, SCL, text) {
  const fs2 = Math.round(9 * SCL);
  const top = n.y + effRadius(n) + 9;       // textBaseline 'top'
  const w = monoWidth(text, fs2);
  return { x1: n.x - w / 2, x2: n.x + w / 2, y1: top, y2: top + fs2, fs: fs2 };
}
function boxOf(n) {
  const hw = n._halfW || n.radius, hh = n._halfH || n.radius;
  return { x1: n.x - hw, x2: n.x + hw, y1: n.y - hh, y2: n.y + hh };
}
function rectsOverlap(a, b) {
  const ox = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
  const oy = Math.min(a.y2, b.y2) - Math.max(a.y1, b.y1);
  return (ox > 0 && oy > 0) ? { ox, oy } : null;
}

const BADGE_TEXT = '47.8s'; // longest realistic fmtScanDur output seen in the screenshot

for (const [W, H] of [[1950,1000],[1950,900],[1400,800],[1280,750],[1233,750],[800,900],[420,1780]]) {
  const R = layout(W, H, SOLVER);
  applyDrawDims(R.all);
  console.log(`\n==== W=${W} H=${H}  SCL=${R.SCL.toFixed(3)}  badgeFont=${Math.round(9*R.SCL)}`);
  for (const id of GROUP_ANCHORS) {
    const n = R.byId[id];
    if (!n) continue;
    const b = badgeRect(n, R.SCL, BADGE_TEXT);
    const own = boxOf(n);
    const hits = [];
    for (const q of R.all) {
      if (q === n) continue;
      const o = rectsOverlap(b, boxOf(q));
      if (o) hits.push(`${q.id}(ox=${o.ox.toFixed(1)},oy=${o.oy.toFixed(1)})`);
    }
    const offBottom = b.y2 > H ? ` OFF-CANVAS(by ${(b.y2 - H).toFixed(1)})` : '';
    const belowOwn = (b.y1 - own.y2).toFixed(1);
    console.log(`  ${id.padEnd(7)} y=${n.y.toFixed(1).padStart(7)} halfH=${(n._halfH||n.radius).toFixed(1).padStart(5)} effR=${effRadius(n).toFixed(1).padStart(6)} badge=[${b.y1.toFixed(1)}..${b.y2.toFixed(1)}] gapBelowOwnAABB=${belowOwn.padStart(6)}${offBottom}  hits: ${hits.length ? hits.join(' ') : 'none'}`);
  }
}

// --- would the PROPOSED FIX (a) actually clear the strip? -----------------
// Proposal: add Math.round(9*SCL)+15 to box.h for anchors. box.h is symmetric
// about n.y, so that only buys (font+15)/2 of extra halfH.
console.log('\n=== proposed fix (a): +(round(9*SCL)+15) to box.h — clearance arithmetic ===');
for (const [W,H] of [[1950,1000],[1400,800],[1233,750],[800,900]]) {
  const R = layout(W,H,SOLVER); applyDrawDims(R.all);
  const font = Math.round(9*R.SCL);
  console.log(`  W=${W} SCL=${R.SCL.toFixed(3)} font=${font} added-to-halfH=${((font+15)/2).toFixed(1)}`);
  for (const id of GROUP_ANCHORS) {
    const n = R.byId[id]; if (!n) continue;
    const needBelowCentre = effRadius(n) + 9 + font;      // badge bottom, relative to n.y
    const haveBelowCentre = (n._halfH || n.radius) + (font + 15) / 2;
    console.log(`    ${id.padEnd(7)} badge bottom needs ${needBelowCentre.toFixed(1)} below centre; fixed halfH gives ${haveBelowCentre.toFixed(1)}  ${haveBelowCentre >= needBelowCentre ? 'OK' : 'STILL SHORT by ' + (needBelowCentre-haveBelowCentre).toFixed(1)}`);
  }
}

// --- H sweep: does the badge ever fall off the bottom of the canvas? -------
console.log('\n=== H sweep at W=1950 and W=1233: lowest anchor badge bottom vs H ===');
for (const W of [1950, 1233, 800]) {
  for (const H of [420, 500, 600, 700, 800, 900, 1000, 1200]) {
    const R = layout(W, H, SOLVER); applyDrawDims(R.all);
    let worst = null;
    for (const id of GROUP_ANCHORS) {
      const n = R.byId[id]; if (!n) continue;
      const b = badgeRect(n, R.SCL, BADGE_TEXT);
      if (!worst || b.y2 > worst.y2) worst = { id, ...b };
    }
    const off = worst.y2 - H;
    console.log(`  W=${String(W).padStart(4)} H=${String(H).padStart(4)}  lowest badge: ${worst.id.padEnd(7)} bottom=${worst.y2.toFixed(1).padStart(7)}  H=${H}  ${off > 0 ? 'OFF-CANVAS by ' + off.toFixed(1) : 'on canvas (' + (-off).toFixed(1) + 'px margin)'}`);
  }
}

// --- does the badge land on the NEIGHBOUR'S drawn sub-text ink? ------------
// drawNodeTag: label at n.y - 7*SCL, sub line i at n.y + 6*SCL + i*(FONT_SUB+2)
// drawHubNode: sub at n.y + 8*SCL.  drawStorageNode: n.y + h/2 + 12*SCL + i*(...)
console.log('\n=== badge vs neighbour DRAWN SUB-TEXT ink (not just AABB) ===');
for (const [W,H] of [[1950,1000],[1400,800],[1233,750]]) {
  const R = layout(W,H,SOLVER); applyDrawDims(R.all);
  console.log(`  -- W=${W} H=${H}`);
  for (const id of GROUP_ANCHORS) {
    const n = R.byId[id]; if (!n) continue;
    const b = badgeRect(n, R.SCL, BADGE_TEXT);
    for (const q of R.all) {
      if (q === n || !q.sub) continue;
      const lines = q.sub.split('\n');
      for (let i = 0; i < lines.length; i++) {
        let cy;
        if (q.shape === 'hub') { if (i > 0) continue; cy = q.y + 8 * R.SCL; }
        else if (q.shape === 'cylinder') { cy = q.y + q._boxH / 2 + 12 * R.SCL + i * (R.FONT_SUB + 2); }
        else if (q.id === 'engine') { if (i > 0) continue; cy = q.y + 12 * R.SCL; }
        else { cy = q.y + 6 * R.SCL + i * (R.FONT_SUB + 2); }
        const w = measureText(lines[i], R.FONT_SUB);
        const lr = { x1: q.x - w/2, x2: q.x + w/2, y1: cy - R.FONT_SUB*0.6, y2: cy + R.FONT_SUB*0.6 };
        const o = rectsOverlap(b, lr);
        if (o) console.log(`     ${id} badge OVERLAPS ${q.id} sub-line ${i} ("${lines[i]}")  ox=${o.ox.toFixed(1)} oy=${o.oy.toFixed(1)}`);
      }
    }
  }
}

// --- counterfactual: would a BOX-HUGGING badge (matching ringBoxPath, which
// drawRingCircle already uses for isBoxNode) be enough on its own? ----------
console.log('\n=== counterfactual A: badge top = n.y + halfH + 14 (hugs the ring, no measurement change) ===');
for (const [W,H] of [[1950,1000],[1400,800],[1233,750],[800,900]]) {
  const R = layout(W,H,SOLVER); applyDrawDims(R.all);
  const font = Math.round(9*R.SCL);
  const out = [];
  for (const id of GROUP_ANCHORS) {
    const n = R.byId[id]; if (!n) continue;
    const w = monoWidth(BADGE_TEXT, font);
    const b = { x1:n.x-w/2, x2:n.x+w/2, y1:n.y + (n._halfH||n.radius) + 14, y2:n.y + (n._halfH||n.radius) + 14 + font };
    const hits = R.all.filter(q => q !== n && rectsOverlap(b, boxOf(q))).map(q => q.id);
    out.push(`${id}:${hits.length ? hits.join('/') : 'clear'}`);
  }
  console.log(`  W=${W} H=${H}  ` + out.join('  '));
}

console.log('\n=== counterfactual B: box-hugging badge AND halfH grown by (font+14) below-centre-equivalent ===');
console.log('  (i.e. overlap pass reserves the strip: effective halfH := halfH + 14 + font)');
for (const [W,H] of [[1950,1000],[1400,800],[1233,750],[800,900]]) {
  const R = layout(W,H,SOLVER); applyDrawDims(R.all);
  const font = Math.round(9*R.SCL);
  console.log(`  W=${W} H=${H} font=${font}: strip needed below AABB = ${14+font}px; overlapPad currently = 14px  -> pad alone is ${14 >= 14+font ? 'enough' : 'SHORT by ' + font + 'px'}`);
}
