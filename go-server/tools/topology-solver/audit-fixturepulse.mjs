// Standalone replay of topology.js layoutAll() for the STORAGE zone only.
// Purpose: measure the REAL vertical/horizontal gaps between postgres,
// fixtures and wayback after the solver remap + overlap pass, so the
// drawFixturePulse() claim can be checked against geometry instead of guesses.
import fs from 'fs';
import path from 'path';

const OUT = path.resolve('output');
const LAYOUTS = {
  desktop: JSON.parse(fs.readFileSync(path.join(OUT, 'desktop-layout.json'), 'utf8')),
  tablet: JSON.parse(fs.readFileSync(path.join(OUT, 'tablet-layout.json'), 'utf8')),
  mobile: JSON.parse(fs.readFileSync(path.join(OUT, 'mobile-layout.json'), 'utf8'))
};

// Helvetica advance widths (units/1000) — a close stand-in for -apple-system.
const HELV = {' ':278,'!':278,'"':355,'#':556,'$':556,'%':889,'&':667,"'":191,'(':333,')':333,'*':389,'+':584,',':278,'-':333,'.':278,'/':278,'0':556,'1':556,'2':556,'3':556,'4':556,'5':556,'6':556,'7':556,'8':556,'9':556,':':278,';':278,'<':584,'=':584,'>':584,'?':556,'@':1015,'A':667,'B':667,'C':722,'D':722,'E':667,'F':611,'G':778,'H':722,'I':278,'J':500,'K':667,'L':556,'M':833,'N':722,'O':778,'P':667,'Q':778,'R':722,'S':667,'T':611,'U':722,'V':667,'W':944,'X':667,'Y':667,'Z':611,'[':278,'\\':278,']':278,'^':469,'_':556,'a':556,'b':556,'c':500,'d':556,'e':556,'f':278,'g':556,'h':556,'i':222,'j':222,'k':500,'l':222,'m':833,'n':556,'o':556,'p':556,'q':556,'r':333,'s':500,'t':278,'u':556,'v':500,'w':722,'x':500,'y':500,'z':500,'\u00b7':333};
const FUDGE = Number(process.env.FUDGE || 1.0); // scale factor sensitivity knob
function measure(text, size) {
  let u = 0;
  for (const ch of text) u += (HELV[ch] !== undefined ? HELV[ch] : 556);
  return (u / 1000) * size * FUDGE;
}

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub) {
  let labelW = measure(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const s = measure(l, fontSub); if (s > subW) subW = s; }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + subExtra); }
  return { w, h, halfW: w / 2, halfH: h / 2 };
}

function buildNodes() {
  const SOURCES = [
    { id:'root', label:'Root / TLD', sub:'IANA Root Zone\nTLD Registries', zone:'source' },
    { id:'rdap', label:'RDAP / WHOIS', sub:'Registration Data\nAccess Protocol', zone:'source' },
    { id:'ct', label:'CT / Subdomains', sub:'crt.sh \u00b7 Certspotter\nTransparency Logs', zone:'source' },
    { id:'cisa', label:'CISA / Threat', sub:'BOD 19-02\nIP Scanner Detection', zone:'source' },
    { id:'probes', label:'Probe Fleet', sub:'SMTP \u00b7 DANE \u00b7 TLS\nNmap \u00b7 testssl.sh', zone:'source' }
  ].map(s => ({ ...s, radius: 30, shape: 'rect' }));
  const HUB = { id:'hub', label:'DNS Resolvers', sub:'Signal Aggregation', zone:'hub', radius:44, shape:'hub' };
  const ENGINE = { id:'engine', label:'ICIE', sub:'Analysis Engine', zone:'engine', radius:54, shape:'rect' };
  const CONFIDENCE = [
    { id:'ietf', label:'IETF Metadata', sub:'RFC Status \u00b7 Errata\nDraft Tracker', zone:'confidence' },
    { id:'icae', label:'ICAE', sub:'Accuracy Audit', zone:'confidence' },
    { id:'icuae', label:'ICuAE', sub:'Currency Audit', zone:'confidence' },
    { id:'ede', label:'EDE', sub:'Epistemic\nDisclosure', zone:'confidence' }
  ].map(c => ({ ...c, radius: c.id==='ede'?48:(c.id==='ietf'?36:42), shape: c.id==='ietf'?'rect':'diamond' }));
  const STORAGE = [
    { id:'postgres', label:'PostgreSQL', sub:'Scan Results \u00b7 History\nDrift \u00b7 Analytics', zone:'storage' },
    { id:'fixtures', label:'Golden Fixtures', sub:'Known-Good Baselines\nRFC Compliance Seeds', zone:'storage' },
    { id:'wayback', label:'Internet Archive', sub:'Wayback Machine\nPermanent Record', zone:'storage' }
  ].map(s => ({ ...s, radius: s.id==='postgres'?36:(s.id==='wayback'?32:34), shape:'cylinder' }));
  const PROTOS = ['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'];
  const PLBL = { spf:'SPF', dkim:'DKIM', dmarc:'DMARC', dnssec:'DNSSEC', dane:'DANE', mtasts:'MTA-STS', tlsrpt:'TLS-RPT', bimi:'BIMI', caa:'CAA' };
  const PROTOCOLS = PROTOS.map(id => ({ id, label: PLBL[id], sub: null, zone:'protocol', radius:36, shape:'circle' }));
  const OUTPUTS = [
    { id:'reports', label:'Reports', sub:'Engineer \u00b7 Executive\nRecon \u00b7 Comparison', zone:'output' },
    { id:'jsonapi', label:'JSON API', sub:'Analysis \u00b7 Checksums\nSubdomains \u00b7 Health', zone:'output' },
    { id:'seo', label:'Schema.org', sub:'JSON-LD Structured Data\nGoogle \u00b7 Rich Results', zone:'output' },
    { id:'badges', label:'SVG Badges', sub:'Posture Indicators\nEmbeddable', zone:'output' }
  ].map(o => ({ ...o, radius: 36, shape: 'hexagon' }));
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

function layout(W, H, SHOW_OUTPUTS = false) {
  const N = buildNodes();
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const all = [...N.SOURCES, N.HUB, N.ENGINE, ...N.CONFIDENCE, ...N.STORAGE, ...N.PROTOCOLS, ...N.OUTPUTS];
  const meas = n => {
    const b = computeNodeBox(n.shape, n.radius, n.label, n.sub, SCL, FONT_LABEL, FONT_SUB);
    n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH;
  };
  all.forEach(meas);

  const titleSafe = Math.max(H * 0.07, 42);
  const legendSafe = H * 0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const gcx = W * 0.04 + globeR;
  const pipeStart = gcx + globeR + W * 0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W * 0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal * 0.01);
  const srcNeed = Math.max(...N.SOURCES.map(n => n._boxW), N.HUB._boxW) + 26;
  const confNeed = Math.max(...N.CONFIDENCE.map(n => n._boxW)) + 26;
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
    hub: { bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH*0.20, y2: titleSafe + usableH*0.70 } },
    engine: { bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH*0.30 } },
    confidence: { bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH*0.25, y2: titleSafe + usableH*0.75 } },
    storage: { bounds: { x1: col2L - c2w*0.3, x2: col2R + c2w*0.3, y1: titleSafe + usableH*0.68, y2: legendSafe } },
    protocol: { bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH*0.88 } },
    output: { bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe } }
  };

  // --- re-partition stacked zone bands by shelf-fit need (ba815061b) ---
  const byZone = {};
  all.forEach(nd => { const zk = nd.zone; (byZone[zk] = byZone[zk] || []).push(nd); });
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
  const repartLog = [];
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
    const bottom = zones[stack[stack.length-1]].bounds.y2;
    let needs = null, usedPad = 0;
    for (const p of [14, 8, 4, 0]) {
      const n = stack.map(zk => { const zb = zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2 - zb.x1, p); });
      const total = n.reduce((s,v)=>s+v,0) + p*(stack.length-1);
      if (total <= bottom - top) { needs = n; usedPad = p; break; }
    }
    if (!needs) { repartLog.push(`stack ${stack} DEFICIT but no pad fits — bands kept`); return; }
    const leftover = (bottom-top) - needs.reduce((s,v)=>s+v,0) - usedPad*(stack.length-1);
    const share = leftover / stack.length;
    let cursor = top;
    stack.forEach((zk, i) => {
      zones[zk].bounds.y1 = cursor;
      zones[zk].bounds.y2 = cursor + needs[i] + share;
      cursor = zones[zk].bounds.y2 + usedPad;
      grouped[zk] = true;
    });
    repartLog.push(`stack [${stack}] REPARTITIONED pad=${usedPad} share=${share.toFixed(1)}`);
  });

  // --- solver remap ---
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const L = LAYOUTS[profile];
  const solverData = L.nodeCenters;
  const ref = { w: L.canvas.width, h: L.canvas.height };
  const usableW = W - consoleReserve;
  all.forEach(nd => {
    const pos = solverData[nd.id];
    if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    const z = zones[nd.zone];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw*0.15), zpy = Math.min(20, zh*0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) nd.targetX = Math.max(z.bounds.x1+zpx, Math.min(z.bounds.x2-zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) nd.targetY = Math.max(z.bounds.y1+zpy, Math.min(z.bounds.y2-zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1+10, Math.min(globalBounds.x2-10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1+10, Math.min(globalBounds.y2-10, nd.targetY));
  });
  // protocol ellipse rescale (does not touch storage)
  const pxs = N.PROTOCOLS.map(p=>p.targetX), pys = N.PROTOCOLS.map(p=>p.targetY);
  const minPX = Math.min(...pxs), maxPX = Math.max(...pxs);
  const minPY = Math.min(...pys), maxPY = Math.max(...pys);
  const pz = zones.protocol.bounds;
  const padX = 52*SCL, padY = 44*SCL;
  const tx1 = pz.x1+padX, tx2 = pz.x2-padX, ty1 = pz.y1+padY, ty2 = pz.y2-padY;
  if (maxPX-minPX > 1 && tx2-tx1 > 40) N.PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX-minPX)/(maxPX-minPX))*(tx2-tx1); });
  if (maxPY-minPY > 1 && ty2-ty1 > 40) N.PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY-minPY)/(maxPY-minPY))*(ty2-ty1); });

  // --- overlap pass ---
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters = op + 1;
    let any = false;
    for (let i = 0; i < all.length; i++) for (let j = i+1; j < all.length; j++) {
      const na = all[i], nb = all[j];
      const ohw = na._halfW + nb._halfW + overlapPad;
      const ohh = na._halfH + nb._halfH + overlapPad;
      const odx = Math.abs(nb.targetX - na.targetX), ody = Math.abs(nb.targetY - na.targetY);
      if (odx < ohw && ody < ohh) {
        const overX = ohw - odx, overY = ohh - ody, pushStr = 0.7;
        if (overX < overY) { const sx = (nb.targetX >= na.targetX ? 1 : -1)*overX*pushStr; na.targetX -= sx; nb.targetX += sx; }
        else { const sy = (nb.targetY >= na.targetY ? 1 : -1)*overY*pushStr; na.targetY -= sy; nb.targetY += sy; }
        any = true;
      }
    }
    if (!any) break;
    all.forEach(nd => {
      const z = zones[nd.zone];
      if (z && z.bounds) {
        nd.targetX = Math.max(z.bounds.x1+nd._halfW, Math.min(z.bounds.x2-nd._halfW, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1+nd._halfH, Math.min(z.bounds.y2-nd._halfH, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1+10, Math.min(globalBounds.x2-10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1+10, Math.min(globalBounds.y2-10, nd.targetY));
    });
  }
  return { all, N, SCL, FONT_SUB, zones, iters, W, H, profile, repartLog, storageZone: zones.storage.bounds };
}

function report(W, H) {
  const r = layout(W, H);
  const get = id => r.all.find(n => n.id === id);
  const pg = get('postgres'), fx = get('fixtures'), wb = get('wayback');
  console.log(`\n===== W=${W} H=${H}  profile=${r.profile} SCL=${r.SCL.toFixed(4)} FONT_SUB=${r.FONT_SUB} overlapIters=${r.iters}`);
  r.repartLog.forEach(l => console.log('   repart:', l));
  console.log(`   storage zone y: ${r.storageZone.y1.toFixed(1)} .. ${r.storageZone.y2.toFixed(1)}  (h=${(r.storageZone.y2-r.storageZone.y1).toFixed(1)})  x: ${r.storageZone.x1.toFixed(1)}..${r.storageZone.x2.toFixed(1)}`);
  for (const n of [pg, fx, wb]) {
    console.log(`   ${n.id.padEnd(9)} x=${n.targetX.toFixed(2)} y=${n.targetY.toFixed(2)} halfW=${n._halfW.toFixed(2)} halfH=${n._halfH.toFixed(2)}  AABB y ${(n.targetY-n._halfH).toFixed(2)}..${(n.targetY+n._halfH).toFixed(2)}`);
  }
  // pulse geometry
  const pulseTop = fx.targetY - (fx._halfH + 10) - 1;
  const pulseBot = fx.targetY + (fx._halfH + 10) + 1;
  const pulseL = fx.targetX - (fx._halfW + 10) - 1;
  const pulseR = fx.targetX + (fx._halfW + 10) + 1;
  console.log(`   PULSE ink rect: x ${pulseL.toFixed(2)}..${pulseR.toFixed(2)}  y ${pulseTop.toFixed(2)}..${pulseBot.toFixed(2)}`);
  for (const n of [pg, wb]) {
    // cylinder silhouette ink: x = +/- halfW (+0.4 stroke); y top cap up to -halfH-7-0.4, bottom cap to +halfH+7+0.4
    const cl = n.targetX - n._halfW - 0.4, cr = n.targetX + n._halfW + 0.4;
    const ct = n.targetY - n._halfH - 7.4, cb = n.targetY + n._halfH + 7.4;
    const ox = Math.min(pulseR, cr) - Math.max(pulseL, cl);
    const oy = Math.min(pulseBot, cb) - Math.max(pulseTop, ct);
    const hit = ox > 0 && oy > 0;
    console.log(`   vs ${n.id.padEnd(9)} silhouette x ${cl.toFixed(2)}..${cr.toFixed(2)} y ${ct.toFixed(2)}..${cb.toFixed(2)}  -> ox=${ox.toFixed(2)} oy=${oy.toFixed(2)} ${hit ? 'INTERSECT' : 'clear'}`);
    // also raw AABB-vs-AABB gap
    const gapY = Math.abs(n.targetY - fx.targetY) - (n._halfH + fx._halfH);
    const gapX = Math.abs(n.targetX - fx.targetX) - (n._halfW + fx._halfW);
    console.log(`      AABB gap vs fixtures: dx-gap=${gapX.toFixed(2)}  dy-gap=${gapY.toFixed(2)}`);
    // sub-text ink of that neighbour (drawStorageNode line 1852)
    const subTop = n.targetY + n._halfH + 12*r.SCL - r.FONT_SUB*0.6;
    const subBot = n.targetY + n._halfH + 12*r.SCL + (2-1)*(r.FONT_SUB+2) + r.FONT_SUB*0.6;
    console.log(`      ${n.id} sub-text ink y ${subTop.toFixed(2)}..${subBot.toFixed(2)}  (fixtures AABB top=${(fx.targetY-fx._halfH).toFixed(2)})`);
  }
}

for (const [W, H] of [[1950, 900], [1950, 1100], [1233, 750], [1440, 900], [1100, 800], [800, 700], [1000, 800]]) report(W, H);
