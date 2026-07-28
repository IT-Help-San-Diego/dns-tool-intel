/* Independent replication of the SHIPPED client edge-label placement path
   (go-server/static/js/topology.js drawFlowEdge, lines 1499-1611) plus the
   full layoutAll() pipeline that feeds it. Written from source, not copied
   from any prior harness. Text widths use the solver's own estimateTextWidth
   (per-char table) since there is no canvas here; a width-sensitivity sweep
   is run at the end so no conclusion rests on the estimator being exact. */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEG = Math.PI / 180;

// ---- text width (mirror of src/nodeMetrics.ts estimateTextWidth) ----------
let WIDTH_FUDGE = 1.0;
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
  return total * fontSize * WIDTH_FUDGE;
}

// ---- node data (verbatim from topology.js 548-600) ------------------------
const mkSources = () => ([
  { id:'root',  label:'Root / TLD',     sub:'IANA Root Zone\nTLD Registries', zone:'source' },
  { id:'rdap',  label:'RDAP / WHOIS',   sub:'Registration Data\nAccess Protocol', zone:'source' },
  { id:'ct',    label:'CT / Subdomains',sub:'crt.sh · Certspotter\nTransparency Logs', zone:'source' },
  { id:'cisa',  label:'CISA / Threat',  sub:'BOD 19-02\nIP Scanner Detection', zone:'source' },
  { id:'probes',label:'Probe Fleet',    sub:'SMTP · DANE · TLS\nNmap · testssl.sh', zone:'source' },
]);
const mkHub = () => ({ id:'hub', label:'DNS Resolvers', sub:'Signal Aggregation', zone:'hub', radius:44, shape:'hub' });
const mkEngine = () => ({ id:'engine', label:'ICIE', sub:'Analysis Engine', zone:'engine', radius:54, shape:'rect' });
const mkConfidence = () => ([
  { id:'ietf',  label:'IETF Metadata', sub:'RFC Status · Errata\nDraft Tracker', zone:'confidence' },
  { id:'icae',  label:'ICAE',  sub:'Accuracy Audit', zone:'confidence' },
  { id:'icuae', label:'ICuAE', sub:'Currency Audit', zone:'confidence' },
  { id:'ede',   label:'EDE',   sub:'Epistemic\nDisclosure', zone:'confidence' },
]);
const mkStorage = () => ([
  { id:'postgres', label:'PostgreSQL',      sub:'Scan Results · History\nDrift · Analytics', zone:'storage' },
  { id:'fixtures', label:'Golden Fixtures', sub:'Known-Good Baselines\nRFC Compliance Seeds', zone:'storage' },
  { id:'wayback',  label:'Internet Archive',sub:'Wayback Machine\nPermanent Record', zone:'storage' },
]);
const mkProtocols = () => ([
  { id:'spf', label:'SPF' }, { id:'dkim', label:'DKIM' }, { id:'dmarc', label:'DMARC' },
  { id:'dnssec', label:'DNSSEC' }, { id:'dane', label:'DANE' }, { id:'mtasts', label:'MTA-STS' },
  { id:'tlsrpt', label:'TLS-RPT' }, { id:'bimi', label:'BIMI' }, { id:'caa', label:'CAA' },
]);
const mkOutputs = () => ([
  { id:'reports', label:'Reports',    sub:'Engineer · Executive\nRecon · Comparison', zone:'output' },
  { id:'jsonapi', label:'JSON API',   sub:'Analysis · Checksums\nSubdomains · Health', zone:'output' },
  { id:'seo',     label:'Schema.org', sub:'JSON-LD Structured Data\nGoogle · Rich Results', zone:'output' },
  { id:'badges',  label:'SVG Badges', sub:'Posture Indicators\nEmbeddable', zone:'output' },
]);

const PROTO_EDGES = [
  { from:'dmarc', to:'spf',    type:'hard', label:'alignment',     labelT:0.45 },
  { from:'dmarc', to:'dkim',   type:'hard', label:'alignment',     labelT:0.45 },
  { from:'dane',  to:'dnssec', type:'hard', label:'requires',      labelT:0.35 },
  { from:'bimi',  to:'dmarc',  type:'hard', label:'p=quarantine+', labelT:0.5 },
  { from:'tlsrpt',to:'mtasts', type:'soft', label:'reports',       labelT:0.5 },
  { from:'tlsrpt',to:'dane',   type:'soft', label:'reports',       labelT:0.4 },
  { from:'caa',   to:'dnssec', type:'soft', label:'strengthens',   labelT:0.5 },
];

const LAYOUTS = {
  desktop: JSON.parse(fs.readFileSync(path.join(HERE,'output/desktop-layout.json'),'utf8')),
  tablet:  JSON.parse(fs.readFileSync(path.join(HERE,'output/tablet-layout.json'),'utf8')),
  mobile:  JSON.parse(fs.readFileSync(path.join(HERE,'output/mobile-layout.json'),'utf8')),
};

const SHOW_OUTPUTS = false;   // topology.js:2117

// ---- computeNodeBox (topology.js:677-718) ---------------------------------
function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub) {
  const labelW = estimateTextWidth(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n'); subLineCount = lines.length;
    for (const l of lines) { const sw = estimateTextWidth(l, fontSub); if (sw > subW) subW = sw; }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle')        { w = Math.max(radius*2, contentW);   h = radius*2; }
  else if (shape === 'diamond')  { w = Math.max(radius*1.7, contentW+8); h = radius*1.7 + subExtra; }
  else if (shape === 'hexagon')  { w = Math.max(radius*2, contentW);   h = radius*2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius*2.4, contentW); h = radius*1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.4, 40*scale); }
  else { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.3, 40*scale + (subLineCount>1 ? (subLineCount-1)*(fontSub+2) : 0)); }
  return { w, h, halfW: w/2, halfH: h/2 };
}

function buildScene(W, H) {
  // computeScaling (topology.js:668-675)
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13*SCL)));
  const FONT_SUB   = Math.round(Math.max(8,  Math.min(12, 10*SCL)));

  const SOURCES = mkSources(), HUB = mkHub(), ENGINE = mkEngine();
  const CONFIDENCE = mkConfidence(), STORAGE = mkStorage();
  const PROTOCOLS = mkProtocols(), OUTPUTS = mkOutputs();

  SOURCES.forEach(s => { s.radius = 30; s.shape = 'rect'; });
  CONFIDENCE.forEach(c => { c.radius = c.id==='ede'?48 : c.id==='ietf'?36 : 42; c.shape = c.id==='ietf'?'rect':'diamond'; });
  STORAGE.forEach(s => { s.radius = s.id==='postgres'?36 : s.id==='wayback'?32 : 34; s.shape='cylinder'; });
  PROTOCOLS.forEach(p => { p.radius = 36; p.shape='circle'; p.zone='protocol'; });
  OUTPUTS.forEach(o => { o.radius = 36; o.shape='hexagon'; });

  const all = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  const byId = {}; all.forEach(n => byId[n.id] = n);
  const measure = n => { const b = computeNodeBox(n.shape, n.radius, n.label, n.sub||null, SCL, FONT_LABEL, FONT_SUB);
                         n._boxW=b.w; n._boxH=b.h; n._halfW=b.halfW; n._halfH=b.halfH; };

  const titleSafe = Math.max(H*0.07, 42);
  const legendSafe = H*0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W*0.13*SCL, H*0.25*SCL, 180);
  const globe = { R: globeR, cx: W*0.04 + globeR, cy: titleSafe + usableH*0.42 };

  const pipeStart = globe.cx + globeR + W*0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W*0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal*0.01);

  SOURCES.forEach(measure); measure(HUB); CONFIDENCE.forEach(measure);
  const srcNeed = Math.max(...SOURCES.map(n=>n._boxW), HUB._boxW) + 26;
  const confNeed = Math.max(...CONFIDENCE.map(n=>n._boxW)) + 26;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal*0.13), pipeTotal*0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal*0.14), pipeTotal*0.24);
  const c4w = SHOW_OUTPUTS ? pipeTotal*0.16 : 0;
  const c3w = pipeTotal - c1w - c2w - c4w - colGap*(SHOW_OUTPUTS?3:2);
  const col1L = pipeStart, col1R = col1L + c1w;
  const col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w;
  const col4L = col3R + colGap, col4R = pipeEnd;

  const srcCx = (col1L+col1R)/2;
  const srcSpacing = usableH/(SOURCES.length+1);
  SOURCES.forEach((s,i)=>{ s.targetX = srcCx; s.targetY = titleSafe + (i+1)*srcSpacing; });
  HUB.targetX = srcCx; HUB.targetY = globe.cy;

  const procCx = (col2L+col2R)/2;
  ENGINE.targetX = procCx; ENGINE.targetY = titleSafe + usableH*0.15;
  const confSpread = Math.max(40, (col2R-col2L)*0.32);
  const confY = titleSafe + usableH*0.42;
  CONFIDENCE[0].targetX = procCx;                    CONFIDENCE[0].targetY = confY - usableH*0.06;
  CONFIDENCE[1].targetX = procCx - confSpread*0.5;   CONFIDENCE[1].targetY = confY + usableH*0.06;
  CONFIDENCE[2].targetX = procCx + confSpread*0.5;   CONFIDENCE[2].targetY = confY + usableH*0.06;
  CONFIDENCE[3].targetX = procCx;                    CONFIDENCE[3].targetY = confY + usableH*0.18;

  const storeY = titleSafe + usableH*0.78;
  const storeSpread = Math.max(confSpread*0.8, 60);
  STORAGE[0].targetX = procCx;               STORAGE[0].targetY = storeY;
  STORAGE[1].targetX = procCx - storeSpread; STORAGE[1].targetY = storeY + usableH*0.10;
  STORAGE[2].targetX = procCx + storeSpread; STORAGE[2].targetY = storeY + usableH*0.10;

  const protoCx = (col3L+col3R)/2, protoCy = titleSafe + usableH*0.42;
  const protoRx = (col3R-col3L)*0.38, protoRy = usableH*0.28;
  const angleMap = [-130,-90,-50,-10,30,70,110,150,190];
  PROTOCOLS.forEach((p,i)=>{ const a=angleMap[i]*DEG; p.targetX = protoCx + protoRx*Math.cos(a); p.targetY = protoCy + protoRy*Math.sin(a); });

  const outCx = (col4L+col4R)/2, outSpacing = usableH/(OUTPUTS.length+1);
  OUTPUTS.forEach((o,i)=>{ o.targetX = outCx; o.targetY = titleSafe + (i+1)*outSpacing; });

  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  const zones = {
    source:     { bounds:{ x1:col1L, x2:col1R, y1:titleSafe, y2:legendSafe } },
    hub:        { bounds:{ x1:col1L, x2:col1R, y1:titleSafe+usableH*0.20, y2:titleSafe+usableH*0.70 } },
    engine:     { bounds:{ x1:col2L, x2:col2R, y1:titleSafe, y2:titleSafe+usableH*0.30 } },
    confidence: { bounds:{ x1:col2L, x2:col2R, y1:titleSafe+usableH*0.25, y2:titleSafe+usableH*0.75 } },
    storage:    { bounds:{ x1:col2L-c2w*0.3, x2:col2R+c2w*0.3, y1:titleSafe+usableH*0.68, y2:legendSafe } },
    protocol:   { bounds:{ x1:col3L, x2:col3R, y1:titleSafe, y2:titleSafe+usableH*0.88 } },
    output:     { bounds:{ x1:col4L, x2:col4R, y1:titleSafe, y2:legendSafe } },
  };

  all.forEach(measure);

  // ---- shelf re-partition IIFE (topology.js:1069-1151) --------------------
  (function() {
    const byZone = {};
    all.forEach(nd => { const zk = nd.zone || nd.id; (byZone[zk] = byZone[zk]||[]).push(nd); });
    function shelfNeed(members, zw, pad) {
      let rowW=0, rowH=0, needH=0, rows=0;
      members.forEach(nd => {
        const w = (nd._halfW||nd.radius)*2, h = (nd._halfH||nd.radius)*2;
        if (rowW>0 && rowW+pad+w>zw) { needH+=rowH; rows++; rowW=0; rowH=0; }
        rowW += rowW>0 ? pad+w : w;
        if (h>rowH) rowH=h;
      });
      needH+=rowH; rows++;
      return needH + pad*(rows-1);
    }
    const keys = Object.keys(byZone).filter(zk => zones[zk] && zones[zk].bounds).sort();
    const grouped = {};
    keys.forEach(ka => {
      if (grouped[ka]) return;
      const a = zones[ka].bounds; const stack = [ka];
      keys.forEach(kb => {
        if (kb===ka || grouped[kb]) return;
        const b = zones[kb].bounds;
        const xOver = Math.min(a.x2,b.x2) - Math.max(a.x1,b.x1);
        const minW = Math.min(a.x2-a.x1, b.x2-b.x1);
        const contains = (a.y1<=b.y1 && a.y2>=b.y2) || (b.y1<=a.y1 && b.y2>=a.y2);
        if (xOver > minW*0.6 && !contains) stack.push(kb);
      });
      if (stack.length<2) return;
      stack.sort((x,y)=>zones[x].bounds.y1 - zones[y].bounds.y1);
      const anyDeficit = stack.some(zk => { const zb=zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2-zb.x1, 0) > zb.y2-zb.y1; });
      if (!anyDeficit) return;
      const top = zones[stack[0]].bounds.y1;
      const bottom = zones[stack[stack.length-1]].bounds.y2;
      let needs=null, usedPad=0;
      for (const p of [14,8,4,0]) {
        const n = stack.map(zk => { const zb=zones[zk].bounds; return shelfNeed(byZone[zk], zb.x2-zb.x1, p); });
        const total = n.reduce((s,v)=>s+v,0) + p*(stack.length-1);
        if (total <= bottom-top) { needs=n; usedPad=p; break; }
      }
      if (!needs) return;
      const leftover = (bottom-top) - needs.reduce((s,v)=>s+v,0) - usedPad*(stack.length-1);
      const share = leftover/stack.length;
      let cursor = top;
      stack.forEach((zk,i)=>{ zones[zk].bounds.y1 = cursor; zones[zk].bounds.y2 = cursor + needs[i] + share; cursor = zones[zk].bounds.y2 + usedPad; grouped[zk]=true; });
    });
  })();

  // ---- solver remap (topology.js:1153-1229) --------------------------------
  const solverProfile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const layout = LAYOUTS[solverProfile];
  const solverData = layout.nodeCenters;
  const ref = { w: layout.canvas.width, h: layout.canvas.height };
  const usableW = W - consoleReserve;
  all.forEach(nd => {
    const pos = solverData[nd.id]; if (!pos) return;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    const z = zones[nd.zone || nd.id];
    if (z && z.bounds) {
      const zw = z.bounds.x2-z.bounds.x1, zh = z.bounds.y2-z.bounds.y1;
      const zpx = Math.min(30, zw*0.15), zpy = Math.min(20, zh*0.15);
      if (z.bounds.x1+zpx < z.bounds.x2-zpx) nd.targetX = Math.max(z.bounds.x1+zpx, Math.min(z.bounds.x2-zpx, nd.targetX));
      if (z.bounds.y1+zpy < z.bounds.y2-zpy) nd.targetY = Math.max(z.bounds.y1+zpy, Math.min(z.bounds.y2-zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1+10, Math.min(globalBounds.x2-10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1+10, Math.min(globalBounds.y2-10, nd.targetY));
  });
  {
    const pxs = PROTOCOLS.map(p=>p.targetX), pys = PROTOCOLS.map(p=>p.targetY);
    const minPX=Math.min(...pxs), maxPX=Math.max(...pxs), minPY=Math.min(...pys), maxPY=Math.max(...pys);
    const pz = zones.protocol.bounds;
    const padX = 52*SCL, padY = 44*SCL;
    const tx1 = pz.x1+padX, tx2 = pz.x2-padX, ty1 = pz.y1+padY, ty2 = pz.y2-padY;
    if (maxPX-minPX > 1 && tx2-tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX-minPX)/(maxPX-minPX))*(tx2-tx1); });
    if (maxPY-minPY > 1 && ty2-ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY-minPY)/(maxPY-minPY))*(ty2-ty1); });
  }

  // ---- overlap pass (topology.js:1234-1272) --------------------------------
  const overlapPad = 14;
  let opUsed = 0;
  for (let op=0; op<40; op++) {
    opUsed = op+1;
    let any = false;
    for (let i=0;i<all.length;i++) for (let j=i+1;j<all.length;j++) {
      const na=all[i], nb=all[j];
      const ohw = (na._halfW||na.radius)+(nb._halfW||nb.radius)+overlapPad;
      const ohh = (na._halfH||na.radius)+(nb._halfH||nb.radius)+overlapPad;
      const odx = Math.abs(nb.targetX-na.targetX), ody = Math.abs(nb.targetY-na.targetY);
      if (odx<ohw && ody<ohh) {
        const overX = ohw-odx, overY = ohh-ody, pushStr = 0.7;
        if (overX<overY) { const sx=(nb.targetX>=na.targetX?1:-1)*overX*pushStr; na.targetX-=sx; nb.targetX+=sx; }
        else { const sy=(nb.targetY>=na.targetY?1:-1)*overY*pushStr; na.targetY-=sy; nb.targetY+=sy; }
        any = true;
      }
    }
    if (!any) break;
    all.forEach(nd => {
      const z = zones[nd.zone||nd.id];
      if (z && z.bounds) {
        const zHw = nd._halfW||nd.radius, zHh = nd._halfH||nd.radius;
        nd.targetX = Math.max(z.bounds.x1+zHw, Math.min(z.bounds.x2-zHw, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1+zHh, Math.min(z.bounds.y2-zHh, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1+10, Math.min(globalBounds.x2-10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1+10, Math.min(globalBounds.y2-10, nd.targetY));
    });
  }
  all.forEach(nd => { nd.x = nd.targetX; nd.y = nd.targetY; });

  return { W,H,SCL,FONT_SUB,all,byId,PROTOCOLS,OUTPUTS,zones,globalBounds,solverProfile,opUsed,consoleReserve };
}

// ---- findEdgeCurveOffset (topology.js:1398-1424) ---------------------------
function findEdgeCurveOffset(S, from, to, edgeType) {
  if (edgeType === 'flow') return null;
  const isProto = id => S.PROTOCOLS.some(p=>p.id===id);
  if (!isProto(from.id) || !isProto(to.id)) return null;
  const mx=(from.x+to.x)/2, my=(from.y+to.y)/2;
  const edx=to.x-from.x, edy=to.y-from.y;
  const elen = Math.sqrt(edx*edx+edy*edy)||1;
  const perpX=-edy/elen, perpY=edx/elen;
  let bestOffset=0, closest=Infinity;
  for (const pn of S.PROTOCOLS) {
    if (pn.id===from.id||pn.id===to.id) continue;
    const dx2=pn.x-mx, dy2=pn.y-my;
    const d=Math.sqrt(dx2*dx2+dy2*dy2);
    if (d < pn.radius+50 && d < closest) {
      closest=d;
      const side = dx2*perpX+dy2*perpY;
      bestOffset = (side>0?-1:1)*Math.max(40, pn.radius+20);
    }
  }
  if (bestOffset===0) return null;
  return { cx: mx+perpX*bestOffset, cy: my+perpY*bestOffset };
}

// ---- penetration of a pill rect into a node's drawn shape -----------------
function pillNodePenetration(lx, ly, pw, ph, n) {
  if (n.shape === 'circle') {
    // closest point on pill rect to circle centre
    const cx = Math.max(lx-pw/2, Math.min(lx+pw/2, n.x));
    const cy = Math.max(ly-ph/2, Math.min(ly+ph/2, n.y));
    const d = Math.hypot(cx-n.x, cy-n.y);
    return n.radius - d;      // >0 => pill ink is inside the circle
  }
  const hw = n._halfW||n.radius, hh = n._halfH||n.radius;
  const ox = Math.min(lx+pw/2, n.x+hw) - Math.max(lx-pw/2, n.x-hw);
  const oy = Math.min(ly+ph/2, n.y+hh) - Math.max(ly-ph/2, n.y-hh);
  if (ox<=0 || oy<=0) return -Math.max(-ox,-oy);
  return Math.min(ox, oy);
}

function worstNodeHit(S, lx, ly, pw, ph) {
  let best = { pen: -Infinity, id: null };
  for (const n of S.all) {
    if (n.zone === 'output' && !SHOW_OUTPUTS) continue;   // hidden, not drawn
    const p = pillNodePenetration(lx, ly, pw, ph, n);
    if (p > best.pen) best = { pen: p, id: n.id };
  }
  return best;
}

// ---- replicate drawFlowEdge's label placement, stage by stage --------------
function runLabels(S) {
  const placed = [];
  const rows = [];
  const HUD_ACTIVE = false;
  for (const e of PROTO_EDGES) {
    const from = S.byId[e.from], to = S.byId[e.to];
    const curve = findEdgeCurveOffset(S, from, to, e.type);
    const t = e.labelT || 0.5;
    let lx, ly;
    if (curve) {
      lx = (1-t)*(1-t)*from.x + 2*(1-t)*t*curve.cx + t*t*to.x;
      ly = (1-t)*(1-t)*from.y + 2*(1-t)*t*curve.cy + t*t*to.y;
    } else {
      lx = from.x + (to.x-from.x)*t;
      ly = from.y + (to.y-from.y)*t;
    }
    ly -= 8*S.SCL;
    const anchor = { x:lx, y:ly };

    // STAGE 1: node avoidance, single ordered pass, POINT-based (1511-1535)
    for (const nn of S.all) {
      const nhw = (nn._halfW || nn._boxW/2 || nn.radius) + 12;
      const nhh = (nn._halfH || nn._boxH/2 || nn.radius) + 12;
      if (nn.shape === 'circle') {
        const ldx = lx-nn.x, ldy = ly-nn.y;
        const ldist = Math.hypot(ldx, ldy);
        if (ldist < nn.radius+24 && ldist > 0.1) {
          const lnorm = (nn.radius+28)/ldist;
          lx = nn.x + ldx*lnorm; ly = nn.y + ldy*lnorm;
        }
      } else {
        const ndx = lx-nn.x, ndy = ly-nn.y;
        if (Math.abs(ndx)<nhw && Math.abs(ndy)<nhh) {
          if (Math.abs(ndx)/nhw > Math.abs(ndy)/nhh) lx = nn.x + (ndx>=0?1:-1)*(nhw+6);
          else ly = nn.y + (ndy>=0?1:-1)*(nhh+6);
        }
      }
    }
    const afterNodes = { x:lx, y:ly };

    const edgeFontSize = Math.max(8, S.FONT_SUB-1);
    const tw = estimateTextWidth(e.label, edgeFontSize);
    const pw = tw + 10*S.SCL;
    const ph = edgeFontSize + 8*S.SCL;
    const hitAfterNodes = worstNodeHit(S, lx, ly, pw, ph);

    // STAGE 2: label-label separation (1543-1559)
    for (let pass=0; pass<3; pass++) {
      let moved = false;
      for (const pl of placed) {
        const olx = Math.min(lx+pw/2, pl.x+pl.w/2) - Math.max(lx-pw/2, pl.x-pl.w/2);
        const oly = Math.min(ly+ph/2, pl.y+pl.h/2) - Math.max(ly-ph/2, pl.y-pl.h/2);
        if (olx>0 && oly>0) {
          if (olx<oly) lx += (lx>=pl.x?1:-1)*(olx+6);
          else         ly += (ly>=pl.y?1:-1)*(oly+6);
          moved = true;
        }
      }
      if (!moved) break;
    }
    const afterSep = { x:lx, y:ly };
    const hitAfterSep = worstNodeHit(S, lx, ly, pw, ph);

    // STAGE 3: viewport clamp (1561-1562)
    ly = Math.max(20, Math.min(S.H-20, ly));
    lx = Math.max(30, Math.min(S.W-30, lx));
    const final = { x:lx, y:ly };
    const hitFinal = worstNodeHit(S, lx, ly, pw, ph);

    placed.push({ x:lx, y:ly, w:pw, h:ph });
    rows.push({ label:e.label, edge:e.from+'->'+e.to, anchor, afterNodes, afterSep, final,
                pw:+pw.toFixed(1), ph:+ph.toFixed(1),
                hitAfterNodes, hitAfterSep, hitFinal,
                sepMoved: Math.hypot(afterSep.x-afterNodes.x, afterSep.y-afterNodes.y),
                clampMoved: Math.hypot(final.x-afterSep.x, final.y-afterSep.y) });
  }
  return rows;
}

function report(W,H) {
  const S = buildScene(W,H);
  const rows = runLabels(S);
  console.log('\n===== W=%d H=%d  SCL=%s FONT_SUB=%d profile=%s consoleReserve=%d overlapIters=%d fudge=%s',
    W,H,S.SCL.toFixed(3),S.FONT_SUB,S.solverProfile,S.consoleReserve,S.opUsed,WIDTH_FUDGE.toFixed(2));
  const f = n => (n>=0?' ':'') + n.toFixed(1);
  for (const r of rows) {
    console.log(
      '  %s (%s) pill %sx%s\n' +
      '     anchor (%s,%s) -> afterNodes (%s,%s) -> afterSep (%s,%s) -> final (%s,%s)\n' +
      '     worst node ink-penetration: afterNodes %s [%s]  afterSep %s [%s]  FINAL %s [%s]   sepMoved %s clampMoved %s',
      r.label.padEnd(14), r.edge, r.pw, r.ph,
      f(r.anchor.x), f(r.anchor.y), f(r.afterNodes.x), f(r.afterNodes.y),
      f(r.afterSep.x), f(r.afterSep.y), f(r.final.x), f(r.final.y),
      f(r.hitAfterNodes.pen), r.hitAfterNodes.id,
      f(r.hitAfterSep.pen), r.hitAfterSep.id,
      f(r.hitFinal.pen), r.hitFinal.id,
      f(r.sepMoved), f(r.clampMoved));
  }
  const worsened = rows.filter(r => r.hitFinal.pen > r.hitAfterNodes.pen + 0.01);
  const badAfterStage1 = rows.filter(r => r.hitAfterNodes.pen > 0);
  const badFinal = rows.filter(r => r.hitFinal.pen > 0);
  console.log('  SUMMARY: overlapping-a-node after stage1 = %d/%d ; after all stages = %d/%d ; made worse by stage2/3 = %d',
    badAfterStage1.length, rows.length, badFinal.length, rows.length, worsened.length);
  return { rows, badAfterStage1: badAfterStage1.length, badFinal: badFinal.length, worsened: worsened.length, n: rows.length };
}

const sizes = [[1950,900],[1950,1050],[1400,800],[1233,750],[800,700],[1000,800],[1600,900]];
const agg = [];
for (const [w,h] of sizes) agg.push([w,h,report(w,h)]);

console.log('\n\n===== TEXT-WIDTH SENSITIVITY SWEEP (does the conclusion depend on the estimator?) =====');
for (const fudge of [0.85, 1.0, 1.15]) {
  WIDTH_FUDGE = fudge;
  let s1=0, sF=0, worse=0, tot=0;
  for (const [w,h] of sizes) {
    const S = buildScene(w,h);
    const rows = runLabels(S);
    tot += rows.length;
    s1 += rows.filter(r=>r.hitAfterNodes.pen>0).length;
    sF += rows.filter(r=>r.hitFinal.pen>0).length;
    worse += rows.filter(r=>r.hitFinal.pen > r.hitAfterNodes.pen+0.01).length;
  }
  console.log('  fudge %s : already-overlapping after stage1 %d/%d ; final %d/%d ; worsened by stage2/3 %d',
    fudge.toFixed(2), s1, tot, sF, tot, worse);
}
WIDTH_FUDGE = 1.0;
