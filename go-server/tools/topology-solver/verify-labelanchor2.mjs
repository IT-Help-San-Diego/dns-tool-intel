// Stage-by-stage attribution + proposed-fix trial for the edge-label placement
// in go-server/static/js/topology.js lines 1499-1611.
// Layout comes from the verbatim shipped slabs (see verify-labelanchor.mjs).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SLAB = (n) => readFileSync(join(here, 'slabs', n), 'utf8');
const LAYOUTS = {
  desktop: JSON.parse(readFileSync(join(here, 'output/desktop-layout.json'), 'utf8')),
  tablet:  JSON.parse(readFileSync(join(here, 'output/tablet-layout.json'), 'utf8')),
  mobile:  JSON.parse(readFileSync(join(here, 'output/mobile-layout.json'), 'utf8')),
};

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

const harness = new Function('__W','__H','__LAYOUTS','__estimate', `
'use strict';
let SOLVER_LAYOUTS = __LAYOUTS, SOLVER_ACTIVE = false;
let W = __W, H = __H;
let SCL = 1, FONT_LABEL = 13, FONT_SUB = 10, FONT_TAG = 13, MIN_SPACING = 8;
let COLORS = { email:'#4fc3f7',transport:'#81c784',policy:'#ffb74d',brand:'#ce93d8',
  source:'#5c6bc0',intel:'#78909c',engine:'#e0e0e0',storage:'#ff8a65',output:'#90caf9' };
let DEG = Math.PI/180;
let allLayoutNodes = [];
let globe = {R:0,cx:0,cy:0}, convergePt = {x:0,y:0};
let SHOW_OUTPUTS = false, HUD_ACTIVE = false, debugBounds = false;
function forceDirectedLayout(){ throw new Error('DEAD CODE REACHED'); }
let ctx = { font:'10px x',
  measureText(t){ let m=/^(?:bold )?([\\d.]+)px/.exec(this.font); return {width:__estimate(t, m?parseFloat(m[1]):10)}; },
  save(){},restore(){},beginPath(){},moveTo(){},lineTo(){},arc(){},closePath(){},
  fill(){},stroke(){},fillText(){},setLineDash(){},
  createLinearGradient(){return {addColorStop(){}};} };
${SLAB('slabA.js')}
${SLAB('slabB.js')}
${SLAB('slabC.js')}
let PROTO_IDS = {}; PROTOCOLS.forEach(p => PROTO_IDS[p.id]=true);
function findEdgeCurveOffset(from,to,edgeType){
  if (edgeType==='flow') return null;
  if (!PROTO_IDS[from.id]||!PROTO_IDS[to.id]) return null;
  let mx=(from.x+to.x)/2,my=(from.y+to.y)/2,edx=to.x-from.x,edy=to.y-from.y;
  let elen=Math.sqrt(edx*edx+edy*edy)||1,perpX=-edy/elen,perpY=edx/elen;
  let bestOffset=0,closestDist=Infinity;
  for (let pi=0;pi<PROTOCOLS.length;pi++){ let pn=PROTOCOLS[pi];
    if(pn.id===from.id||pn.id===to.id) continue;
    let dx2=pn.x-mx,dy2=pn.y-my,d=Math.sqrt(dx2*dx2+dy2*dy2);
    if(d<pn.radius+50&&d<closestDist){closestDist=d;let side=dx2*perpX+dy2*perpY;
      bestOffset=(side>0?-1:1)*Math.max(40,pn.radius+20);}}
  if(bestOffset===0) return null;
  return {cx:mx+perpX*bestOffset,cy:my+perpY*bestOffset};
}
return { allNodes, PROTOCOLS, PROTO_EDGES, allLayoutNodes:(function(){layoutAll();return allLayoutNodes;})(),
         findEdgeCurveOffset, SCL, FONT_SUB, W, H, SOLVER_ACTIVE };
`);

function rectPtDist(cx, cy, rx, ry, hw, hh) {
  return Math.hypot(Math.max(Math.abs(cx-rx)-hw,0), Math.max(Math.abs(cy-ry)-hh,0));
}
function penetration(pl, nn) {
  if (nn.shape === 'circle') {
    const d = rectPtDist(nn.x, nn.y, pl.x, pl.y, pl.w/2, pl.h/2);
    return d < nn.radius ? nn.radius - d : 0;
  }
  const ox = Math.min(pl.x+pl.w/2, nn.x+nn._halfW) - Math.max(pl.x-pl.w/2, nn.x-nn._halfW);
  const oy = Math.min(pl.y+pl.h/2, nn.y+nn._halfH) - Math.max(pl.y-pl.h/2, nn.y-nn._halfH);
  return (ox > 0 && oy > 0) ? Math.min(ox, oy) : 0;
}

// ---------- placement, instrumented; mode 'shipped' | 'fixed' ----------
function place(api, e, placed, mode) {
  const { SCL, FONT_SUB, W, H, allLayoutNodes } = api;
  const from = api.allNodes[e.from], to = api.allNodes[e.to];
  const curve = api.findEdgeCurveOffset(from, to, e.type);
  const t = e.labelT || 0.5;
  let lx, ly;
  if (curve) {
    lx = (1-t)*(1-t)*from.x + 2*(1-t)*t*curve.cx + t*t*to.x;
    ly = (1-t)*(1-t)*from.y + 2*(1-t)*t*curve.cy + t*t*to.y;
  } else { lx = from.x + (to.x-from.x)*t; ly = from.y + (to.y-from.y)*t; }
  ly -= 8*SCL;
  const anchor = { x: lx, y: ly };

  const edgeFontSize = Math.max(8, FONT_SUB - 1);
  const pw = estimateTextWidth(e.label, edgeFontSize) + 10*SCL;
  const ph = edgeFontSize + 8*SCL;

  const fired = [];
  const OUTER = mode === 'shipped+iterate' ? 12 : 1;
  for (let pass = 0; pass < OUTER; pass++) {
  let movedAny = false;
  for (let nri = 0; nri < allLayoutNodes.length; nri++) {
    const nn = allLayoutNodes[nri];
    const nhw = (nn._halfW || nn._boxW/2 || nn.radius) + 12;
    const nhh = (nn._halfH || nn._boxH/2 || nn.radius) + 12;
    if (nn.shape === 'circle') {
      if (mode === 'shipped' || mode === 'shipped+iterate') {
        const ldx = lx-nn.x, ldy = ly-nn.y, ldist = Math.hypot(ldx, ldy);
        if (ldist < nn.radius + 24 && ldist > 0.1) {
          const k = (nn.radius + 28)/ldist; lx = nn.x + ldx*k; ly = nn.y + ldy*k; fired.push(nn.id); movedAny = true;
        }
      } else {
        const trigPad = mode === 'fixA' ? 6 : mode === 'fixB' ? 24 : 0;
        const d = rectPtDist(nn.x, nn.y, lx, ly, pw/2, ph/2);
        if (d < nn.radius + trigPad) {
          const ldx = lx-nn.x, ldy = ly-nn.y; let ldist = Math.hypot(ldx, ldy);
          if (ldist < 0.1) { ldist = 1; }
          const k = (nn.radius + Math.hypot(pw, ph)/2 + 6)/ldist;
          lx = nn.x + (ldx||1)*k; ly = nn.y + ldy*k; fired.push(nn.id);
        }
      }
    } else {
      const ndx = lx-nn.x, ndy = ly-nn.y;
      if (mode === 'shipped') {
        if (Math.abs(ndx) < nhw && Math.abs(ndy) < nhh) {
          if (Math.abs(ndx)/nhw > Math.abs(ndy)/nhh) lx = nn.x + (ndx>=0?1:-1)*(nhw+6);
          else ly = nn.y + (ndy>=0?1:-1)*(nhh+6);
          fired.push(nn.id); movedAny = true;
        }
      } else {
        if (Math.abs(ndx) < nhw + pw/2 && Math.abs(ndy) < nhh + ph/2) {
          if (Math.abs(ndx)/(nhw+pw/2) > Math.abs(ndy)/(nhh+ph/2)) lx = nn.x + (ndx>=0?1:-1)*(nhw+pw/2+6);
          else ly = nn.y + (ndy>=0?1:-1)*(nhh+ph/2+6);
          fired.push(nn.id);
        }
      }
    }
  }
  if (!movedAny) break;
  }
  const afterNodes = { x: lx, y: ly, w: pw, h: ph };

  for (let p = 0; p < 3; p++) {
    let moved = false;
    for (const pl of placed) {
      const olx = Math.min(lx+pw/2, pl.x+pl.w/2) - Math.max(lx-pw/2, pl.x-pl.w/2);
      const oly = Math.min(ly+ph/2, pl.y+pl.h/2) - Math.max(ly-ph/2, pl.y-pl.h/2);
      if (olx > 0 && oly > 0) {
        if (olx < oly) lx += (lx>=pl.x?1:-1)*(olx+6); else ly += (ly>=pl.y?1:-1)*(oly+6);
        moved = true;
      }
    }
    if (!moved) break;
  }
  const afterLL = { x: lx, y: ly, w: pw, h: ph };
  ly = Math.max(20, Math.min(H-20, ly));
  lx = Math.max(30, Math.min(W-30, lx));
  const final = { x: lx, y: ly, w: pw, h: ph };
  placed.push(final);
  return { anchor, afterNodes, afterLL, final, fired, pw, ph };
}

const worst = (api, pl, visibleOnly) => {
  let best = null;
  for (const nn of api.allLayoutNodes) {
    if (visibleOnly && nn.zone === 'output') continue;
    const p = penetration(pl, nn);
    if (p > 0.01 && (!best || p > best.p)) best = { id: nn.id, p };
  }
  return best;
};

for (const [vw, vh] of [[1950,1000],[1918,1000],[1400,900],[1233,750],[1000,800],[800,700]]) {
  const api = harness(vw, vh, LAYOUTS, estimateTextWidth);
  console.log(`\n########## ${vw}x${vh}  SCL=${api.SCL.toFixed(3)} ##########`);
  for (const mode of ['shipped', 'fixA', 'fixB', 'fixC', 'shipped+iterate']) {
    const placed = [];
    let visHits = 0, totalPen = 0, hidHits = 0;
    const lines = [];
    for (const e of api.PROTO_EDGES) {
      const r = place(api, e, placed, mode);
      const wv = worst(api, r.final, true);
      const wa = worst(api, r.final, false);
      if (wv) { visHits++; totalPen += wv.p; }
      if (wa && !wv) hidHits++;
      // where did the damage come from?
      const penAfterNodes = worst(api, r.afterNodes, true);
      lines.push(`    ${e.label.padEnd(14)} fired=[${r.fired.join(',')||'-'}]  ` +
        `afterNodes worst=${penAfterNodes ? penAfterNodes.id+':'+penAfterNodes.p.toFixed(1) : 'clear'}  ` +
        `LLmove=${Math.hypot(r.afterLL.x-r.afterNodes.x, r.afterLL.y-r.afterNodes.y).toFixed(1)}  ` +
        `clampmove=${Math.hypot(r.final.x-r.afterLL.x, r.final.y-r.afterLL.y).toFixed(1)}  ` +
        `FINAL worst=${wv ? wv.id+':'+wv.p.toFixed(1) : 'clear'}`);
    }
    console.log(`  --- ${mode}: ${visHits}/7 labels overlap a VISIBLE node, total pen ${totalPen.toFixed(1)}px (hidden-only hits: ${hidHits}) ---`);
    lines.forEach(l => console.log(l));
  }
}
