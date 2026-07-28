// INDEPENDENT adversarial replay of the SHIPPED client edge-label placement.
// slabs/slab{A,B,C,D}.js are byte-for-byte extracts of
// go-server/static/js/topology.js lines 548-660, 662-745, 910-1304, 1499-1610,
// so the arithmetic cannot drift from the shipped file. Only the canvas text
// metric is a stand-in (the solver's own estimateTextWidth).
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

const harness = new Function('__W', '__H', '__LAYOUTS', '__estimate', `
'use strict';
let SOLVER_LAYOUTS = __LAYOUTS;
let SOLVER_ACTIVE = false;
let W = __W, H = __H;
let SCL = 1, FONT_LABEL = 13, FONT_SUB = 10, FONT_TAG = 13, MIN_SPACING = 8;
let COLORS = { email:'#4fc3f7', transport:'#81c784', policy:'#ffb74d', brand:'#ce93d8',
  source:'#5c6bc0', intel:'#78909c', engine:'#e0e0e0', storage:'#ff8a65', output:'#90caf9' };
let DEG = Math.PI / 180;
let allLayoutNodes = [];
let globe = { R:0, cx:0, cy:0 };
let convergePt = { x:0, y:0 };
let SHOW_OUTPUTS = false;   // shipped: declared false, never reassigned anywhere in the file
let HUD_ACTIVE = false;
let debugBounds = false;
function forceDirectedLayout() { throw new Error('DEAD CODE REACHED: forceDirectedLayout'); }
let ctx = {
  font: '10px x',
  measureText(t) { let m = /^(?:bold )?([\\d.]+)px/.exec(this.font); return { width: __estimate(t, m ? parseFloat(m[1]) : 10) }; },
  save(){}, restore(){}, beginPath(){}, moveTo(){}, lineTo(){}, arc(){}, closePath(){},
  fill(){}, stroke(){}, fillText(){}, setLineDash(){},
  createLinearGradient(){ return { addColorStop(){} }; }
};

${SLAB('slabA.js')}
${SLAB('slabB.js')}
${SLAB('slabC.js')}

let PROTO_IDS = {};
PROTOCOLS.forEach(function(p){ PROTO_IDS[p.id] = true; });

function findEdgeCurveOffset(from, to, edgeType) {
  if (edgeType === 'flow') return null;
  if (!PROTO_IDS[from.id] || !PROTO_IDS[to.id]) return null;
  let mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
  let edx = to.x - from.x, edy = to.y - from.y;
  let elen = Math.sqrt(edx*edx + edy*edy) || 1;
  let perpX = -edy/elen, perpY = edx/elen;
  let bestOffset = 0, closestDist = Infinity;
  for (let pi = 0; pi < PROTOCOLS.length; pi++) {
    let pn = PROTOCOLS[pi];
    if (pn.id === from.id || pn.id === to.id) continue;
    let dx2 = pn.x - mx, dy2 = pn.y - my;
    let distToMid = Math.sqrt(dx2*dx2 + dy2*dy2);
    if (distToMid < pn.radius + 50 && distToMid < closestDist) {
      closestDist = distToMid;
      let side = dx2*perpX + dy2*perpY;
      bestOffset = (side > 0 ? -1 : 1) * Math.max(40, pn.radius + 20);
    }
  }
  if (bestOffset === 0) return null;
  return { cx: mx + perpX*bestOffset, cy: my + perpY*bestOffset };
}

let placedEdgeLabels = [];
// slab D is the shipped block from drawFlowEdge lines 1499-1610.
function placeLabel(e, from, to, curve, isHL) {
  let __out = null;
  ${SLAB('slabD.js').replace(
      'placedEdgeLabels.push({ x: lx, y: ly, w: pw, h: ph });',
      'placedEdgeLabels.push({ x: lx, y: ly, w: pw, h: ph }); __out = { x: lx, y: ly, w: pw, h: ph };')}
  return __out;
}

layoutAll();
return { allNodes, PROTOCOLS, PROTO_EDGES, FLOW_EDGES, allLayoutNodes,
         placeLabel, findEdgeCurveOffset, placedEdgeLabels,
         scale: { SCL, FONT_LABEL, FONT_SUB, W, H, SOLVER_ACTIVE } };
`);

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

function rectPointDist(px, py, rx, ry, hw, hh) {
  const dx = Math.max(Math.abs(px - rx) - hw, 0);
  const dy = Math.max(Math.abs(py - ry) - hh, 0);
  return Math.hypot(dx, dy);
}

for (const [vw, vh] of [[1950, 1000], [1233, 750], [800, 700]]) {
  const api = harness(vw, vh, LAYOUTS, estimateTextWidth);
  const S = api.scale;
  console.log(`\n=========== viewport ${vw}x${vh}  SCL=${S.SCL.toFixed(4)} FONT_SUB=${S.FONT_SUB} SOLVER_ACTIVE=${S.SOLVER_ACTIVE} ===========`);
  console.log('  protocol centres: ' + api.PROTOCOLS.map(p => `${p.id}(${p.x.toFixed(0)},${p.y.toFixed(0)})`).join(' '));

  for (const e of api.PROTO_EDGES) {
    const from = api.allNodes[e.from], to = api.allNodes[e.to];
    const curve = api.findEdgeCurveOffset(from, to, e.type);
    const t = e.labelT || 0.5;
    let ax, ay;
    if (curve) {
      ax = (1-t)*(1-t)*from.x + 2*(1-t)*t*curve.cx + t*t*to.x;
      ay = (1-t)*(1-t)*from.y + 2*(1-t)*t*curve.cy + t*t*to.y;
    } else { ax = from.x + (to.x-from.x)*t; ay = from.y + (to.y-from.y)*t; }
    ay -= 8 * S.SCL;

    const pl = api.placeLabel(e, from, to, curve, false);
    if (!pl) { console.log(`  ${e.label}: not placed`); continue; }

    const hits = [];
    for (const nn of api.allLayoutNodes) {
      const hidden = nn.zone === 'output';   // never drawn: SHOW_OUTPUTS === false
      let pen = 0, kind = '';
      if (nn.shape === 'circle') {
        const d = rectPointDist(nn.x, nn.y, pl.x, pl.y, pl.w/2, pl.h/2);
        if (d < nn.radius) { pen = nn.radius - d; kind = 'circle'; }
      } else {
        const ox = Math.min(pl.x+pl.w/2, nn.x+nn._halfW) - Math.max(pl.x-pl.w/2, nn.x-nn._halfW);
        const oy = Math.min(pl.y+pl.h/2, nn.y+nn._halfH) - Math.max(pl.y-pl.h/2, nn.y-nn._halfH);
        if (ox > 0 && oy > 0) { pen = Math.min(ox, oy); kind = `box ${ox.toFixed(1)}x${oy.toFixed(1)}`; }
      }
      if (pen > 0.01) hits.push(`${nn.id}${hidden ? '[HIDDEN]' : ''}=${pen.toFixed(1)}(${kind})`);
    }
    console.log(`  ${e.label.padEnd(14)} anchor(${ax.toFixed(1)},${ay.toFixed(1)}) -> pill centre(${pl.x.toFixed(1)},${pl.y.toFixed(1)}) ${pl.w.toFixed(1)}x${pl.h.toFixed(1)} moved=${Math.hypot(pl.x-ax, pl.y-ay).toFixed(1)}`);
    console.log(`     DRAWN-INK overlaps: ${hits.length ? hits.join('  ') : 'NONE'}`);
  }
}
