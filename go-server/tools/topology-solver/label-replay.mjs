// Offline replay of drawResolverMarkers()'s label placement, ported line-for-line
// from go-server/static/js/topology.js lines 147-345, using the REAL globe-core.js
// (projectPt, RESOLVER_POPS) loaded from source.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
const gcSrc = fs.readFileSync(path.join(ROOT, 'go-server/static/js/globe-core.js'), 'utf8');
// globe-core.js is an IIFE that assigns globalThis.GlobeCore. Just eval it.
(0, eval)(gcSrc);
const GC = globalThis.GlobeCore;
const DEG = Math.PI / 180;

// ---- text metrics: Helvetica AFM widths (units/1000) --------------------
const AFM = { ' ': 278, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '—': 1000, '.': 278, '/': 278, 'ã': 556, '0': 556, '1': 556 };
let WIDTH_FUDGE = 1.0;
function measure(text, fontSize) {
  let u = 0;
  for (const ch of text) u += (AFM[ch] !== undefined ? AFM[ch] : 556);
  return (u / 1000) * fontSize * WIDTH_FUDGE;
}

function rectsOverlap(a, b) {
  const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
  const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
  return (ox > 0 && oy > 0) ? { ox, oy } : null;
}

// ---- geometry, ported from layoutAll() ---------------------------------
function geometry(W, H) {
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_TAG = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_LABEL = FONT_TAG;
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const titleSafe = Math.max(H * 0.07, 42);
  const legendSafe = H * 0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const cx = W * 0.04 + globeR;
  const cy = titleSafe + usableH * 0.42;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeStart = cx + globeR + W * 0.02;
  const pipeEnd = W * 0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  return { W, H, SCL, FONT_TAG, FONT_LABEL, FONT_SUB, titleSafe, legendSafe, usableH, globeR, cx, cy, pipeStart, pipeEnd, pipeTotal };
}

// SOURCES + HUB are the only layout nodes that can fall inside the label band
// (labels are bounded at maxLabelRight = cx+R+labelBand+labelGap).
const SOURCES = [
  { label: 'Root / TLD', sub: 'IANA Root Zone\nTLD Registries' },
  { label: 'RDAP / WHOIS', sub: 'Registration Data\nAccess Protocol' },
  { label: 'CT / Subdomains', sub: 'crt.sh · Certspotter\nTransparency Logs' },
  { label: 'CISA / Threat', sub: 'BOD 19-02\nIP Scanner Detection' },
  { label: 'Probe Fleet', sub: 'SMTP · DANE · TLS\nNmap · testssl.sh' }
];

function nodeObstacles(g) {
  // computeNodeBox for shape 'rect' (default branch) and 'hub'
  const boxOf = (label, sub, radius, shape) => {
    let labelW = measure(label, g.FONT_LABEL);
    let subW = 0, lines = 0;
    if (sub) { const L = sub.split('\n'); lines = L.length; for (const s of L) subW = Math.max(subW, measure(s, g.FONT_SUB)); }
    const contentW = Math.max(labelW, subW) + 24 * g.SCL;
    if (shape === 'hub') return { w: Math.max(radius * 2.4, contentW), h: Math.max(radius * 1.4, 40 * g.SCL) };
    return { w: Math.max(radius * 2.4, contentW), h: Math.max(radius * 1.3, 40 * g.SCL + (lines > 1 ? (lines - 1) * (g.FONT_SUB + 2) : 0)) };
  };
  const srcBoxes = SOURCES.map(s => boxOf(s.label, s.sub, 30, 'rect'));
  const hubBox = boxOf('DNS Resolvers', 'Signal Aggregation', 44, 'hub');
  const srcNeed = Math.max(...srcBoxes.map(b => b.w), hubBox.w) + 26;
  const c1w = Math.min(Math.max(srcNeed, g.pipeTotal * 0.13), g.pipeTotal * 0.30);
  const col1L = g.pipeStart, col1R = col1L + c1w;
  const srcCx = (col1L + col1R) / 2;
  const srcSpacing = g.usableH / (SOURCES.length + 1);
  const out = [];
  srcBoxes.forEach((b, i) => {
    const y = g.titleSafe + (i + 1) * srcSpacing;
    out.push({ x: srcCx - b.w / 2, y: y - b.h / 2, w: b.w, h: b.h, id: 'src' + i });
  });
  out.push({ x: srcCx - hubBox.w / 2, y: g.cy - hubBox.h / 2, w: hubBox.w, h: hubBox.h, id: 'hub' });
  return { obstacles: out, srcCx, col1L, col1R };
}

// ---- the port of drawResolverMarkers placement -------------------------
function runSim(opts) {
  const { W, H, LABEL_LERP, RELAYOUT_INTERVAL, frames, withObstacles, fixA, fixB, dump } = opts;
  const g = geometry(W, H);
  const gs = GC.createGlobeState();
  gs.cx = g.cx; gs.cy = g.cy; gs.R = g.globeR; gs.rotLon = -58;
  const { obstacles } = nodeObstacles(g);

  const cache = {};
  let prevVisibleSet = '';
  let frameCount = 0;
  const dtSec = 1 / 60;

  let framesWithDrawnOverlap = 0, framesWithIdealOverlap = 0;
  const worst = new Map();
  let dumped = null;

  for (let f = 0; f < frames; f++) {
    gs.rotLon = (gs.rotLon + 4.8 * dtSec) % 360;

    const visiblePops = [];
    for (let i = 0; i < GC.RESOLVER_POPS.length; i++) {
      const pop = GC.RESOLVER_POPS[i];
      const p = GC.projectPt(gs, pop.lat, pop.lon);
      if (p.vis) visiblePops.push({ pop, p, idx: i });
    }
    visiblePops.sort((a, b) => a.p.depth - b.p.depth);

    frameCount++;
    const visIds = visiblePops.map(v => v.idx).slice().sort((a, b) => a - b);
    const visKey = visIds.join(',');
    const periodicRelayout = (frameCount % RELAYOUT_INTERVAL === 0);
    const visChanged = visKey !== prevVisibleSet || periodicRelayout;
    prevVisibleSet = visKey;

    const placedBoxes = [];
    if (withObstacles) for (const o of obstacles) placedBoxes.push({ ...o });

    const cityLabeled = {};
    const labelGap = 12 * g.SCL;
    const labelBand = 190 * g.SCL;
    const maxLabelRight = gs.cx + gs.R + labelBand + labelGap;
    const maxLabelBottom = gs.cy + gs.R + labelBand;

    const drawn = [];   // what is actually rendered this frame (cur)
    const ideals = [];  // what the search committed (ideal)

    for (let vi = 0; vi < visiblePops.length; vi++) {
      const vp = visiblePops[vi];
      const pop2 = vp.pop, p2 = vp.p;
      if (cityLabeled[pop2.city]) continue;
      cityLabeled[pop2.city] = true;

      const label = pop2.city;
      const tw = measure(label, g.FONT_TAG);
      const tagW = tw + 18 * g.SCL;
      const tagH = Math.round(20 * g.SCL + 2);

      const cacheKey = 'r' + vp.idx;
      let cached = cache[cacheKey];

      if (!cached || visChanged) {
        const baseAngle = Math.atan2(p2.y - gs.cy, p2.x - gs.cx);
        let bestX2 = null, bestY2 = null, bestScore = Infinity;
        const candidateAngles = [0, 15, -15, 30, -30, 45, -45, 60, -60, 75, -75, 90, -90, 105, -105, 120, -120, 135, -135, 150, -150, 165, -165, 180];
        const candidateDists = [gs.R * 0.15 + labelGap, gs.R * 0.25 + labelGap, gs.R * 0.35 + labelGap, gs.R * 0.5 + labelGap, gs.R * 0.68 + labelGap, gs.R * 0.88 + labelGap];
        for (let di = 0; di < candidateDists.length; di++) {
          for (let ci = 0; ci < candidateAngles.length; ci++) {
            const ca = baseAngle + candidateAngles[ci] * DEG;
            const dist = candidateDists[di];
            let cx2 = p2.x + Math.cos(ca) * dist;
            let cy2 = p2.y + Math.sin(ca) * dist;
            if (Math.cos(ca) < 0) cx2 -= tagW;
            if (cx2 < 4 || cx2 + tagW > maxLabelRight) continue;
            if (cy2 < 4 || cy2 + tagH > maxLabelBottom) continue;
            let hasCollision = false;
            for (let pi = 0; pi < placedBoxes.length; pi++) {
              const pb = placedBoxes[pi];
              if (cx2 < pb.x + pb.w + 3 && cx2 + tagW > pb.x - 3 && cy2 < pb.y + pb.h + 3 && cy2 + tagH > pb.y - 3) { hasCollision = true; break; }
            }
            const distFromDot = Math.hypot(cx2 + tagW / 2 - p2.x, cy2 + tagH / 2 - p2.y);
            const score = (hasCollision ? 10000 : 0) + distFromDot;
            if (score < bestScore) { bestScore = score; bestX2 = cx2; bestY2 = cy2; }
          }
        }
        if (bestX2 === null) {
          bestX2 = Math.min(Math.max(4, p2.x - tagW / 2), maxLabelRight - tagW);
          bestY2 = Math.min(gs.cy + gs.R + 16 * g.SCL, maxLabelBottom - tagH);
          bestScore = 10000;
        }
        if (bestScore >= 10000) {
          for (let ri = 0; ri < 8; ri++) {
            let shifted = false;
            for (let pi2 = 0; pi2 < placedBoxes.length; pi2++) {
              const pb2 = placedBoxes[pi2];
              const ovX = Math.min(bestX2 + tagW, pb2.x + pb2.w) - Math.max(bestX2, pb2.x);
              const ovY = Math.min(bestY2 + tagH, pb2.y + pb2.h) - Math.max(bestY2, pb2.y);
              if (ovX > 0 && ovY > 0) {
                if (ovY < ovX) { bestY2 += (bestY2 < pb2.y ? -(ovY + 4) : (ovY + 4)); }
                else { bestX2 += (bestX2 < pb2.x ? -(ovX + 4) : (ovX + 4)); }
                shifted = true;
              }
            }
            if (!shifted) break;
          }
          bestX2 = Math.max(4, Math.min(bestX2, maxLabelRight - tagW));
          bestY2 = Math.max(4, Math.min(bestY2, maxLabelBottom - tagH));
        }
        cache[cacheKey] = { idealX: bestX2, idealY: bestY2, curX: cached ? cached.curX : bestX2, curY: cached ? cached.curY : bestY2, fallback: bestScore >= 10000 };
        cached = cache[cacheKey];
      } else {
        const offsetX = p2.x - cached._lastDotX;
        const offsetY = p2.y - cached._lastDotY;
        cached.idealX += offsetX; cached.idealY += offsetY;
        cached.curX += offsetX; cached.curY += offsetY;
      }
      cached._lastDotX = p2.x; cached._lastDotY = p2.y;
      cached.curX += (cached.idealX - cached.curX) * LABEL_LERP;
      cached.curY += (cached.idealY - cached.curY) * LABEL_LERP;

      const rawTagX = cached.curX, rawTagY = cached.curY;
      if (fixA) {
        placedBoxes.push({
          x: Math.min(cached.curX, cached.idealX), y: Math.min(cached.curY, cached.idealY),
          w: tagW + Math.abs(cached.idealX - cached.curX), h: tagH + Math.abs(cached.idealY - cached.curY),
          id: label, isLabel: true
        });
      } else {
        placedBoxes.push({ x: rawTagX, y: rawTagY, w: tagW, h: tagH, id: label, isLabel: true });
      }
      drawn.push({ x: rawTagX, y: rawTagY, w: tagW, h: tagH, id: label, ref: cached });
      ideals.push({ x: cached.idealX, y: cached.idealY, w: tagW, h: tagH, id: label });
    }

    if (fixB) {
      // push-apart over the DRAWN boxes, writing back into cur
      const obs = withObstacles ? obstacles : [];
      for (let ri = 0; ri < 8; ri++) {
        let shifted = false;
        for (let i = 0; i < drawn.length; i++) {
          const a = drawn[i];
          const others = obs.concat(drawn.filter((_, j) => j !== i));
          for (const b of others) {
            const ov = rectsOverlap(a, b);
            if (ov) {
              if (ov.oy < ov.ox) a.y += (a.y < b.y ? -(ov.oy + 2) : (ov.oy + 2));
              else a.x += (a.x < b.x ? -(ov.ox + 2) : (ov.ox + 2));
              shifted = true;
            }
          }
        }
        if (!shifted) break;
      }
      for (const d of drawn) { d.ref.curX = d.x; d.ref.curY = d.y; }
    }

    let frameDrawnOv = false, frameIdealOv = false;
    for (let i = 0; i < drawn.length; i++) for (let j = i + 1; j < drawn.length; j++) {
      const ov = rectsOverlap(drawn[i], drawn[j]);
      if (ov) {
        frameDrawnOv = true;
        const key = [drawn[i].id, drawn[j].id].sort().join(' x ');
        const prev = worst.get(key);
        const mag = Math.min(ov.ox, ov.oy);
        if (!prev || mag > prev.mag) worst.set(key, { mag, ox: ov.ox, oy: ov.oy });
      }
    }
    for (let i = 0; i < ideals.length; i++) for (let j = i + 1; j < ideals.length; j++) {
      if (rectsOverlap(ideals[i], ideals[j])) frameIdealOv = true;
    }
    if (frameDrawnOv) framesWithDrawnOverlap++;
    if (frameIdealOv) framesWithIdealOverlap++;
    if (dump && f === dump && !dumped) dumped = { visChanged, drawn: drawn.map(d => ({ id: d.id, x: +d.x.toFixed(1), y: +d.y.toFixed(1) })), ideals: ideals.map(d => ({ id: d.id, x: +d.x.toFixed(1), y: +d.y.toFixed(1) })) };
  }

  return {
    frames, drawnPct: (100 * framesWithDrawnOverlap / frames).toFixed(1),
    idealPct: (100 * framesWithIdealOverlap / frames).toFixed(1),
    worst: [...worst.entries()].sort((a, b) => b[1].mag - a[1].mag).slice(0, 8).map(([k, v]) => `${k}: ${v.ox.toFixed(1)}x${v.oy.toFixed(1)}`),
    dumped
  };
}

// ---- experiment matrix -------------------------------------------------
const FR = 9000;
const rows = [];
function run(name, o) {
  const r = runSim({ frames: FR, LABEL_LERP: 0.12, RELAYOUT_INTERVAL: 120, withObstacles: true, fixA: false, fixB: false, ...o });
  rows.push({ name, drawn: r.drawnPct + '%', ideal: r.idealPct + '%' });
  return r;
}

console.log('=== W=1950 H=1000 (user\'s real Safari window) ===');
let base = run('baseline lerp=0.12 relayout=120 +nodes', { W: 1950, H: 1000 });
console.log('worst drawn pairs:', base.worst);
run('LERP=1 (cur==ideal) relayout=120 +nodes', { W: 1950, H: 1000, LABEL_LERP: 1 });
run('LERP=1 relayout=1 +nodes', { W: 1950, H: 1000, LABEL_LERP: 1, RELAYOUT_INTERVAL: 1 });
run('LERP=1 relayout=30 +nodes', { W: 1950, H: 1000, LABEL_LERP: 1, RELAYOUT_INTERVAL: 30 });
run('LERP=0.12 relayout=1 +nodes', { W: 1950, H: 1000, RELAYOUT_INTERVAL: 1 });
run('baseline NO node obstacles (claim\'s sim)', { W: 1950, H: 1000, withObstacles: false });
run('LERP=1 NO node obstacles (claim\'s control)', { W: 1950, H: 1000, withObstacles: false, LABEL_LERP: 1 });
run('LERP=1 relayout=1 NO nodes', { W: 1950, H: 1000, withObstacles: false, LABEL_LERP: 1, RELAYOUT_INTERVAL: 1 });
const fa = run('FIX(a) swept-box only +nodes', { W: 1950, H: 1000, fixA: true });
console.log('fix(a) worst:', fa.worst);
const fab = run('FIX(a)+(b) +nodes', { W: 1950, H: 1000, fixA: true, fixB: true });
console.log('fix(a)+(b) worst:', fab.worst);
const fb = run('FIX(b) only +nodes', { W: 1950, H: 1000, fixB: true });
console.log('fix(b) only worst:', fb.worst);
console.table(rows);

const rows2 = [];
function run2(name, o) {
  const r = runSim({ frames: FR, LABEL_LERP: 0.12, RELAYOUT_INTERVAL: 120, withObstacles: true, fixA: false, fixB: false, ...o });
  rows2.push({ name, drawn: r.drawnPct + '%', ideal: r.idealPct + '%' });
  return r;
}
console.log('\n=== other viewports (with node obstacles) ===');
for (const [W, H] of [[1233, 750], [1400, 900], [1280, 800], [800, 700]]) {
  run2(`W=${W} baseline`, { W, H });
  run2(`W=${W} LERP=1`, { W, H, LABEL_LERP: 1 });
  run2(`W=${W} FIX(a)+(b)`, { W, H, fixA: true, fixB: true });
}
console.table(rows2);

console.log('\n=== text-width sensitivity (W=1950, baseline) ===');
for (const fudge of [0.9, 1.0, 1.1]) {
  WIDTH_FUDGE = fudge;
  const r = runSim({ frames: FR, W: 1950, H: 1000, LABEL_LERP: 0.12, RELAYOUT_INTERVAL: 120, withObstacles: true });
  const r1 = runSim({ frames: FR, W: 1950, H: 1000, LABEL_LERP: 1, RELAYOUT_INTERVAL: 120, withObstacles: true });
  console.log(`fudge=${fudge}  baseline drawn=${r.drawnPct}% ideal=${r.idealPct}%   LERP=1 drawn=${r1.drawnPct}% ideal=${r1.idealPct}%`);
}
WIDTH_FUDGE = 1.0;
