// Standalone replication of topology.js layoutAll() for the ENGINE-box audit.
// Node declarations are EXTRACTED FROM THE REAL SOURCE FILE (not retyped) so
// they cannot drift. Layout math is transcribed from go-server/static/js/topology.js.
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { estimateTextWidth } from './src/nodeMetrics.js';

const ROOT = path.resolve('/Users/careybalboa/Documents/GitHub/dns-tool-intel/.claude/worktrees/mystifying-jang-08534f');
const SRC = fs.readFileSync(path.join(ROOT, 'go-server/static/js/topology.js'), 'utf8');

// --- extract the node literals verbatim from the shipped file -------------
function grab(startMarker, endMarker) {
  const i = SRC.indexOf(startMarker);
  if (i < 0) throw new Error('marker not found: ' + startMarker);
  const j = SRC.indexOf(endMarker, i);
  return SRC.slice(i, j + endMarker.length);
}
const decls = [
  grab('let SOURCES = [', '];'),
  grab('let HUB = {', '};'),
  grab('let ENGINE = {', '};'),
  grab('let CONFIDENCE = [', '];'),
  grab('let STORAGE = [', '];'),
  grab('let PROTOCOLS = [', '];'),
  grab('let OUTPUTS = [', '];'),
].join('\n');

const sandbox = {
  COLORS: new Proxy({}, { get: () => '#000' }),
};
vm.createContext(sandbox);
vm.runInContext(decls + '\n; this.__out = {SOURCES,HUB,ENGINE,CONFIDENCE,STORAGE,PROTOCOLS,OUTPUTS};', sandbox);
const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = sandbox.__out;

// radii / shapes exactly as topology.js lines 604-637
SOURCES.forEach(s => { s.radius = 30; s.shape = 'rect'; });
CONFIDENCE.forEach(c => {
  c.radius = c.id === 'ede' ? 48 : c.id === 'ietf' ? 36 : 42;
  c.shape = c.id === 'ietf' ? 'rect' : 'diamond';
});
STORAGE.forEach(s => {
  s.radius = s.id === 'postgres' ? 36 : s.id === 'wayback' ? 32 : 34;
  s.shape = 'cylinder';
});
PROTOCOLS.forEach(p => { p.radius = 36; p.shape = 'circle'; p.zone = 'protocol'; });
OUTPUTS.forEach(o => { o.radius = 36; o.shape = 'hexagon'; });
// ENGINE: NOTE — no shape assigned anywhere. HUB has shape 'hub'.

const SOLVER = {};
for (const p of ['desktop', 'tablet', 'mobile']) {
  SOLVER[p] = JSON.parse(fs.readFileSync(path.join(ROOT, `go-server/tools/topology-solver/output/${p}-layout.json`), 'utf8'));
}

// --- computeNodeBox: transcribed from topology.js:677 ---------------------
function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, measureFn) {
  let labelW = measureFn(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const sw = measureFn(l, fontSub); if (sw > subW) subW = sw; }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0)); }
  return { w, h, halfW: w / 2, halfH: h / 2, contentW, subLineCount };
}

function layout(W, H, opts = {}) {
  const engineShape = opts.engineShape;   // undefined = shipped behaviour
  const engineRadiusForMeasure = opts.engineRadiusForMeasure || ENGINE.radius;

  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const measure = (t, f) => estimateTextWidth(t, f);

  function measureNodeBox(n) {
    const shape = n.id === 'engine' ? engineShape : n.shape;
    const radius = n.id === 'engine' ? engineRadiusForMeasure : n.radius;
    const b = computeNodeBox(shape, radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB, measure);
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

  const SHOW_OUTPUTS = false;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
  const c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
  const c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
  const col1L = pipeStart, col1R = col1L + c1w;
  const col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w;
  const col4L = col3R + colGap, col4R = pipeEnd;

  const srcCx = (col1L + col1R) / 2;
  const srcSpacing = usableH / (SOURCES.length + 1);
  SOURCES.forEach((s, i) => { s.targetX = srcCx; s.targetY = titleSafe + (i + 1) * srcSpacing; });
  HUB.targetX = srcCx; HUB.targetY = globe.cy;

  const procCx = (col2L + col2R) / 2;
  ENGINE.targetX = procCx; ENGINE.targetY = titleSafe + usableH * 0.15;
  const confSpread = Math.max(40, (col2R - col2L) * 0.32);
  const confY = titleSafe + usableH * 0.42;
  CONFIDENCE[0].targetX = procCx; CONFIDENCE[0].targetY = confY - usableH * 0.06;
  CONFIDENCE[1].targetX = procCx - confSpread * 0.5; CONFIDENCE[1].targetY = confY + usableH * 0.06;
  CONFIDENCE[2].targetX = procCx + confSpread * 0.5; CONFIDENCE[2].targetY = confY + usableH * 0.06;
  CONFIDENCE[3].targetX = procCx; CONFIDENCE[3].targetY = confY + usableH * 0.18;

  const storeY = titleSafe + usableH * 0.78;
  const storeSpread = Math.max(confSpread * 0.8, 60);
  STORAGE[0].targetX = procCx; STORAGE[0].targetY = storeY;
  STORAGE[1].targetX = procCx - storeSpread; STORAGE[1].targetY = storeY + usableH * 0.10;
  STORAGE[2].targetX = procCx + storeSpread; STORAGE[2].targetY = storeY + usableH * 0.10;

  const protoCx = (col3L + col3R) / 2, protoCy = titleSafe + usableH * 0.42;
  const protoRx = (col3R - col3L) * 0.38, protoRy = usableH * 0.28;
  const angleMap = [-130, -90, -50, -10, 30, 70, 110, 150, 190], DEG = Math.PI / 180;
  PROTOCOLS.forEach((p, i) => {
    const a = angleMap[i] * DEG;
    p.targetX = protoCx + protoRx * Math.cos(a); p.targetY = protoCy + protoRy * Math.sin(a);
  });
  const outCx = (col4L + col4R) / 2, outSpacing = usableH / (OUTPUTS.length + 1);
  OUTPUTS.forEach((o, i) => { o.targetX = outCx; o.targetY = titleSafe + (i + 1) * outSpacing; });

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

  const allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  allLayoutNodes.forEach(measureNodeBox);

  // --- shelf re-partition (topology.js:1069-1148) --------------------------
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
      const anyDeficit = stack.some(zk => {
        const zb = zones[zk].bounds;
        return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1;
      });
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
      stack.forEach((zk, i) => {
        zones[zk].bounds.y1 = cursor;
        zones[zk].bounds.y2 = cursor + needs[i] + share;
        cursor = zones[zk].bounds.y2 + usedPad;
        grouped[zk] = true;
      });
    });
  })();

  // --- solver remap (topology.js:1150-1226) --------------------------------
  const solverProfile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const solverData = SOLVER[solverProfile].nodeCenters;
  const refCanvas = SOLVER[solverProfile].canvas;
  const ref = { w: refCanvas.width, h: refCanvas.height };
  const usableW = W - consoleReserve;
  allLayoutNodes.forEach(nd => {
    const pos = solverData[nd.id];
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
  // protocol ellipse rescale
  {
    const pxs = PROTOCOLS.map(p => p.targetX), pys = PROTOCOLS.map(p => p.targetY);
    const minPX = Math.min(...pxs), maxPX = Math.max(...pxs), minPY = Math.min(...pys), maxPY = Math.max(...pys);
    const pz = zones.protocol.bounds, padX = 52 * SCL, padY = 44 * SCL;
    const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
    if (maxPX - minPX > 1 && tx2 - tx1 > 40) PROTOCOLS.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
    if (maxPY - minPY > 1 && ty2 - ty1 > 40) PROTOCOLS.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });
  }

  // --- overlap pass (topology.js:1232-1271) --------------------------------
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters = op + 1;
    let any = false;
    for (let i = 0; i < allLayoutNodes.length; i++) {
      for (let j = i + 1; j < allLayoutNodes.length; j++) {
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
  allLayoutNodes.forEach(nd => { nd.x = nd.targetX; nd.y = nd.targetY; });
  return { SCL, W, H, titleSafe, legendSafe, zones, allLayoutNodes, iters, solverProfile, consoleReserve };
}

// ---------------------------------------------------------------------------
function report(W, H, opts) {
  const r = layout(W, H, opts);
  const E = r.allLayoutNodes.find(n => n.id === 'engine');
  const SCL = r.SCL;
  const inkTop = E.y - (54 + 3 + 0.6);   // pulseR max 57 + half stroke 0.6
  const inkBot = E.y + (54 + 3 + 0.6);
  const glowR = (54 + 3) * 2.5;
  console.log(`\n=== W=${W} H=${H} profile=${r.solverProfile} SCL=${SCL.toFixed(4)} consoleReserve=${r.consoleReserve} shape=${opts && opts.engineShape ? opts.engineShape : '(none/RECT)'} passIters=${r.iters}`);
  console.log(`  engine box  w=${E._boxW.toFixed(2)} h=${E._boxH.toFixed(2)}  halfW=${E._halfW.toFixed(2)} halfH=${E._halfH.toFixed(2)}`);
  console.log(`  engine centre (${E.x.toFixed(1)}, ${E.y.toFixed(1)})  AABB y [${(E.y - E._halfH).toFixed(1)}, ${(E.y + E._halfH).toFixed(1)}]`);
  console.log(`  drawn outline y [${inkTop.toFixed(1)}, ${inkBot.toFixed(1)}]  -> vertical overflow ${(57.6 - E._halfH).toFixed(2)}px/side`);
  console.log(`  horizontal: halfW ${E._halfW.toFixed(2)} vs ink 57.60 -> ${(E._halfW - 57.6).toFixed(2)}px slack`);
  console.log(`  engine zone band y [${r.zones.engine.bounds.y1.toFixed(1)}, ${r.zones.engine.bounds.y2.toFixed(1)}]  (height ${(r.zones.engine.bounds.y2 - r.zones.engine.bounds.y1).toFixed(1)})`);
  console.log(`  glow disc radius ${glowR.toFixed(1)} (soft, alpha->0)`);

  // nearest neighbour analysis, ink vs ink
  const others = r.allLayoutNodes.filter(n => n.id !== 'engine');
  const rows = others.map(n => {
    const gapY = Math.abs(n.y - E.y) - E._halfH - n._halfH;   // AABB-to-AABB vertical gap
    const gapX = Math.abs(n.x - E.x) - E._halfW - n._halfW;
    // engine ink vs neighbour AABB (only meaningful when x ranges overlap)
    const xRangesOverlap = Math.abs(n.x - E.x) < (57.6 + n._halfW);
    const inkPen = xRangesOverlap ? (57.6 + n._halfH) - Math.abs(n.y - E.y) : -Infinity;
    return { id: n.id, dx: (n.x - E.x), dy: (n.y - E.y), gapX, gapY, inkPen, xRangesOverlap };
  }).sort((a, b) => Math.hypot(a.dx, a.dy) - Math.hypot(b.dx, b.dy));
  console.log('  nearest neighbours (dx,dy | AABB gapX,gapY | engine-ink penetration into their AABB):');
  rows.slice(0, 5).forEach(x => {
    console.log(`    ${x.id.padEnd(9)} d=(${x.dx.toFixed(1)}, ${x.dy.toFixed(1)})  gapX=${x.gapX.toFixed(1)} gapY=${x.gapY.toFixed(1)}  inkPen=${x.inkPen === -Infinity ? 'n/a (x apart)' : x.inkPen.toFixed(2)}`);
  });
  return { E, r };
}

const viewports = [[1950, 1000], [1950, 750], [1233, 750], [1400, 900], [800, 750], [420, 900]];
console.log('########## SHIPPED (ENGINE has no shape -> RECT branch) ##########');
for (const [w, h] of viewports) report(w, h);

console.log('\n\n########## PROPOSED FIX A: shape:"circle", radius 54 ##########');
for (const [w, h] of viewports) report(w, h, { engineShape: 'circle' });

console.log('\n\n########## PROPOSED FIX B: shape:"circle", measured radius 57 ##########');
for (const [w, h] of viewports) report(w, h, { engineShape: 'circle', engineRadiusForMeasure: 57 });
