// Decisive isolation experiments the original finding did not run.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
(0, eval)(fs.readFileSync(path.join(ROOT, 'go-server/static/js/globe-core.js'), 'utf8'));
const GC = globalThis.GlobeCore;
const DEG = Math.PI / 180;
const AFM = { ' ': 278, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '.': 278, '/': 278, 'ã': 556 };
const measure = (t, s) => { let u = 0; for (const c of t) u += AFM[c] ?? 556; return u / 1000 * s; };
const ov = (a, b) => { const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x), oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y); return ox > 0 && oy > 0 ? { ox, oy } : null; };

function geometry(W, H) {
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_TAG = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const titleSafe = Math.max(H * 0.07, 42), legendSafe = H * 0.95, usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const cx = W * 0.04 + globeR, cy = titleSafe + usableH * 0.42;
  const pipeStart = cx + globeR + W * 0.02, pipeEnd = W * 0.99 - (W >= 1000 ? 386 : 0);
  return { W, H, SCL, FONT_TAG, FONT_LABEL: FONT_TAG, FONT_SUB, titleSafe, legendSafe, usableH, globeR, cx, cy, pipeStart, pipeTotal: pipeEnd - pipeStart };
}
const SRC = [['Root / TLD', 'IANA Root Zone\nTLD Registries'], ['RDAP / WHOIS', 'Registration Data\nAccess Protocol'], ['CT / Subdomains', 'crt.sh · Certspotter\nTransparency Logs'], ['CISA / Threat', 'BOD 19-02\nIP Scanner Detection'], ['Probe Fleet', 'SMTP · DANE · TLS\nNmap · testssl.sh']];
function obstaclesFor(g) {
  const boxOf = (label, sub, radius, hub) => { let lw = measure(label, g.FONT_LABEL), sw = 0, ln = 0; const L = sub.split('\n'); ln = L.length; for (const s of L) sw = Math.max(sw, measure(s, g.FONT_SUB)); const cw = Math.max(lw, sw) + 24 * g.SCL; return hub ? { w: Math.max(radius * 2.4, cw), h: Math.max(radius * 1.4, 40 * g.SCL) } : { w: Math.max(radius * 2.4, cw), h: Math.max(radius * 1.3, 40 * g.SCL + (ln - 1) * (g.FONT_SUB + 2)) }; };
  const sb = SRC.map(s => boxOf(s[0], s[1], 30, false));
  const hb = boxOf('DNS Resolvers', 'Signal Aggregation', 44, true);
  const c1w = Math.min(Math.max(Math.max(...sb.map(b => b.w), hb.w) + 26, g.pipeTotal * 0.13), g.pipeTotal * 0.30);
  const srcCx = (g.pipeStart + g.pipeStart + c1w) / 2, sp = g.usableH / 6;
  const out = sb.map((b, i) => ({ x: srcCx - b.w / 2, y: g.titleSafe + (i + 1) * sp - b.h / 2, w: b.w, h: b.h, id: 'src' + i }));
  out.push({ x: srcCx - hb.w / 2, y: g.cy - hb.h / 2, w: hb.w, h: hb.h, id: 'hub' });
  return { obstacles: out, srcCx, col1L: g.pipeStart, col1R: g.pipeStart + c1w };
}

// register: 'cur' (shipped), 'ideal', 'union'
// resetOnAppear: reset cur=ideal when a label was NOT visible last frame
function sim({ W, H, LERP = 0.12, RELAYOUT = 120, frames = 9000, register = 'cur', resetOnAppear = false, obstaclesOn = true, dumpFrame = -1 }) {
  const g = geometry(W, H);
  const gs = GC.createGlobeState(); gs.cx = g.cx; gs.cy = g.cy; gs.R = g.globeR; gs.rotLon = -58;
  const { obstacles } = obstaclesFor(g);
  const cache = {}; let prevVis = '', fc = 0, prevVisSet = new Set();
  let drawnOvF = 0, idealOvF = 0, relayoutFrames = 0, idealPairsCommittedOverlapping = 0, idealPairChecks = 0;
  let bigLagAppear = 0, bigLagSteady = 0, regEvents = 0, obstacleHits = 0;
  let dump = null;
  for (let f = 0; f < frames; f++) {
    gs.rotLon = (gs.rotLon + 4.8 / 60) % 360;
    const vps = [];
    GC.RESOLVER_POPS.forEach((pop, i) => { const p = GC.projectPt(gs, pop.lat, pop.lon); if (p.vis) vps.push({ pop, p, idx: i }); });
    vps.sort((a, b) => a.p.depth - b.p.depth);
    fc++;
    const visKey = vps.map(v => v.idx).slice().sort((a, b) => a - b).join(',');
    const visChanged = visKey !== prevVis || (fc % RELAYOUT === 0);
    prevVis = visKey;
    if (visChanged) relayoutFrames++;
    const curVisSet = new Set(vps.map(v => v.idx));
    const placed = obstaclesOn ? obstacles.map(o => ({ ...o })) : [];
    const nObs = placed.length;
    const labeled = {}, drawn = [], ideals = [];
    const gap = 12 * g.SCL, band = 190 * g.SCL;
    const maxR = gs.cx + gs.R + band + gap, maxB = gs.cy + gs.R + band;
    for (const vp of vps) {
      if (labeled[vp.pop.city]) continue; labeled[vp.pop.city] = true;
      const p2 = vp.p, label = vp.pop.city;
      const tagW = measure(label, g.FONT_TAG) + 18 * g.SCL, tagH = Math.round(20 * g.SCL + 2);
      const key = 'r' + vp.idx; let c = cache[key];
      const wasVisible = prevVisSet.has(vp.idx);
      if (!c || visChanged) {
        const ba = Math.atan2(p2.y - gs.cy, p2.x - gs.cx);
        let bx = null, by = null, bs = Infinity;
        const angs = [0, 15, -15, 30, -30, 45, -45, 60, -60, 75, -75, 90, -90, 105, -105, 120, -120, 135, -135, 150, -150, 165, -165, 180];
        const dists = [0.15, 0.25, 0.35, 0.5, 0.68, 0.88].map(k => gs.R * k + gap);
        for (const dist of dists) for (const a of angs) {
          const ca = ba + a * DEG;
          let x = p2.x + Math.cos(ca) * dist, y = p2.y + Math.sin(ca) * dist;
          if (Math.cos(ca) < 0) x -= tagW;
          if (x < 4 || x + tagW > maxR) continue;
          if (y < 4 || y + tagH > maxB) continue;
          let col = false, colIsObstacle = false;
          for (let pi = 0; pi < placed.length; pi++) { const pb = placed[pi]; if (x < pb.x + pb.w + 3 && x + tagW > pb.x - 3 && y < pb.y + pb.h + 3 && y + tagH > pb.y - 3) { col = true; colIsObstacle = pi < nObs; break; } }
          if (col && colIsObstacle) obstacleHits++;
          const s = (col ? 10000 : 0) + Math.hypot(x + tagW / 2 - p2.x, y + tagH / 2 - p2.y);
          if (s < bs) { bs = s; bx = x; by = y; }
        }
        if (bx === null) { bx = Math.min(Math.max(4, p2.x - tagW / 2), maxR - tagW); by = Math.min(gs.cy + gs.R + 16 * g.SCL, maxB - tagH); bs = 10000; }
        if (bs >= 10000) {
          for (let ri = 0; ri < 8; ri++) { let sh = false; for (const pb of placed) { const oX = Math.min(bx + tagW, pb.x + pb.w) - Math.max(bx, pb.x), oY = Math.min(by + tagH, pb.y + pb.h) - Math.max(by, pb.y); if (oX > 0 && oY > 0) { if (oY < oX) by += (by < pb.y ? -(oY + 4) : (oY + 4)); else bx += (bx < pb.x ? -(oX + 4) : (oX + 4)); sh = true; } } if (!sh) break; }
          bx = Math.max(4, Math.min(bx, maxR - tagW)); by = Math.max(4, Math.min(by, maxB - tagH));
        }
        cache[key] = { idealX: bx, idealY: by, curX: c ? c.curX : bx, curY: c ? c.curY : by };
        c = cache[key];
        if (resetOnAppear && !wasVisible) { c.curX = c.idealX; c.curY = c.idealY; }
      } else {
        const dx = p2.x - c._lastDotX, dy = p2.y - c._lastDotY;
        c.idealX += dx; c.idealY += dy; c.curX += dx; c.curY += dy;
      }
      c._lastDotX = p2.x; c._lastDotY = p2.y;
      c.curX += (c.idealX - c.curX) * LERP; c.curY += (c.idealY - c.curY) * LERP;
      const lag = Math.hypot(c.idealX - c.curX, c.idealY - c.curY);
      regEvents++;
      if (lag > 50) { if (!wasVisible) bigLagAppear++; else bigLagSteady++; }
      // measure: does this label's COMMITTED ideal overlap an earlier label's committed ideal?
      for (const pv of ideals) { idealPairChecks++; if (ov({ x: c.idealX, y: c.idealY, w: tagW, h: tagH }, pv)) idealPairsCommittedOverlapping++; }
      let box;
      if (register === 'ideal') box = { x: c.idealX, y: c.idealY, w: tagW, h: tagH };
      else if (register === 'union') box = { x: Math.min(c.curX, c.idealX), y: Math.min(c.curY, c.idealY), w: tagW + Math.abs(c.idealX - c.curX), h: tagH + Math.abs(c.idealY - c.curY) };
      else box = { x: c.curX, y: c.curY, w: tagW, h: tagH };
      placed.push(box);
      drawn.push({ x: c.curX, y: c.curY, w: tagW, h: tagH, id: label });
      ideals.push({ x: c.idealX, y: c.idealY, w: tagW, h: tagH, id: label });
    }
    prevVisSet = curVisSet;
    let dov = false, iov = false;
    for (let i = 0; i < drawn.length; i++) for (let j = i + 1; j < drawn.length; j++) if (ov(drawn[i], drawn[j])) dov = true;
    for (let i = 0; i < ideals.length; i++) for (let j = i + 1; j < ideals.length; j++) if (ov(ideals[i], ideals[j])) iov = true;
    if (dov) drawnOvF++; if (iov) idealOvF++;
    if (f === dumpFrame) dump = { visChanged, drawn: drawn.map(d => `${d.id}(${d.x.toFixed(1)},${d.y.toFixed(1)})`), ideals: ideals.map(d => `${d.id}(${d.x.toFixed(1)},${d.y.toFixed(1)})`) };
  }
  return { drawn: (100 * drawnOvF / frames).toFixed(1), ideal: (100 * idealOvF / frames).toFixed(1), relayoutFrames, idealBadPairs: idealPairsCommittedOverlapping, bigLagAppear, bigLagSteady, regEvents, obstacleHits, dump };
}

const W = 1950, H = 1000;
const t = [];
const push = (n, o) => { const r = sim({ W, H, ...o }); t.push({ scenario: n, 'drawn ov %': r.drawn, 'ideal ov %': r.ideal, 'ideal pairs committed overlapping': r.idealBadPairs }); return r; };

console.log('=== ISOLATION MATRIX  W=1950 H=1000, 9000 frames, node obstacles ON ===');
const base = push('SHIPPED: register cur, lerp 0.12', {});
push('register IDEAL (animation UNCHANGED)', { register: 'ideal' });
push('register UNION cur..ideal (proposed fix a)', { register: 'union' });
push('reset cur=ideal on re-appearance ONLY (register cur)', { resetOnAppear: true });
push('reset on re-appear + register ideal', { resetOnAppear: true, register: 'ideal' });
push('LERP=1 (claim\'s control: kills animation too)', { LERP: 1 });
console.table(t);

console.log('\nlag diagnostics (shipped config):');
console.log('  registration events:', base.regEvents, ' relayout frames:', base.relayoutFrames, '/9000');
console.log('  |ideal-cur| > 50px at registration, label had JUST re-appeared:', base.bigLagAppear);
console.log('  |ideal-cur| > 50px at registration, label was already visible :', base.bigLagSteady);
console.log('  candidate rejections caused by a LAYOUT NODE obstacle:', base.obstacleHits);

console.log('\n=== frame 119 dump (shipped config) ===');
const d = sim({ W, H, dumpFrame: 119 });
console.log('visChanged=', d.dump.visChanged);
console.log('ideals :', d.dump.ideals.join('  '));
console.log('drawn  :', d.dump.drawn.join('  '));

console.log('\n=== register-ideal isolation at other viewports ===');
const t2 = [];
for (const [w, h] of [[1233, 750], [1400, 900], [1280, 800], [800, 700]]) {
  const a = sim({ W: w, H: h }), b = sim({ W: w, H: h, register: 'ideal' }), c = sim({ W: w, H: h, register: 'ideal', resetOnAppear: true });
  t2.push({ vp: `${w}x${h}`, shipped: a.drawn + '% / ' + a.ideal + '%', 'register ideal': b.drawn + '% / ' + b.ideal + '%', '+reset on appear': c.drawn + '% / ' + c.ideal + '%' });
}
console.table(t2);
