// Adversarial verification harness for the edge-label node-avoidance claim.
//
// Rather than re-porting the algorithm (which is how prior audits went wrong),
// this EVALUATES THE REAL go-server/static/js/topology.js inside a stubbed
// canvas/DOM, drives one real frame, and records:
//   - every ctx.fillText() call (edge label pills land here)
//   - the debugBounds strokeRect() pass at the end of draw(), which emits
//     each layout node's AABB at its true draw-time x/y
// Nothing about the placement algorithm is reimplemented.
//
// Usage: node verify-edgelabel-sweep.mjs [W H] ...
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
const OUT = path.join(ROOT, 'go-server/tools/topology-solver/output');

// Helvetica AFM advance widths (units/1000). Canvas in Safari uses
// -apple-system; Helvetica is the closest metric-compatible stand-in and only
// affects PILL WIDTH, not the circle-escape geometry under test.
const AFM = { ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278, '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556, '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556, '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, '[': 278, ']': 278, '_': 556, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '—': 1000, '·': 333 };

function textWidth(text, fontSize) {
  let u = 0;
  for (const ch of String(text)) u += (AFM[ch] !== undefined ? AFM[ch] : 556);
  return (u / 1000) * fontSize;
}

function runFrame(W, H) {
  const rec = { fillTexts: [], dashRects: [], dashOn: false, logs: [] };
  let font = '13px sans-serif';

  const ctx = new Proxy({}, {
    get(_t, prop) {
      switch (prop) {
        case 'font': return font;
        case 'measureText': return (t) => {
          const m = /(\d+(?:\.\d+)?)px/.exec(font);
          return { width: textWidth(t, m ? parseFloat(m[1]) : 13) };
        };
        case 'fillText': return (t, x, y) => rec.fillTexts.push({ t: String(t), x, y, font });
        case 'setLineDash': return (a) => { rec.dashOn = Array.isArray(a) && a.length === 2 && a[0] === 3 && a[1] === 3; };
        case 'strokeRect': return (x, y, w, h) => { if (rec.dashOn) rec.dashRects.push({ x, y, w, h }); };
        case 'createLinearGradient':
        case 'createRadialGradient':
          return () => ({ addColorStop() {} });
        case 'canvas': return canvasEl;
        default: return () => {};
      }
    },
    set(_t, prop, val) { if (prop === 'font') font = val; return true; },
  });

  const canvasEl = {
    width: 0, height: 0,
    getContext: () => ctx,
    addEventListener() {}, removeEventListener() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: W, height: H, right: W, bottom: H }),
    style: {},
  };
  const wrapEl = {
    addEventListener() {}, removeEventListener() {}, appendChild() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: W, height: H, right: W, bottom: H }),
    style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    querySelector: () => null, querySelectorAll: () => [],
  };
  const genericEl = () => ({
    addEventListener() {}, removeEventListener() {}, appendChild() {}, remove() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0 }),
    style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    querySelector: () => null, querySelectorAll: () => [], children: [], dataset: {},
    get innerHTML() { return ''; }, set innerHTML(_v) {},
    get textContent() { return ''; }, set textContent(_v) {},
  });

  const doc = {
    hidden: false,
    getElementById: (id) => (id === 'topoCanvas' ? canvasEl : id === 'topoWrap' ? wrapEl : genericEl()),
    querySelector: () => null, querySelectorAll: () => [],
    createElement: () => genericEl(),
    addEventListener() {}, removeEventListener() {},
    body: genericEl(), documentElement: genericEl(),
  };

  const win = {
    devicePixelRatio: 1,
    innerWidth: W, innerHeight: H,
    location: { search: '?debug=bounds', href: 'http://x/topology?debug=bounds', pathname: '/topology' },
    addEventListener() {}, removeEventListener() {},
    requestAnimationFrame: () => 0,
    matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    __TOPO_SOLVER: {
      desktop: JSON.parse(fs.readFileSync(path.join(OUT, 'desktop-layout.json'), 'utf8')),
      tablet: JSON.parse(fs.readFileSync(path.join(OUT, 'tablet-layout.json'), 'utf8')),
      mobile: JSON.parse(fs.readFileSync(path.join(OUT, 'mobile-layout.json'), 'utf8')),
    },
  };

  const sandbox = {
    window: win, document: doc, location: win.location,
    requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    performance: { now: () => 16.7 },
    devicePixelRatio: 1,
    console: { log: (...a) => rec.logs.push(a.join(' ')), warn() {}, error() {} },
    navigator: { userAgent: 'node' },
    fetch: () => Promise.resolve({ ok: false, json: () => Promise.resolve({}) }),
    ResizeObserver: undefined,
    URLSearchParams,
    Image: class { constructor() { this.width = 0; this.height = 0; this.complete = false; } set src(_v) {} addEventListener() {} },
    OffscreenCanvas: class { constructor() {} getContext() { return ctx; } },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  };

  const g = globalThis;
  const saved = {};
  const realConsole = g.console;
  // Some globals (navigator, performance) are non-writable accessors on modern
  // Node; plain assignment throws under module strict mode. defineProperty works.
  for (const k of Object.keys(sandbox)) {
    saved[k] = { had: k in g, val: g[k], desc: Object.getOwnPropertyDescriptor(g, k) };
    Object.defineProperty(g, k, { value: sandbox[k], writable: true, configurable: true, enumerable: true });
  }
  const restore = () => {
    for (const k of Object.keys(sandbox)) {
      const s = saved[k];
      if (s.desc) Object.defineProperty(g, k, s.desc);
      else delete g[k];
    }
    g.console = realConsole;
  };
  let dbg;
  try {
    // globe-core.js is an IIFE assigning globalThis.GlobeCore.
    (0, eval)(fs.readFileSync(path.join(ROOT, 'go-server/static/js/globe-core.js'), 'utf8'));
    (0, eval)(fs.readFileSync(path.join(ROOT, process.env.TOPO_SRC || 'go-server/static/js/topology.js'), 'utf8'));
    dbg = g.__topoDbg || win.__topoDbg;
  } finally {
    restore();
  }
  return { rec, dbg };
}

// allLayoutNodes order, hardcoded from topology.js:1053 for labelling only.
const ORDER = ['root', 'rdap', 'ct', 'cisa', 'probe', 'hub', 'engine',
  'ede', 'ietf', 'consensus', 'archive',
  'postgres', 'fixtures', 'wayback',
  'spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa',
  'reports', 'jsonapi', 'seo', 'badges'];

const PROTO_SEQ = ['alignment', 'alignment', 'requires', 'p=quarantine+', 'reports', 'reports', 'strengthens'];
const PROTO_EDGES = [
  ['dmarc', 'spf'], ['dmarc', 'dkim'], ['dane', 'dnssec'], ['bimi', 'dmarc'],
  ['tlsrpt', 'mtasts'], ['tlsrpt', 'dane'], ['caa', 'dnssec']];

function findSeq(texts, seq) {
  for (let i = 0; i + seq.length <= texts.length; i++) {
    let ok = true;
    for (let j = 0; j < seq.length; j++) if (texts[i + j].t !== seq[j]) { ok = false; break; }
    if (ok) return i;
  }
  return -1;
}

const PROTOS_G = ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'];

if (process.env.ZONES) {
  const H = +(process.env.SWEEP_H || 900);
  console.log('   W  | SCL  | protocol zone x1..x2 (w) | padX=52*SCL | tx2-tx1 | X-spread fires? (needs >40) | zone y1..y2 (h) | 9 circles need 9*72+8*14=760');
  for (let W = 900; W <= 2100; W += 50) {
    const { dbg } = runFrame(W, H);
    const z = dbg.zones.protocol; const scl = dbg.scl;
    const zw = z.x2 - z.x1, padX = 52 * scl, padY = 44 * scl;
    const tx = zw - 2 * padX, ty = (z.y2 - z.y1) - 2 * padY;
    console.log(`${String(W).padStart(5)} | ${scl.toFixed(2)} | ${z.x1.toFixed(0)}..${z.x2.toFixed(0)} (${zw.toFixed(0)}) | ${padX.toFixed(0)} | ${tx.toFixed(1).padStart(7)} | ${tx > 40 ? 'YES' : 'NO '} | ${z.y1.toFixed(0)}..${z.y2.toFixed(0)} (${(z.y2 - z.y1).toFixed(0)}) | Yspread ${ty > 40 ? 'YES' : 'NO'}`);
  }
  process.exit(0);
}

if (process.env.SWEEP) {
  const H = +(process.env.SWEEP_H || 900);
  console.log(`width sweep at H=${H}   (protoMinSep = closest protocol-circle pair; 2*r = 72)`);
  console.log('   W  | SCL  | protoMinSep | pills overlapping a protocol circle | pills containing a node centre');
  for (let W = 700; W <= 2100; W += 25) {
    let out; try { out = runFrame(W, H); } catch (e) { console.log(`${String(W).padStart(5)} ERROR ${e.message}`); continue; }
    const { rec, dbg } = out;
    const nodes = {};
    rec.dashRects.forEach((r, i) => { nodes[ORDER[i] || ('#' + i)] = { x: r.x + r.w / 2, y: r.y + r.h / 2, hw: r.w / 2, hh: r.h / 2 }; });
    let minSep = Infinity;
    for (let i = 0; i < 9; i++) for (let j = i + 1; j < 9; j++) {
      const a = nodes[PROTOS_G[i]], b = nodes[PROTOS_G[j]];
      if (a && b) minSep = Math.min(minSep, Math.hypot(a.x - b.x, a.y - b.y));
    }
    const start = findSeq(rec.fillTexts, PROTO_SEQ);
    let onCircle = [], containing = [];
    if (start >= 0) {
      for (let k = 0; k < 7; k++) {
        const ft = rec.fillTexts[start + k];
        const m = /(\d+(?:\.\d+)?)px/.exec(ft.font); const fs2 = m ? parseFloat(m[1]) : 12;
        const SCL = dbg ? dbg.scl : 1;
        const pw = textWidth(ft.t, fs2) + 10 * SCL, ph = fs2 + 8 * SCL;
        for (const p of PROTOS_G) {
          const n = nodes[p]; if (!n) continue;
          // true disc-vs-pill test against the DRAWN circle (radius 36), not the AABB
          const cx = Math.max(ft.x - pw / 2, Math.min(n.x, ft.x + pw / 2));
          const cy = Math.max(ft.y - ph / 2, Math.min(n.y, ft.y + ph / 2));
          if (Math.hypot(n.x - cx, n.y - cy) < 36) { onCircle.push(`${ft.t}/${p}`); }
          if (Math.abs(n.x - ft.x) <= pw / 2 && Math.abs(n.y - ft.y) <= ph / 2) containing.push(`${ft.t}/${p}`);
        }
      }
    }
    console.log(`${String(W).padStart(5)} | ${(dbg ? dbg.scl : 0).toFixed(2)} | ${minSep.toFixed(1).padStart(11)} | ${String(onCircle.length).padStart(2)}  ${onCircle.slice(0, 4).join(' ')}${onCircle.length > 4 ? ' …' : ''}`.padEnd(100) + ` | ${containing.join(' ') || '-'}`);
  }
  process.exit(0);
}

const sizes = process.argv.length > 2
  ? [[+process.argv[2], +process.argv[3]]]
  : [[1950, 1000], [1950, 900], [1600, 900], [1400, 800], [1233, 750], [1024, 700], [800, 700]];

for (const [W, H] of sizes) {
  let out;
  try { out = runFrame(W, H); }
  catch (err) { console.log(`W=${W} H=${H}  HARNESS ERROR: ${err.message}`); continue; }
  const { rec, dbg } = out;

  const nodes = {};
  rec.dashRects.forEach((r, i) => {
    const id = ORDER[i] || ('#' + i);
    nodes[id] = { id, x: r.x + r.w / 2, y: r.y + r.h / 2, hw: r.w / 2, hh: r.h / 2 };
  });
  if (dbg && dbg.boxes) dbg.boxes.forEach((b, i) => { const n = nodes[ORDER[i]]; if (n) n.zone = b.zone; });

  const start = findSeq(rec.fillTexts, PROTO_SEQ);
  console.log(`\n===== W=${W} H=${H}  solver=${dbg ? dbg.solver : '?'} SCL=${dbg ? dbg.scl : '?'} nodesCaptured=${rec.dashRects.length} =====`);
  if (dbg) console.log(`  logs: ${rec.logs.join(' | ')}`);
  if (start < 0) { console.log('  !! could not locate the 7 proto edge labels among fillText calls'); continue; }

  // Circle geometry of the 9 protocol nodes as actually drawn this frame.
  const PROTOS = ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'];
  console.log('  protocol circle centres (draw-time):');
  PROTOS.forEach((p) => {
    const n = nodes[p];
    if (n) console.log(`    ${p.padEnd(7)} (${n.x.toFixed(1)}, ${n.y.toFixed(1)})  hw=${n.hw.toFixed(1)} hh=${n.hh.toFixed(1)}`);
  });

  // Nearest-neighbour spacing among protocol circles, to test the "86 apart" premise.
  let minSep = Infinity, minPair = '';
  for (let i = 0; i < PROTOS.length; i++) for (let j = i + 1; j < PROTOS.length; j++) {
    const a = nodes[PROTOS[i]], b = nodes[PROTOS[j]];
    if (!a || !b) continue;
    const d = Math.hypot(a.x - b.x, a.y - b.y);
    if (d < minSep) { minSep = d; minPair = PROTOS[i] + '/' + PROTOS[j]; }
  }
  console.log(`  closest protocol pair: ${minPair} at ${minSep.toFixed(1)}px (2*r = 72)`);

  console.log('  edge label pills:');
  for (let k = 0; k < 7; k++) {
    const ft = rec.fillTexts[start + k];
    const m = /(\d+(?:\.\d+)?)px/.exec(ft.font);
    const fs2 = m ? parseFloat(m[1]) : 12;
    const SCL = dbg ? dbg.scl : 1;
    const pw = textWidth(ft.t, fs2) + 10 * SCL;
    const ph = fs2 + 8 * SCL;
    const [ef, et] = PROTO_EDGES[k];
    // Which nodes does the pill rect actually collide with?
    const hits = [];
    for (const id of Object.keys(nodes)) {
      const n = nodes[id];
      const ox = Math.min(ft.x + pw / 2, n.x + n.hw) - Math.max(ft.x - pw / 2, n.x - n.hw);
      const oy = Math.min(ft.y + ph / 2, n.y + n.hh) - Math.max(ft.y - ph / 2, n.y - n.hh);
      if (ox > 0 && oy > 0) hits.push(`${id}(${ox.toFixed(0)}x${oy.toFixed(0)})`);
    }
    // Does the pill CONTAIN a node centre? (the claim's headline assertion)
    const contains = Object.keys(nodes).filter((id) => {
      const n = nodes[id];
      return Math.abs(n.x - ft.x) <= pw / 2 && Math.abs(n.y - ft.y) <= ph / 2;
    });
    // distance from the pill centre to each endpoint circle centre
    const df = nodes[ef] ? Math.hypot(ft.x - nodes[ef].x, ft.y - nodes[ef].y) : NaN;
    const dt = nodes[et] ? Math.hypot(ft.x - nodes[et].x, ft.y - nodes[et].y) : NaN;
    console.log(`    "${ft.t}" ${ef}->${et}  pill(${ft.x.toFixed(1)},${ft.y.toFixed(1)}) ${pw.toFixed(0)}x${ph.toFixed(0)}`);
    console.log(`        dist to ${ef}=${df.toFixed(1)}  to ${et}=${dt.toFixed(1)}   AABB hits: [${hits.join(', ') || 'none'}]`);
    console.log(`        contains node centre: [${contains.join(', ') || 'none'}]`);
  }
}
