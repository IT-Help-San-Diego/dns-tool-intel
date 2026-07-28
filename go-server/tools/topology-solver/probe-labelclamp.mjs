// Adversarial probe for the "edge-label viewport clamp margin (30/20) is
// smaller than the pill half-size" claim (topology.js:1561-1562).
//
// Method: evaluate the REAL go-server/static/js/topology.js in a stubbed
// canvas/DOM, but with a one-line recorder spliced in immediately BEFORE the
// two clamp statements. That gives the PRE-clamp lx/ly plus the measured
// pw/ph for every edge label that is actually drawn. Nothing about the
// placement algorithm is reimplemented.
//
// FORCE_ALL=1 additionally rewrites the label gate
//     if (e.label && (isHL || e.type !== 'flow'))
// to render flow-edge labels too (normally hover-only), to widen coverage.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
const OUT = path.join(ROOT, 'go-server/tools/topology-solver/output');
const SRC = path.join(ROOT, 'go-server/static/js/topology.js');

const AFM = { ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278, '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556, '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556, '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, '[': 278, ']': 278, '_': 556, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '—': 1000 };
const FUDGE = Number(process.env.FUDGE || 1);
function textWidth(text, fontSize) {
  let u = 0;
  for (const ch of String(text)) u += (AFM[ch] !== undefined ? AFM[ch] : 556);
  return (u / 1000) * fontSize * FUDGE;
}

const CLAMP_ANCHOR = `                ly = Math.max(20, Math.min(H - 20, ly));
                lx = Math.max(30, Math.min(W - 30, lx));`;
const GATE_ANCHOR = `if (e.label && (isHL || e.type !== 'flow')) {`;

function instrument(src, forceAll) {
  if (!src.includes(CLAMP_ANCHOR)) throw new Error('clamp anchor not found - source changed');
  let out = src.replace(CLAMP_ANCHOR,
    `                globalThis.__CLAMPREC.push({ label: e.label, type: e.type, preLx: lx, preLy: ly, pw: pw, ph: ph });\n` + CLAMP_ANCHOR +
    `\n                globalThis.__CLAMPREC[globalThis.__CLAMPREC.length-1].postLx = lx;` +
    `\n                globalThis.__CLAMPREC[globalThis.__CLAMPREC.length-1].postLy = ly;`);
  if (forceAll) {
    if (!out.includes(GATE_ANCHOR)) throw new Error('gate anchor not found');
    out = out.replace(GATE_ANCHOR, `if (e.label) {`);
  }
  return out;
}

function runFrame(W, H, forceAll) {
  let font = '13px sans-serif';
  const logs = [];
  const ctx = new Proxy({}, {
    get(_t, prop) {
      switch (prop) {
        case 'font': return font;
        case 'measureText': return (t) => {
          const m = /(\d+(?:\.\d+)?)px/.exec(font);
          return { width: textWidth(t, m ? parseFloat(m[1]) : 13) };
        };
        case 'createLinearGradient':
        case 'createRadialGradient':
          return () => ({ addColorStop() {} });
        case 'canvas': return canvasEl;
        default: return () => {};
      }
    },
    set(_t, prop, val) { if (prop === 'font') font = val; return true; },
  });
  const rectOf = (w, h) => ({ left: 0, top: 0, width: w, height: h, right: w, bottom: h });
  const canvasEl = { width: 0, height: 0, getContext: () => ctx, addEventListener() {}, removeEventListener() {}, getBoundingClientRect: () => rectOf(W, H), style: {} };
  const wrapEl = { addEventListener() {}, removeEventListener() {}, appendChild() {}, getBoundingClientRect: () => rectOf(W, H), style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, querySelector: () => null, querySelectorAll: () => [] };
  const genericEl = () => ({ addEventListener() {}, removeEventListener() {}, appendChild() {}, remove() {}, getBoundingClientRect: () => rectOf(0, 0), style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, querySelector: () => null, querySelectorAll: () => [], children: [], dataset: {}, get innerHTML() { return ''; }, set innerHTML(_v) {}, get textContent() { return ''; }, set textContent(_v) {} });
  const doc = { hidden: false, getElementById: (id) => (id === 'topoCanvas' ? canvasEl : id === 'topoWrap' ? wrapEl : genericEl()), querySelector: () => null, querySelectorAll: () => [], createElement: () => genericEl(), addEventListener() {}, removeEventListener() {}, body: genericEl(), documentElement: genericEl() };
  const win = {
    devicePixelRatio: 1, innerWidth: W, innerHeight: H,
    location: { search: '?debug=bounds', href: 'http://x/topology?debug=bounds', pathname: '/topology' },
    addEventListener() {}, removeEventListener() {}, requestAnimationFrame: () => 0,
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
    performance: { now: () => 16.7 }, devicePixelRatio: 1,
    console: { log: (...a) => logs.push(a.join(' ')), warn() {}, error() {} },
    navigator: { userAgent: 'node' },
    fetch: () => Promise.resolve({ ok: false, json: () => Promise.resolve({}) }),
    ResizeObserver: undefined, URLSearchParams,
    Image: class { constructor() { this.width = 0; this.height = 0; this.complete = false; } set src(_v) {} addEventListener() {} },
    OffscreenCanvas: class { getContext() { return ctx; } },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  };
  const g = globalThis;
  const saved = {};
  const realConsole = g.console;
  for (const k of Object.keys(sandbox)) {
    saved[k] = { desc: Object.getOwnPropertyDescriptor(g, k) };
    Object.defineProperty(g, k, { value: sandbox[k], writable: true, configurable: true, enumerable: true });
  }
  g.__CLAMPREC = [];
  let dbg;
  try {
    (0, eval)(fs.readFileSync(path.join(ROOT, 'go-server/static/js/globe-core.js'), 'utf8'));
    (0, eval)(instrument(fs.readFileSync(SRC, 'utf8'), forceAll));
    dbg = g.__topoDbg || win.__topoDbg;
  } finally {
    for (const k of Object.keys(sandbox)) {
      if (saved[k].desc) Object.defineProperty(g, k, saved[k].desc); else delete g[k];
    }
    g.console = realConsole;
  }
  const rec = g.__CLAMPREC.slice();
  delete g.__CLAMPREC;
  return { rec, dbg, logs };
}

const FORCE_ALL = process.env.FORCE_ALL === '1';
const sizes = process.argv.length > 2
  ? [[+process.argv[2], +process.argv[3] || 900]]
  : [[2560, 1300], [1950, 1000], [1950, 700], [1600, 900], [1400, 800], [1330, 800],
     [1233, 750], [1024, 700], [999, 700], [900, 700], [800, 700], [700, 900],
     [600, 900], [500, 1000], [420, 900], [375, 812], [320, 700]];

console.log(`FORCE_ALL=${FORCE_ALL ? 1 : 0}  FUDGE=${FUDGE}`);
console.log('W    H    SCL   efont pwMax  hwMax  minLx   maxLx   leftGate rightGate  clampBound?  worstOverhang');
for (const [W, H] of sizes) {
  let out;
  try { out = runFrame(W, H, FORCE_ALL); }
  catch (e) { console.log(`${W} ${H}  HARNESS ERROR: ${e.message}`); continue; }
  const { rec, dbg } = out;
  if (!rec.length) { console.log(`${W} ${H}  no labels recorded`); continue; }
  const SCL = dbg ? dbg.scl : NaN;
  const pwMax = Math.max(...rec.map(r => r.pw));
  const minLx = Math.min(...rec.map(r => r.preLx));
  const maxLx = Math.max(...rec.map(r => r.preLx));
  const bound = rec.filter(r => r.preLx !== r.postLx || r.preLy !== r.postLy);
  // worst overhang = how far outside [0,W] the pill would extend AFTER clamping
  let worst = 0, worstLbl = '';
  for (const r of rec) {
    const over = Math.max(r.pw / 2 - r.postLx, (r.postLx + r.pw / 2) - W, 0);
    if (over > worst) { worst = over; worstLbl = r.label; }
  }
  const efont = (rec[0].ph - 8 * SCL).toFixed(1);
  console.log(
    `${String(W).padEnd(4)} ${String(H).padEnd(4)} ${SCL.toFixed(3)} ${String(efont).padEnd(5)} ` +
    `${pwMax.toFixed(1).padEnd(6)} ${(pwMax / 2).toFixed(1).padEnd(6)} ` +
    `${minLx.toFixed(1).padEnd(7)} ${maxLx.toFixed(1).padEnd(7)} ` +
    `${'30'.padEnd(8)} ${String(W - 30).padEnd(10)} ` +
    `${bound.length ? 'YES(' + bound.length + ')' : 'no'}`.padEnd(12) +
    ` ${worst.toFixed(2)}${worstLbl ? ' [' + worstLbl + ']' : ''}   n=${rec.length}`);
  if (bound.length) {
    for (const b of bound.slice(0, 6)) {
      console.log(`      bound: "${b.label}" pre=(${b.preLx.toFixed(1)},${b.preLy.toFixed(1)}) post=(${b.postLx.toFixed(1)},${b.postLy.toFixed(1)}) pw=${b.pw.toFixed(1)} ph=${b.ph.toFixed(1)}`);
    }
  }
}
