// Is the SERVED file (static/js/topology.min.js — templates/topology.html:547)
// in sync with the audited source (static/js/topology.js)?
// Evaluates each in the same stubbed DOM with ?debug=bounds and diffs the
// window.__topoDbg layout snapshot the client itself produces.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
const AFM = { ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278, '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556, '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556, '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, '[': 278, ']': 278, '_': 556, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '—': 1000, '°': 400, 'ã': 556, '×': 584 };

function snapshot(file, W, H) {
  let fontSize = 10;
  const noop = () => {};
  const grad = { addColorStop: noop };
  const ctx = new Proxy({
    set font(v) { const m = /(\d+(?:\.\d+)?)px/.exec(String(v)); if (m) fontSize = parseFloat(m[1]); },
    get font() { return fontSize + 'px x'; },
    measureText(t) { let u = 0; for (const c of String(t)) u += (AFM[c] !== undefined ? AFM[c] : 556); return { width: (u / 1000) * fontSize }; },
    createLinearGradient: () => grad, createRadialGradient: () => grad,
    createPattern: () => null, getImageData: () => ({ data: new Uint8ClampedArray(4) }),
    getLineDash: () => [],
  }, { get(t, p) { if (p in t) return t[p]; return noop; }, set() { return true; } });

  const mk = (id) => {
    const e = { id, style: {}, dataset: {}, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
      getContext: () => ctx, getBoundingClientRect: () => ({ width: W, height: H, top: 0, left: 0, right: W, bottom: H }),
      addEventListener: noop, removeEventListener: noop, appendChild: (c) => c, insertBefore: (c) => c,
      removeChild: (c) => c, setAttribute: noop, removeAttribute: noop, getAttribute: () => null,
      querySelector: () => null, querySelectorAll: () => [], focus: noop, blur: noop, click: noop,
      remove: noop, closest: () => null, scrollIntoView: noop, textContent: '', innerHTML: '', value: '',
      width: 0, height: 0, hidden: false, title: '', type: '', className: '' };
    e.parentNode = e; return e;
  };
  const els = {};
  const doc = { hidden: false, getElementById: (id) => (els[id] = els[id] || mk(id)), createElement: (t) => mk(t),
    addEventListener: noop, removeEventListener: noop, querySelector: () => null, querySelectorAll: () => [],
    body: mk('body'), documentElement: mk('html') };
  const loc = { search: '?debug=bounds', href: 'https://x/topology?debug=bounds', pathname: '/topology' };
  const win = { devicePixelRatio: 1, location: loc, addEventListener: noop, removeEventListener: noop,
    requestAnimationFrame: () => 0, cancelAnimationFrame: noop, setTimeout: () => 0, clearTimeout: noop,
    setInterval: () => 0, clearInterval: noop, matchMedia: () => ({ matches: false, addListener: noop, addEventListener: noop }),
    fetch: () => new Promise(() => {}),
    __TOPO_SOLVER: {
      desktop: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/desktop-layout.json'), 'utf8')),
      tablet: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/tablet-layout.json'), 'utf8')),
      mobile: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/mobile-layout.json'), 'utf8')),
    }, __FIXTURE_CORPUS: null, __TOPO_REPLAY: null };

  const env = { window: win, document: doc, console: { log: noop, warn: noop, error: noop },
    requestAnimationFrame: () => 0, cancelAnimationFrame: noop, setTimeout: () => 0, clearTimeout: noop,
    setInterval: () => 0, clearInterval: noop, fetch: () => new Promise(() => {}),
    Image: function () { return this; }, ResizeObserver: undefined, performance: { now: () => 0 },
    location: loc, navigator: { userAgent: 'node', clipboard: { writeText: () => Promise.resolve() } },
    history: { replaceState: noop, pushState: noop },
    localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
    alert: noop, getComputedStyle: () => ({ getPropertyValue: () => '' }) };

  const gc = fs.readFileSync(path.join(ROOT, 'go-server/static/js/globe-core.js'), 'utf8');
  const js = fs.readFileSync(file, 'utf8');
  const fn = new Function(...Object.keys(env), 'GCS', 'JS', 'eval(GCS); eval(JS);');
  fn(...Object.values(env), gc, js);
  return win.__topoDbg;
}

const A = snapshot(path.join(ROOT, 'go-server/static/js/topology.js'), 1918, 900);
const B = snapshot(path.join(ROOT, 'go-server/static/js/topology.min.js'), 1918, 900);
console.log('source  __topoDbg:', A ? `W=${A.W} solver=${A.solver} nodes=${A.nodes.length}` : 'ABSENT');
console.log('minified __topoDbg:', B ? `W=${B.W} solver=${B.solver} nodes=${B.nodes.length}` : 'ABSENT');
if (A && B) {
  const bm = Object.fromEntries(B.nodes.map((n) => [n.id, n]));
  let worst = 0, worstId = '', missing = [];
  for (const n of A.nodes) {
    const m = bm[n.id];
    if (!m) { missing.push(n.id); continue; }
    const d = Math.hypot(n.x - m.x, n.y - m.y);
    if (d > worst) { worst = d; worstId = n.id; }
  }
  console.log('missing in min:', missing.length ? missing.join(',') : 'none');
  console.log(`max node-position divergence source vs minified: ${worst.toFixed(2)}px (${worstId})`);
  console.log('zones equal:', JSON.stringify(A.zones) === JSON.stringify(B.zones));
}
