// Second half of the adversarial audit: does the phantom-output pinning
// actually HARM the rendered picture, or is the displacement cosmetic churn?
// Measures, per viewport: overlap-pass iteration count (does it converge?),
// visible-vs-visible AABB overlaps, and total displacement of visible nodes
// from their solver-remapped positions.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../..');
const TOPO_SRC = path.join(ROOT, 'go-server/static/js/topology.js');
const GLOBE_SRC = path.join(ROOT, 'go-server/static/js/globe-core.js');

const AFM = { ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278, '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556, '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556, '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944, 'X': 667, 'Y': 667, 'Z': 611, '[': 278, ']': 278, '_': 556, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500, '·': 333, '—': 1000, '°': 400, 'ã': 556, '×': 584 };

function makeCtx() {
  let fontSize = 10;
  const noop = () => {};
  const grad = { addColorStop: noop };
  return {
    set font(v) { const m = /(\d+(?:\.\d+)?)px/.exec(String(v)); if (m) fontSize = parseFloat(m[1]); this._font = v; },
    get font() { return this._font; },
    measureText(t) { let u = 0; for (const ch of String(t)) u += (AFM[ch] !== undefined ? AFM[ch] : 556); return { width: (u / 1000) * fontSize }; },
    createLinearGradient: () => grad, createRadialGradient: () => grad, createPattern: () => null,
    getImageData: () => ({ data: new Uint8ClampedArray(4) }), putImageData: noop, drawImage: noop,
    setTransform: noop, save: noop, restore: noop, beginPath: noop, closePath: noop,
    moveTo: noop, lineTo: noop, arc: noop, arcTo: noop, ellipse: noop, rect: noop,
    quadraticCurveTo: noop, bezierCurveTo: noop, fill: noop, stroke: noop,
    fillRect: noop, strokeRect: noop, clearRect: noop, clip: noop,
    fillText: noop, strokeText: noop, setLineDash: noop, getLineDash: () => [],
    translate: noop, rotate: noop, scale: noop,
  };
}
function makeEl(id, ctx, sizeRef) {
  const el = {
    id, tagName: 'DIV', className: '', textContent: '', innerHTML: '', value: '',
    style: {}, dataset: {}, title: '', type: '', href: '', checked: false, hidden: false, width: 0, height: 0,
    classList: { add: () => {}, remove: () => {}, toggle: () => {}, contains: () => false },
    getContext: () => ctx,
    getBoundingClientRect: () => ({ width: sizeRef.W, height: sizeRef.H, top: 0, left: 0, right: sizeRef.W, bottom: sizeRef.H }),
    addEventListener: () => {}, removeEventListener: () => {},
    appendChild: (c) => c, insertBefore: (c) => c, removeChild: (c) => c,
    setAttribute: () => {}, removeAttribute: () => {}, getAttribute: () => null,
    querySelector: () => null, querySelectorAll: () => [],
    focus: () => {}, blur: () => {}, click: () => {}, remove: () => {},
    closest: () => null, scrollIntoView: () => {},
    get parentNode() { return el; }, get firstChild() { return null; }, get children() { return []; },
  };
  return el;
}

const C_ANCHOR = `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);`;
const LOOP_ANCHOR = `            let overlapPad = 14;
            for (let op = 0; op < 40; op++) {`;

function run({ W, H, fixC = false }) {
  const sizeRef = { W, H };
  const ctx = makeCtx();
  const els = {};
  const doc = {
    hidden: false,
    getElementById: (id) => (els[id] = els[id] || makeEl(id, ctx, sizeRef)),
    createElement: (t) => makeEl('created-' + t, ctx, sizeRef),
    addEventListener: () => {}, removeEventListener: () => {},
    querySelector: () => null, querySelectorAll: () => [],
    body: makeEl('body', ctx, sizeRef), documentElement: makeEl('html', ctx, sizeRef),
  };
  const win = {
    devicePixelRatio: 1,
    location: { search: '', href: 'https://x/topology', pathname: '/topology' },
    addEventListener: () => {}, removeEventListener: () => {},
    requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    matchMedia: () => ({ matches: false, addListener: () => {}, addEventListener: () => {} }),
    fetch: () => new Promise(() => {}),
    __TOPO_SOLVER: {
      desktop: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/desktop-layout.json'), 'utf8')),
      tablet: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/tablet-layout.json'), 'utf8')),
      mobile: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/mobile-layout.json'), 'utf8')),
    },
    __FIXTURE_CORPUS: null, __TOPO_REPLAY: null,
  };
  const sandbox = {
    window: win, document: doc, console: { log: () => {}, warn: () => {}, error: () => {} },
    requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    fetch: () => new Promise(() => {}),
    Image: function () { this.onload = null; return this; },
    ResizeObserver: undefined, performance: { now: () => 0 }, location: win.location,
    navigator: { userAgent: 'node', clipboard: { writeText: () => Promise.resolve() } },
    history: { replaceState: () => {}, pushState: () => {} },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    alert: () => {}, getComputedStyle: () => ({ getPropertyValue: () => '' }),
  };

  let src = fs.readFileSync(TOPO_SRC, 'utf8');
  const globeSrc = fs.readFileSync(GLOBE_SRC, 'utf8');
  if (fixC) {
    if (!src.includes(C_ANCHOR)) throw new Error('C anchor missing');
    src = src.replace(C_ANCHOR, `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS);`);
  }
  src = src.replace("                    if (stack.length < 2) return;",
                    "                    if (stack.length < 2) return;\n                    (window.__STACKS = window.__STACKS || []).push(stack.slice());");
  // snapshot positions right before the overlap pass, and count iterations
  if (!src.includes(LOOP_ANCHOR)) throw new Error('loop anchor missing');
  src = src.replace(LOOP_ANCHOR,
`            window.__PRE = allLayoutNodes.map(function(n){ return {id:n.id, x:n.targetX, y:n.targetY}; });
            window.__ITER = 0;
            let overlapPad = 14;
            for (let op = 0; op < 40; op++) {
                window.__ITER = op + 1;`);

  const tail = `        loop();\n    })();`;
  src = src.replace(tail, `
        window.__T = { resize: resize, get allLayoutNodes() { return allLayoutNodes; }, OUTPUTS: OUTPUTS };
    })();`);
  const fn = new Function(...Object.keys(sandbox), 'GC', 'TS', `eval(GC); eval(TS);`);
  fn(...Object.values(sandbox), globeSrc, src);
  const T = win.__T;
  T.resize();
  const nodes = {};
  T.allLayoutNodes.forEach((n) => { nodes[n.id] = { zone: n.zone, x: n.x, y: n.y, hw: n._halfW || n.radius, hh: n._halfH || n.radius }; });
  T.OUTPUTS.forEach((n) => { nodes[n.id] = { zone: 'output', x: n.targetX, y: n.targetY, hw: n._halfW || n.radius, hh: n._halfH || n.radius }; });
  const pre = {}; win.__PRE.forEach((p) => { pre[p.id] = p; });
  return { nodes, pre, iters: win.__ITER, stacks: win.__STACKS || [] };
}

const VISIBLE = ['root','rdap','ct','cisa','probes','hub','engine','ietf','icae','icuae','ede',
                 'postgres','fixtures','wayback','spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'];

function visOverlaps(nodes) {
  let n = 0, worst = 0, pairs = [];
  for (let i = 0; i < VISIBLE.length; i++) for (let j = i + 1; j < VISIBLE.length; j++) {
    const a = nodes[VISIBLE[i]], b = nodes[VISIBLE[j]];
    if (!a || !b) continue;
    const ox = Math.min(a.x + a.hw, b.x + b.hw) - Math.max(a.x - a.hw, b.x - b.hw);
    const oy = Math.min(a.y + a.hh, b.y + b.hh) - Math.max(a.y - a.hh, b.y - b.hh);
    if (ox > 0 && oy > 0) { n++; const d = Math.min(ox, oy); if (d > worst) worst = d; pairs.push(VISIBLE[i] + '/' + VISIBLE[j] + ':' + d.toFixed(0)); }
  }
  return { n, worst, pairs };
}
function driftFromSolver(res) {
  let tot = 0, worst = 0, id = '';
  for (const k of VISIBLE) {
    if (!res.nodes[k] || !res.pre[k]) continue;
    const d = Math.hypot(res.nodes[k].x - res.pre[k].x, res.nodes[k].y - res.pre[k].y);
    tot += d; if (d > worst) { worst = d; id = k; }
  }
  return { tot, worst, id };
}

for (const [W, H] of [[1950,900],[1600,900],[1512,900],[1440,900],[1233,750],[1024,750],[800,750],[420,900]]) {
  const A = run({ W, H });
  const C = run({ W, H, fixC: true });
  const oa = visOverlaps(A.nodes), oc = visOverlaps(C.nodes);
  const da = driftFromSolver(A), dc = driftFromSolver(C);
  console.log(`W=${W} H=${H}  repartition stacks: ${JSON.stringify(A.stacks)}`);
  console.log(`   shipped : iters=${A.iters}/40  visible-overlap pairs=${oa.n} worst=${oa.worst.toFixed(1)}px  drift-from-solver total=${da.tot.toFixed(0)}px worst=${da.worst.toFixed(1)}px (${da.id})`);
  console.log(`   no-OUTPUT: iters=${C.iters}/40  visible-overlap pairs=${oc.n} worst=${oc.worst.toFixed(1)}px  drift-from-solver total=${dc.tot.toFixed(0)}px worst=${dc.worst.toFixed(1)}px (${dc.id})`);
  for (const k of VISIBLE) {
    const a=A.nodes[k], c=C.nodes[k];
    const dx=a.x-c.x, dy=a.y-c.y;
    if (Math.hypot(dx,dy) > 0.05) console.log(`     phantom effect on ${k}: d=(${dx.toFixed(1)}, ${dy.toFixed(1)})`);
  }
  if (oa.pairs.length) console.log(`     shipped pairs: ${oa.pairs.join(', ')}`);
  if (oc.pairs.length) console.log(`     no-OUTPUT pairs: ${oc.pairs.join(', ')}`);
}
