// INDEPENDENT adversarial audit of the claim:
//   "the 'output' zone's x-bounds are inverted (col4L = pipeEnd + colGap,
//    col4R = pipeEnd) at every viewport, pinning 4 never-drawn nodes at
//    pipeEnd-10, inside the protocol column, where they displace visible
//    protocol circles."
//
// Loads the REAL shipped topology.js with the REAL solver payload, and runs
// five variants:
//   base   - shipped
//   fixA   - proposed fix (a): no colGap when c4w == 0  (col4L = col3R)
//   fixB   - proposed fix (b): degenerate-band guard on the overlap-pass clamp
//   fixAB  - both
//   fixC   - build allLayoutNodes without the hidden OUTPUTS
// and reports, per viewport: the column arithmetic, the final x of every
// output node, and the displacement of every VISIBLE node vs. base.
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

const A_ANCHOR = `            let col4L = col3R + colGap;`;
const B_ANCHOR = `                        nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
                        nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));`;
const C_ANCHOR = `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);`;

function run({ W, H, fixA = false, fixB = false, fixC = false }) {
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

  if (fixA) {
    if (!src.includes(A_ANCHOR)) throw new Error('A anchor missing');
    src = src.replace(A_ANCHOR, `            let col4L = c4w > 0 ? col3R + colGap : col3R;`);
  }
  if (fixB) {
    if (!src.includes(B_ANCHOR)) throw new Error('B anchor missing');
    src = src.replace(B_ANCHOR,
`                        if (z.bounds.x1 + zHw <= z.bounds.x2 - zHw) {
                            nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
                        }
                        if (z.bounds.y1 + zHh <= z.bounds.y2 - zHh) {
                            nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));
                        }`);
  }
  if (fixC) {
    if (!src.includes(C_ANCHOR)) throw new Error('C anchor missing');
    src = src.replace(C_ANCHOR, `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS);`);
  }

  // expose the column arithmetic straight out of layoutAll
  const DBG_ANCHOR = `            let globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };`;
  if (!src.includes(DBG_ANCHOR)) throw new Error('dbg anchor missing');
  src = src.replace(DBG_ANCHOR, DBG_ANCHOR + `
            window.__COLS = { pipeStart: pipeStart, pipeEnd: pipeEnd, pipeTotal: pipeTotal, colGap: colGap,
                              c1w: c1w, c2w: c2w, c3w: c3w, c4w: c4w,
                              col1L: col1L, col1R: col1R, col2L: col2L, col2R: col2R,
                              col3L: col3L, col3R: col3R, col4L: col4L, col4R: col4R,
                              consoleReserve: consoleReserve, SCL: SCL };`);

  const tail = `        loop();\n    })();`;
  if (!src.includes(tail)) throw new Error('tail anchor missing');
  src = src.replace(tail, `
        window.__T = { resize: resize, get W() { return W; }, get SCL() { return SCL; },
                       get SOLVER_ACTIVE() { return SOLVER_ACTIVE; },
                       get allLayoutNodes() { return allLayoutNodes; },
                       OUTPUTS: OUTPUTS, get SHOW_OUTPUTS() { return SHOW_OUTPUTS; } };
    })();`);

  const fn = new Function(...Object.keys(sandbox), 'GC', 'TS', `eval(GC); eval(TS);`);
  fn(...Object.values(sandbox), globeSrc, src);
  const T = win.__T;
  T.resize();
  const nodes = {};
  T.allLayoutNodes.forEach((n) => { nodes[n.id] = { zone: n.zone, x: n.x, y: n.y, hw: n._halfW || n.radius, hh: n._halfH || n.radius }; });
  // outputs are dropped from allLayoutNodes under fixC; read them directly
  T.OUTPUTS.forEach((n) => { nodes[n.id] = { zone: n.zone, x: n.targetX, y: n.targetY, hw: n._halfW || n.radius, hh: n._halfH || n.radius }; });
  return { cols: win.__COLS, nodes, solver: T.SOLVER_ACTIVE, showOutputs: T.SHOW_OUTPUTS, SCL: T.SCL };
}

const VISIBLE = ['root','rdap','ct','cisa','probes','hub','engine','ietf','icae','icuae','ede',
                 'postgres','fixtures','wayback','spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'];
const OUTS = ['reports','jsonapi','seo','badges'];

const VIEWPORTS = (process.env.VP ? JSON.parse(process.env.VP) : [
  [1950, 900], [1600, 900], [1512, 900], [1512, 850], [1440, 900],
  [1233, 750], [1024, 750], [1000, 900], [999, 900], [800, 750], [420, 900],
]);
if (process.env.PROBEA) {
  for (const [W,H] of VIEWPORTS) {
    const b = run({W,H}); const a = run({W,H,fixA:true});
    console.log(`W=${W} H=${H}  base col4w=${(b.cols.col4R-b.cols.col4L).toExponential(4)}  fixA col4w=${(a.cols.col4R-a.cols.col4L).toExponential(4)}`);
  }
  process.exit(0);
}

function diff(a, b) {
  let worst = 0, worstId = '', n = 0;
  for (const id of VISIBLE) {
    if (!a.nodes[id] || !b.nodes[id]) continue;
    const d = Math.hypot(a.nodes[id].x - b.nodes[id].x, a.nodes[id].y - b.nodes[id].y);
    if (d > 0.05) n++;
    if (d > worst) { worst = d; worstId = id; }
  }
  return { worst, worstId, n };
}

for (const [W, H] of VIEWPORTS) {
  const base = run({ W, H });
  const c = base.cols;
  console.log(`\n===== W=${W} H=${H}  SCL=${base.SCL.toFixed(3)} solver=${base.solver} SHOW_OUTPUTS=${base.showOutputs}`);
  console.log(`  consoleReserve=${c.consoleReserve} pipeStart=${c.pipeStart.toFixed(2)} pipeEnd=${c.pipeEnd.toFixed(2)} colGap=${c.colGap.toFixed(2)} c4w=${c.c4w}`);
  console.log(`  col3=[${c.col3L.toFixed(2)}, ${c.col3R.toFixed(2)}]  col4=[${c.col4L.toFixed(2)}, ${c.col4R.toFixed(2)}]  ` +
              `col3R-pipeEnd=${(c.col3R - c.pipeEnd).toFixed(6)}  col4 width=${(c.col4R - c.col4L).toFixed(4)} ${c.col4R < c.col4L ? '<-- INVERTED' : ''}`);
  const xs = OUTS.map((id) => base.nodes[id].x);
  console.log(`  output x: ${OUTS.map((id, i) => id + '=' + xs[i].toFixed(2)).join('  ')}   (pipeEnd-10 = ${(c.pipeEnd - 10).toFixed(2)})`);
  const protoX = ['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'].map((i) => base.nodes[i].x);
  console.log(`  protocol x-range ${Math.min(...protoX).toFixed(1)}..${Math.max(...protoX).toFixed(1)}`);

  for (const [tag, opts] of [['fixA (col4L=col3R)', { fixA: true }],
                             ['fixB (clamp guard) ', { fixB: true }],
                             ['fixA+fixB          ', { fixA: true, fixB: true }],
                             ['fixC (drop OUTPUTS)', { fixC: true }]]) {
    const v = run({ W, H, ...opts });
    const d = diff(base, v);
    const vx = OUTS.map((id) => v.nodes[id].x);
    console.log(`   ${tag}: visible moved=${d.n}/${VISIBLE.length} worst=${d.worst.toFixed(1)}px (${d.worstId || '-'})   outputs x -> ${vx.map((x) => x.toFixed(1)).join(', ')}`);
  }
}
