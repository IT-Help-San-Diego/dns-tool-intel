// Adversarial verification harness for the claim:
//   "Edge labels are deflected by output nodes that are never painted"
//   (go-server/static/js/topology.js:1511)
//
// Loads the REAL shipped topology.js in a stubbed DOM, with the REAL
// window.__TOPO_SOLVER payload the Go handler injects (the three
// tools/topology-solver/output/*-layout.json files), runs the REAL
// resize()/layoutAll() and the REAL drawFlowEdge() label pass, and diffs
// the shipped sweep against a sweep patched to skip hidden output nodes.
//
// Canvas text metrics are Helvetica AFM widths (units/1000) — the same
// approximation the other harnesses in this directory use.
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
  const ctx = {
    set font(v) { const m = /(\d+(?:\.\d+)?)px/.exec(String(v)); if (m) fontSize = parseFloat(m[1]); this._font = v; },
    get font() { return this._font; },
    measureText(t) {
      let u = 0;
      for (const ch of String(t)) u += (AFM[ch] !== undefined ? AFM[ch] : 556);
      return { width: (u / 1000) * fontSize };
    },
    createLinearGradient: () => grad,
    createRadialGradient: () => grad,
    createPattern: () => null,
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
    putImageData: noop,
    drawImage: noop,
    setTransform: noop, save: noop, restore: noop, beginPath: noop, closePath: noop,
    moveTo: noop, lineTo: noop, arc: noop, arcTo: noop, ellipse: noop, rect: noop,
    quadraticCurveTo: noop, bezierCurveTo: noop, fill: noop, stroke: noop,
    fillRect: noop, strokeRect: noop, clearRect: noop, clip: noop,
    fillText: noop, strokeText: noop, setLineDash: noop, getLineDash: () => [],
    translate: noop, rotate: noop, scale: noop,
  };
  return ctx;
}

function makeEl(id, ctx, sizeRef) {
  const el = {
    id, tagName: 'DIV', className: '', textContent: '', innerHTML: '', value: '',
    style: {}, dataset: {}, title: '', type: '', href: '', checked: false, hidden: false,
    width: 0, height: 0,
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

function run({ W, H, patchSweep = false, dropOutputsFromOverlapPass = false }) {
  const sizeRef = { W, H };
  const ctx = makeCtx();

  const els = {};
  const doc = {
    hidden: false,
    getElementById: (id) => (els[id] = els[id] || makeEl(id, ctx, sizeRef)),
    createElement: (t) => makeEl('created-' + t, ctx, sizeRef),
    addEventListener: () => {}, removeEventListener: () => {},
    querySelector: () => null, querySelectorAll: () => [],
    body: makeEl('body', ctx, sizeRef),
    documentElement: makeEl('html', ctx, sizeRef),
  };
  const win = {
    devicePixelRatio: 1,
    location: { search: '', href: 'https://x/topology', pathname: '/topology' },
    addEventListener: () => {}, removeEventListener: () => {},
    requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    matchMedia: () => ({ matches: false, addListener: () => {}, addEventListener: () => {} }),
    fetch: () => new Promise(() => {}),
    // exactly what internal/handlers/topology.go injects
    __TOPO_SOLVER: {
      desktop: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/desktop-layout.json'), 'utf8')),
      tablet: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/tablet-layout.json'), 'utf8')),
      mobile: JSON.parse(fs.readFileSync(path.join(__dirname, 'output/mobile-layout.json'), 'utf8')),
    },
    __FIXTURE_CORPUS: null,
    __TOPO_REPLAY: null,
  };

  const sandbox = {
    window: win, document: doc, console: { log: () => {}, warn: () => {}, error: () => {} },
    requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    fetch: () => new Promise(() => {}),
    Image: function () { this.onload = null; return this; },
    ResizeObserver: undefined,
    performance: { now: () => 0 },
    location: win.location,
    navigator: { userAgent: 'node', clipboard: { writeText: () => Promise.resolve() } },
    history: { replaceState: () => {}, pushState: () => {} },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    alert: () => {},
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
  };

  // globe-core.js is an IIFE assigning globalThis.GlobeCore.
  let src = fs.readFileSync(TOPO_SRC, 'utf8');
  const globeSrc = fs.readFileSync(GLOBE_SRC, 'utf8');

  if (patchSweep) {
    const anchor = `                for (let nri = 0; nri < allLayoutNodes.length; nri++) {
                    let nn = allLayoutNodes[nri];
`;
    if (!src.includes(anchor)) throw new Error('sweep anchor not found');
    src = src.replace(anchor, anchor + `                    if (nn.zone === 'output' && (HUD_ACTIVE || !SHOW_OUTPUTS)) continue;\n`);
  }
  if (dropOutputsFromOverlapPass) {
    const a2 = `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);`;
    if (!src.includes(a2)) throw new Error('allLayoutNodes anchor not found');
    src = src.replace(a2, `            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS);`);
  }

  // Export internals instead of starting the rAF loop.
  const tail = `        loop();\n    })();`;
  if (!src.includes(tail)) throw new Error('tail anchor not found');
  src = src.replace(tail, `
        window.__T = {
            resize: resize,
            get W() { return W; }, get H() { return H; }, get SCL() { return SCL; },
            get SOLVER_ACTIVE() { return SOLVER_ACTIVE; },
            get allLayoutNodes() { return allLayoutNodes; },
            OUTPUTS: OUTPUTS, PROTOCOLS: PROTOCOLS,
            PROTO_EDGES: PROTO_EDGES, FLOW_EDGES: FLOW_EDGES,
            drawFlowEdge: drawFlowEdge,
            resetLabels: function() { placedEdgeLabels = []; },
            get placedEdgeLabels() { return placedEdgeLabels; },
            setHud: function(v) { HUD_ACTIVE = v; },
            get HUD_ACTIVE() { return HUD_ACTIVE; },
            get SHOW_OUTPUTS() { return SHOW_OUTPUTS; }
        };
    })();`);

  const fn = new Function(...Object.keys(sandbox), 'globalThis_GC_SRC', 'TOPO_SRC_TEXT', `
    eval(globalThis_GC_SRC);
    eval(TOPO_SRC_TEXT);
  `);
  fn(...Object.values(sandbox), globeSrc, src);

  const T = win.__T;
  T.resize(); // -> layoutAll() at W,H

  // First frame: node .x/.y are set to .targetX/.targetY by layoutAll.
  // Reproduce draw()'s label pass exactly (same order).
  T.resetLabels();
  const out = [];
  const record = (arr) => arr.forEach((e) => {
    const before = T.placedEdgeLabels.length;
    T.drawFlowEdge(e);
    if (T.placedEdgeLabels.length > before) {
      const p = T.placedEdgeLabels[T.placedEdgeLabels.length - 1];
      out.push({ key: e.from + '->' + e.to + ':' + e.label, ...p });
    }
  });
  record(T.FLOW_EDGES);
  record(T.PROTO_EDGES);

  const nodes = {};
  T.allLayoutNodes.forEach((n) => {
    nodes[n.id] = { zone: n.zone, x: n.x, y: n.y, hw: n._halfW || n.radius, hh: n._halfH || n.radius, r: n.radius, shape: n.shape };
  });
  return { W: T.W, H: T.H, SCL: T.SCL, solver: T.SOLVER_ACTIVE, hud: T.HUD_ACTIVE, showOutputs: T.SHOW_OUTPUTS, labels: out, nodes };
}

function labelVsCircle(l, n) {
  // pill AABB vs circle AABB (conservative: circle AABB)
  const ox = Math.min(l.x + l.w / 2, n.x + n.r) - Math.max(l.x - l.w / 2, n.x - n.r);
  const oy = Math.min(l.y + l.h / 2, n.y + n.r) - Math.max(l.y - l.h / 2, n.y - n.r);
  return ox > 0 && oy > 0 ? { ox, oy } : null;
}

const VIEWPORTS = [
  { W: 1950, H: 900, tag: "user's real Safari" },
  { W: 1233, H: 750, tag: 'broken browser pane report' },
  { W: 1024, H: 750, tag: "claim's harness" },
  { W: 800, H: 750, tag: 'tablet (no console reserve)' },
];

for (const vp of VIEWPORTS) {
  const A = run({ W: vp.W, H: vp.H, patchSweep: false });
  const B = run({ W: vp.W, H: vp.H, patchSweep: true });
  console.log(`\n===== W=${vp.W} H=${vp.H}  (${vp.tag})  SCL=${A.SCL.toFixed(3)} solver=${A.solver} HUD=${A.hud} SHOW_OUTPUTS=${A.showOutputs}`);
  console.log('  output hexagon centres (never painted):');
  for (const id of ['reports', 'jsonapi', 'seo', 'badges']) {
    const n = A.nodes[id];
    console.log(`    ${id.padEnd(8)} x=${n.x.toFixed(1)} y=${n.y.toFixed(1)} halfW=${n.hw.toFixed(1)} halfH=${n.hh.toFixed(1)}  sweep-box=±${(n.hw + 12).toFixed(1)}x±${(n.hh + 12).toFixed(1)}`);
  }
  const protoXs = ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa'].map((i) => A.nodes[i].x);
  console.log(`  protocol circle x-range: ${Math.min(...protoXs).toFixed(1)} .. ${Math.max(...protoXs).toFixed(1)} (r=${A.nodes.spf.r})`);

  const bByKey = Object.fromEntries(B.labels.map((l) => [l.key, l]));
  let moved = 0;
  for (const l of A.labels) {
    const b = bByKey[l.key];
    if (!b) { console.log(`  !! ${l.key} present in shipped, absent in patched`); continue; }
    const d = Math.hypot(l.x - b.x, l.y - b.y);
    if (d > 0.05) {
      moved++;
      console.log(`  MOVED ${l.key.padEnd(28)} shipped=(${l.x.toFixed(1)},${l.y.toFixed(1)})  patched=(${b.x.toFixed(1)},${b.y.toFixed(1)})  delta=${d.toFixed(1)}px`);
    }
  }
  if (!moved) console.log('  no label position differs between shipped sweep and output-skipping sweep');

  // overlap accounting against VISIBLE protocol circles
  const score = (res, tag) => {
    let n = 0, worst = 0;
    for (const l of res.labels) {
      for (const id of ['spf', 'dkim', 'dmarc', 'dnssec', 'dane', 'mtasts', 'tlsrpt', 'bimi', 'caa']) {
        const o = labelVsCircle(l, res.nodes[id]);
        if (o) { n++; worst = Math.max(worst, Math.min(o.ox, o.oy)); }
      }
    }
    console.log(`  ${tag}: label-on-protocol-circle collisions = ${n}, worst penetration = ${worst.toFixed(1)}px`);
    return n;
  };
  score(A, 'shipped ');
  score(B, 'patched ');
}

// Extra: does removing OUTPUTS from the node overlap pass move visible nodes?
console.log('\n===== side question: do the invisible hexagons also move VISIBLE nodes in the overlap pass?');
for (const vp of VIEWPORTS) {
  const A = run({ W: vp.W, H: vp.H });
  const C = run({ W: vp.W, H: vp.H, dropOutputsFromOverlapPass: true });
  let worst = 0, worstId = '';
  for (const id of Object.keys(C.nodes)) {
    if (!A.nodes[id]) continue;
    const d = Math.hypot(A.nodes[id].x - C.nodes[id].x, A.nodes[id].y - C.nodes[id].y);
    if (d > worst) { worst = d; worstId = id; }
  }
  console.log(`  W=${vp.W}: max visible-node displacement caused by OUTPUTS in the overlap pass = ${worst.toFixed(1)}px (${worstId})`);
}
