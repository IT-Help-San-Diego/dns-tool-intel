// Width/height sweep for the "hidden output hexagons deflect edge labels" claim.
// Reuses the harness in verify-hidden-output-deflection.mjs by re-importing its run().
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(__dirname, 'verify-hidden-output-deflection.mjs'), 'utf8');
// strip the driver section so we can reuse run()
const cut = src.indexOf('const VIEWPORTS = [');
const mod = src.slice(0, cut) + '\nexport { run };\n';
const tmp = path.join(__dirname, '.__hidden-output-lib.mjs');
fs.writeFileSync(tmp, mod);
const { run } = await import('./.__hidden-output-lib.mjs');
fs.unlinkSync(tmp);

function diff(W, H) {
  const A = run({ W, H });
  const B = run({ W, H, patchSweep: true });
  const b = Object.fromEntries(B.labels.map((l) => [l.key, l]));
  let n = 0, maxD = 0;
  for (const l of A.labels) {
    const q = b[l.key];
    if (!q) continue;
    const d = Math.hypot(l.x - q.x, l.y - q.y);
    if (d > 0.05) { n++; maxD = Math.max(maxD, d); }
  }
  return { n, maxD, outX: A.nodes.seo.x, protoMaxX: Math.max(...['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'].map(i=>A.nodes[i].x)) };
}

console.log('W sweep at H=900');
for (let W = 700; W <= 2200; W += 50) {
  const r = diff(W, 900);
  console.log(`  W=${String(W).padStart(4)}  labelsMoved=${r.n}  maxDelta=${r.maxD.toFixed(1).padStart(6)}px   seo.x=${r.outX.toFixed(0).padStart(5)}  protoMaxX=${r.protoMaxX.toFixed(0).padStart(5)}`);
}
console.log('\nH sweep at W=1950');
for (let H = 600; H <= 1400; H += 100) {
  const r = diff(1950, H);
  console.log(`  H=${String(H).padStart(4)}  labelsMoved=${r.n}  maxDelta=${r.maxD.toFixed(1)}px`);
}
console.log('\nH sweep at W=1440 (common laptop)');
for (let H = 600; H <= 1200; H += 100) {
  const r = diff(1440, H);
  console.log(`  H=${String(H).padStart(4)}  labelsMoved=${r.n}  maxDelta=${r.maxD.toFixed(1)}px`);
}
