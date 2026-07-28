import { layout } from './sim-protocol-rescale.js';

function show(W: number, H = 900) {
  const a = layout(W, H, { fix: false });
  const b = layout(W, H, { fix: true });
  console.log(`\n===== W=${W} H=${H}  SCL=${a.SCL.toFixed(3)} =====`);
  console.log(`pipeStart=${a.pipeStart.toFixed(1)} pipeEnd=${a.pipeEnd.toFixed(1)} pipeTotal=${a.pipeTotal.toFixed(1)} usableW=${a.usableW}`);
  console.log(`srcNeed=${a.srcNeed.toFixed(1)} confNeed=${a.confNeed.toFixed(1)} c1w=${a.c1w.toFixed(1)} c2w=${a.c2w.toFixed(1)} c3w=${a.c3w.toFixed(1)}`);
  console.log(`protocol zone x=[${a.col3L.toFixed(1)}, ${a.col3R.toFixed(1)}]  clamp window=[${a.clampLo.toFixed(1)}, ${a.clampHi.toFixed(1)}]  padX=${a.padX.toFixed(1)} tx=[${a.tx1.toFixed(1)}, ${a.tx2.toFixed(1)}]`);
  console.log('raw remapped x:', a.rawProto.map(p => `${p.id}=${p.raw.toFixed(1)}`).join(' '));
  console.log(`CURRENT: minPX=${a.minPX.toFixed(1)} maxPX=${a.maxPX.toFixed(1)} span=${(a.maxPX - a.minPX).toFixed(2)} guard=${a.guardX}`);
  console.log(`   FIX : minPX=${b.minPX.toFixed(1)} maxPX=${b.maxPX.toFixed(1)} span=${(b.maxPX - b.minPX).toFixed(2)} guard=${b.guardX}`);
  console.log('CURRENT final:', a.finalX.map(p => `${p.id}(${p.x.toFixed(0)},${p.y.toFixed(0)})`).join(' '));
  console.log('   FIX final:', b.finalX.map(p => `${p.id}(${p.x.toFixed(0)},${p.y.toFixed(0)})`).join(' '));
  console.log(`CURRENT spanX=${a.finalSpanX.toFixed(1)} spanY=${a.finalSpanY.toFixed(1)} protoOverlapPairs=${a.protoOverlaps} iters=${a.iters}`);
  console.log(`   FIX  spanX=${b.finalSpanX.toFixed(1)} spanY=${b.finalSpanY.toFixed(1)} protoOverlapPairs=${b.protoOverlaps} iters=${b.iters}`);
  const identical = a.finalX.every((p, i) => Math.abs(p.x - b.finalX[i].x) < 1e-6 && Math.abs(p.y - b.finalX[i].y) < 1e-6);
  console.log(`FIX CHANGES RENDERED OUTPUT? ${identical ? 'NO — byte-identical' : 'YES'}`);
}

for (const W of (process.argv.slice(2).length ? process.argv.slice(2).map(Number) : [1233, 1400, 1918, 1950])) show(W);

// boundary sweep: where does the guard flip?
let prev: boolean | null = null;
const flips: string[] = [];
for (let W = 700; W <= 2400; W++) {
  const g = layout(W, 900).guardX;
  if (prev !== null && g !== prev) flips.push(`${W - 1}->${W}: guard ${prev} -> ${g}`);
  prev = g;
}
console.log('\nGuard transitions across W=700..2400 (H=900):', flips.join(' | '));

// sensitivity to text-metric error at the user's real width
console.log('\nText-metric sensitivity at W=1918, H=900 (k scales every measureText result):');
for (const k of [0.85, 1.0, 1.15, 1.3, 1.5, 2.0]) {
  const r = layout(1918, 900, { k });
  console.log(`  k=${k}: col3L=${r.col3L.toFixed(1)} clampLo=${r.clampLo.toFixed(1)} rawMin=${Math.min(...r.rawProto.map(p => p.raw)).toFixed(1)} guard=${r.guardX} spanX=${r.finalSpanX.toFixed(1)} ovl=${r.protoOverlaps}`);
}

// height sensitivity at the user's real width
console.log('\nHeight sensitivity at W=1918:');
for (const H of [750, 800, 900, 1000, 1100, 1300]) {
  const r = layout(1918, H);
  console.log(`  H=${H}: col3L=${r.col3L.toFixed(1)} clampLo=${r.clampLo.toFixed(1)} rawMin=${Math.min(...r.rawProto.map(p => p.raw)).toFixed(1)} guard=${r.guardX} spanX=${r.finalSpanX.toFixed(1)} ovl=${r.protoOverlaps}`);
}
