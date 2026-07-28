// Part 2: (a) how much of the remap position is *immediately inadmissible*
// to the pass's clamp, (b) is the ship-vs-fix delta causal or chaotic
// (epsilon-perturbation sensitivity test), (c) does the fix reduce overlaps.
import fs from 'fs';
import { execSync } from 'child_process';

const src = fs.readFileSync(new URL('./audit-clampinset.mjs', import.meta.url), 'utf8');
// reuse layout() by re-evaluating the module body up to the driver
const body = src.slice(0, src.indexOf('const SOLVER = {};'));
const mod = await import('data:text/javascript;base64,' + Buffer.from(
  body + '\nexport { layout, buildNodes, computeNodeBox };'
).toString('base64'));
const { layout } = mod;

const SOLVER = {};
for (const p of ['desktop','tablet','mobile'])
  SOLVER[p] = JSON.parse(fs.readFileSync(new URL('./output/'+p+'-layout.json', import.meta.url),'utf8'));

function overlapStats(R) {
  const a = R.all; let n = 0, worst = 0, worstPair = null;
  for (let i=0;i<a.length;i++) for (let j=i+1;j<a.length;j++) {
    const A=a[i],B=a[j];
    const ox = (A._halfW+B._halfW) - Math.abs(A.targetX-B.targetX);
    const oy = (A._halfH+B._halfH) - Math.abs(A.targetY-B.targetY);
    if (ox>0 && oy>0) { n++; const m=Math.min(ox,oy); if(m>worst){worst=m;worstPair=A.id+'/'+B.id;} }
  }
  return { n, worst, worstPair };
}
// same but only counting nodes that are actually DRAWN (SHOW_OUTPUTS=false)
function overlapStatsVisible(R) {
  const a = R.all.filter(n => n.zone !== 'output'); let n = 0, worst = 0, worstPair=null;
  for (let i=0;i<a.length;i++) for (let j=i+1;j<a.length;j++) {
    const A=a[i],B=a[j];
    const ox = (A._halfW+B._halfW) - Math.abs(A.targetX-B.targetX);
    const oy = (A._halfH+B._halfH) - Math.abs(A.targetY-B.targetY);
    if (ox>0 && oy>0) { n++; const m=Math.min(ox,oy); if(m>worst){worst=m;worstPair=A.id+'/'+B.id;} }
  }
  return { n, worst, worstPair };
}

console.log('=== (a) how far the remap position sits OUTSIDE the pass clamp admissible band ===');
for (const W of [1950, 1233, 800]) {
  const R = layout(W, 900, SOLVER, 'ship');
  let rows = [];
  for (const n of R.all) {
    const t = R.T[n.id];
    const lo = t.zx1 + t.hw, hi = t.zx2 - t.hw;
    let adm = t.afterZone;
    if (lo <= hi) adm = Math.max(lo, Math.min(hi, t.afterZone));
    else adm = lo; // Math.max wins in the shipped code — NO guard at line 1266
    rows.push({ id:n.id, zone:n.zone, d: adm - t.afterZone, inverted: lo > hi });
  }
  rows.sort((a,b)=>Math.abs(b.d)-Math.abs(a.d));
  const nz = rows.filter(r=>Math.abs(r.d)>0.001);
  console.log('  W='+W+': '+nz.length+'/27 nodes land where the pass clamp will not accept them.  worst: ' +
    nz.slice(0,6).map(r=>r.id+'('+r.zone+(r.inverted?',INVERTED zone':'')+') '+r.d.toFixed(1)).join(', '));
}

console.log('\n=== (b) chaos test: is the ship-vs-fix delta causal, or just re-rolling a chaotic system? ===');
console.log('    control = shipped code with ONE node\'s remapped X nudged by +0.01px (a change');
console.log('    far too small to represent any real "fix"). If that moves the final layout as');
console.log('    much as the proposed fix does, the fix\'s delta is noise, not repair.\n');

// epsilon variant: monkeypatch by re-running layout with a mode that adds eps
const body2 = body.replace(
  "const zpx = (mode==='fix')",
  "if (mode==='eps' && nd.id==='root') nd.targetX += 0.01;\n      const zpx = (mode==='fix')");
const mod2 = await import('data:text/javascript;base64,' + Buffer.from(
  body2 + '\nexport { layout };').toString('base64'));

for (const W of [1950, 1233, 800]) {
  const A = layout(W, 900, SOLVER, 'ship');
  const B = layout(W, 900, SOLVER, 'fix');
  const E = mod2.layout(W, 900, SOLVER, 'eps');
  const dFix = Math.max(...A.all.map(n=>Math.hypot(B.T[n.id].final-A.T[n.id].final, B.T[n.id].finalY-A.T[n.id].finalY)));
  const dEps = Math.max(...A.all.map(n=>Math.hypot(E.T[n.id].final-A.T[n.id].final, E.T[n.id].finalY-A.T[n.id].finalY)));
  const sFix = A.all.reduce((s,n)=>s+Math.hypot(B.T[n.id].final-A.T[n.id].final, B.T[n.id].finalY-A.T[n.id].finalY),0);
  const sEps = A.all.reduce((s,n)=>s+Math.hypot(E.T[n.id].final-A.T[n.id].final, E.T[n.id].finalY-A.T[n.id].finalY),0);
  console.log('  W='+String(W).padStart(4)+
    '   proposed fix: max node move '+dFix.toFixed(1).padStart(6)+'px, total '+sFix.toFixed(1).padStart(7)+'px' +
    '   |   +0.01px nudge: max node move '+dEps.toFixed(1).padStart(6)+'px, total '+sEps.toFixed(1).padStart(7)+'px');
}

console.log('\n=== (c) does the fix reduce real overlaps? (AABB, all 27 / drawn-only 23) ===');
for (const W of [1950, 1600, 1400, 1233, 1100, 800]) {
  const A = layout(W, 900, SOLVER, 'ship');
  const B = layout(W, 900, SOLVER, 'fix');
  const oa = overlapStats(A), ob = overlapStats(B);
  const va = overlapStatsVisible(A), vb = overlapStatsVisible(B);
  console.log('  W='+String(W).padStart(4)+'  iters ship='+String(A.iters).padStart(2)+' fix='+String(B.iters).padStart(2)+
    '   all27 overlaps ship='+String(oa.n).padStart(3)+' fix='+String(ob.n).padStart(3)+
    '   drawn23 overlaps ship='+String(va.n).padStart(3)+' fix='+String(vb.n).padStart(3)+
    '   worst drawn ship='+va.worst.toFixed(1).padStart(6)+'px ('+(va.worstPair||'-')+')'+
    '  fix='+vb.worst.toFixed(1).padStart(6)+'px ('+(vb.worstPair||'-')+')');
}

console.log('\n=== (d) the OTHER direction: what if the PASS clamp used the loose inset instead? ===');
const body3 = body.replace(
  "const zHw=nd._halfW||nd.radius, zHh=nd._halfH||nd.radius;",
  "const _zw=z.bounds.x2-z.bounds.x1,_zh=z.bounds.y2-z.bounds.y1;const zHw=Math.min(30,_zw*0.15), zHh=Math.min(20,_zh*0.15);");
const mod3 = await import('data:text/javascript;base64,' + Buffer.from(
  body3 + '\nexport { layout };').toString('base64'));
for (const W of [1950, 1233, 800]) {
  const A = layout(W, 900, SOLVER, 'ship');
  const C = mod3.layout(W, 900, SOLVER, 'ship');
  const va = overlapStatsVisible(A), vc = overlapStatsVisible(C);
  // do boxes escape their zone?
  let escA=0, escC=0;
  for (const n of A.all) { if(n.zone==='output')continue; const z=A.zones[n.zone||n.id].bounds;
    if (n.targetX-n._halfW < z.x1-0.5 || n.targetX+n._halfW > z.x2+0.5) escA++; }
  for (const n of C.all) { if(n.zone==='output')continue; const z=C.zones[n.zone||n.id].bounds;
    if (n.targetX-n._halfW < z.x1-0.5 || n.targetX+n._halfW > z.x2+0.5) escC++; }
  console.log('  W='+String(W).padStart(4)+'  drawn overlaps: ship='+va.n+' loose-pass-clamp='+vc.n+
    '    boxes escaping their zone in X: ship='+escA+' loose-pass-clamp='+escC);
}

console.log('\n=== (e) ghost OUTPUTS: never drawn (SHOW_OUTPUTS=false, line 2078) yet in allLayoutNodes (1053) ===');
for (const W of [1950, 1233, 800]) {
  const A = layout(W, 900, SOLVER, 'ship');
  const z = A.zones.output.bounds;
  const outs = A.all.filter(n=>n.zone==='output');
  console.log('  W='+String(W).padStart(4)+'  output zone x=['+z.x1.toFixed(1)+', '+z.x2.toFixed(1)+']  width='+(z.x2-z.x1).toFixed(1)+
    ' (INVERTED)   4 ghosts all pinned at x='+outs.map(o=>o.targetX.toFixed(1)).join('/'));
  // how many pushes did ghosts inflict on drawn nodes?
  let touch=0;
  for (const o of outs) for (const n of A.all) { if(n.zone==='output')continue;
    const ohw=o._halfW+n._halfW+14, ohh=o._halfH+n._halfH+14;
    if (Math.abs(o.targetX-n.targetX)<ohw && Math.abs(o.targetY-n.targetY)<ohh) touch++; }
  console.log('        ghost/drawn pairs still colliding at the final iteration: '+touch);
}
