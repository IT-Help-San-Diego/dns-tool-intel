// Part 3: width sweep — is the proposed fix a systematic improvement or a coin flip?
// Plus per-node 1px sensitivity, and the postgres/fixtures X-vs-Y story.
import fs from 'fs';
const src = fs.readFileSync(new URL('./audit-clampinset.mjs', import.meta.url), 'utf8');
const body = src.slice(0, src.indexOf('const SOLVER = {};'));
const mod = await import('data:text/javascript;base64,' + Buffer.from(body + '\nexport { layout };').toString('base64'));
const { layout } = mod;
const SOLVER = {};
for (const p of ['desktop','tablet','mobile'])
  SOLVER[p] = JSON.parse(fs.readFileSync(new URL('./output/'+p+'-layout.json', import.meta.url),'utf8'));

function drawnOverlap(R) {
  const a = R.all.filter(n=>n.zone!=='output');
  let n=0, depth=0;
  for (let i=0;i<a.length;i++) for (let j=i+1;j<a.length;j++) {
    const A=a[i],B=a[j];
    const ox=(A._halfW+B._halfW)-Math.abs(A.targetX-B.targetX);
    const oy=(A._halfH+B._halfH)-Math.abs(A.targetY-B.targetY);
    if(ox>0&&oy>0){n++; depth+=Math.min(ox,oy);}
  }
  return {n, depth};
}

console.log('=== width sweep H=900, W=1000..2000 step 10: drawn-node AABB overlaps, ship vs proposed fix ===');
let better=0, worse=0, same=0, dShip=0, dFix=0, nShip=0, nFix=0;
const rows=[];
for (let W=1000; W<=2000; W+=10) {
  const A=layout(W,900,SOLVER,'ship'), B=layout(W,900,SOLVER,'fix');
  const a=drawnOverlap(A), b=drawnOverlap(B);
  nShip+=a.n; nFix+=b.n; dShip+=a.depth; dFix+=b.depth;
  if (b.depth < a.depth-0.01) better++; else if (b.depth > a.depth+0.01) worse++; else same++;
  rows.push([W,a.n,a.depth,b.n,b.depth]);
}
console.log('  widths sampled: '+rows.length);
console.log('  fix strictly better: '+better+'   strictly worse: '+worse+'   identical: '+same);
console.log('  total overlapping pairs  ship='+nShip+'  fix='+nFix);
console.log('  total overlap depth      ship='+dShip.toFixed(1)+'px  fix='+dFix.toFixed(1)+'px');
console.log('  widths where fix is WORSE: '+rows.filter(r=>r[4]>r[2]+0.01).map(r=>r[0]+'(+'+(r[4]-r[2]).toFixed(1)+')').join(' ')||'  (none)');
console.log('  widths where fix is BETTER: '+rows.filter(r=>r[4]<r[2]-0.01).map(r=>r[0]+'(-'+(r[2]-r[4]).toFixed(1)+')').join(' ')||'  (none)');

console.log('\n=== per-node +1px sensitivity at W=1950 (shipped code, one node nudged after remap) ===');
const bodyN = body.replace(
  "const zpx = (mode==='fix')",
  "if (typeof globalThis.__NUDGE==='string' && nd.id===globalThis.__NUDGE) nd.targetX += 1;\n      const zpx = (mode==='fix')");
const modN = await import('data:text/javascript;base64,' + Buffer.from(bodyN+'\nexport { layout };').toString('base64'));
{
  const base = layout(1950,900,SOLVER,'ship');
  const ids = base.all.map(n=>n.id);
  const out=[];
  for (const id of ids) {
    globalThis.__NUDGE = id;
    const P = modN.layout(1950,900,SOLVER,'ship');
    const mx = Math.max(...ids.map(k=>Math.hypot(P.T[k].final-base.T[k].final, P.T[k].finalY-base.T[k].finalY)));
    out.push([id, mx]);
  }
  globalThis.__NUDGE = null;
  out.sort((a,b)=>b[1]-a[1]);
  console.log('  a 1px nudge to ONE node changes the final layout by up to:');
  console.log('    '+out.slice(0,8).map(o=>o[0]+'='+o[1].toFixed(1)+'px').join('  '));
  console.log('  (amplification factor of the largest: '+out[0][1].toFixed(1)+'x)');
}

console.log('\n=== postgres/fixtures at W=1950: does the fix separate them in X (claimed axis) or Y? ===');
{
  const A=layout(1950,900,SOLVER,'ship'), B=layout(1950,900,SOLVER,'fix');
  for (const [nm,R] of [['ship',A],['fix ',B]]) {
    const p=R.all.find(n=>n.id==='postgres'), f=R.all.find(n=>n.id==='fixtures');
    const ox=(p._halfW+f._halfW)-Math.abs(p.targetX-f.targetX);
    const oy=(p._halfH+f._halfH)-Math.abs(p.targetY-f.targetY);
    console.log('  '+nm+'  postgres=('+p.targetX.toFixed(1)+','+p.targetY.toFixed(1)+')  fixtures=('+f.targetX.toFixed(1)+','+f.targetY.toFixed(1)+
      ')   dX='+Math.abs(p.targetX-f.targetX).toFixed(1)+' (need '+(p._halfW+f._halfW).toFixed(1)+')'+
      '   dY='+Math.abs(p.targetY-f.targetY).toFixed(1)+' (need '+(p._halfH+f._halfH).toFixed(1)+')'+
      '   overlapX='+ox.toFixed(1)+' overlapY='+oy.toFixed(1));
  }
  console.log('  -> the claim\'s mechanism is about the X inset. Check which axis actually moved.');
}

console.log('\n=== does the storage stack fit its zone AT ALL at W=1950? (feasibility check) ===');
for (const W of [1950,1600,1400,1233,1100,800]) {
  const A=layout(W,900,SOLVER,'ship');
  const z=A.zones.storage.bounds;
  const S=A.all.filter(n=>n.zone==='storage');
  const zw=z.x2-z.x1, zh=z.y2-z.y1;
  // admissible centre band width for each node under the PASS clamp
  const bands=S.map(n=>({id:n.id, wBand:(zw-2*n._halfW), hBand:(zh-2*n._halfH)}));
  // can 3 boxes with pad 14 be placed inside zw x zh at all?
  const sumW=S.reduce((s,n)=>s+2*n._halfW,0)+14*2;
  const sumH=S.reduce((s,n)=>s+2*n._halfH,0)+14*2;
  const maxW=Math.max(...S.map(n=>2*n._halfW)), maxH=Math.max(...S.map(n=>2*n._halfH));
  console.log('  W='+String(W).padStart(4)+'  storage zone '+zw.toFixed(1)+' x '+zh.toFixed(1)+
    '   one row needs W='+sumW.toFixed(1)+'  one column needs H='+sumH.toFixed(1)+
    '   widest box='+maxW.toFixed(1)+'  tallest='+maxH.toFixed(1)+
    '   => row fits:'+(sumW<=zw)+'  column fits:'+(sumH<=zh)+
    '   centre bands: '+bands.map(b=>b.id+' w'+b.wBand.toFixed(0)+'/h'+b.hBand.toFixed(0)).join(' '));
}
