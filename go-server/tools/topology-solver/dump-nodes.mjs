import fs from 'node:fs';
const src = fs.readFileSync('verify-labelpipe.mjs','utf8')
  .replace(/const sizes = [\s\S]*$/,'export { buildScene, runLabels };');
fs.writeFileSync('.mod-labelpipe.mjs', src);
const { buildScene } = await import('./.mod-labelpipe.mjs');
for (const [W,H] of [[1903,940],[1903,1000],[1950,900],[1400,800],[1233,750],[800,700]]) {
  const S = buildScene(W,H);
  const P = S.PROTOCOLS.map(p=>({id:p.id,x:+p.x.toFixed(1),y:+p.y.toFixed(1)}));
  const xs = P.map(p=>p.x), ys = P.map(p=>p.y);
  // pairwise circle overlaps (r=36 each)
  let ov=0, worst=0, pairs=[];
  for(let i=0;i<P.length;i++)for(let j=i+1;j<P.length;j++){
    const d=Math.hypot(P[i].x-P[j].x,P[i].y-P[j].y);
    if(d<72){ov++; const pen=72-d; if(pen>worst)worst=pen; pairs.push(P[i].id+'/'+P[j].id+' d='+d.toFixed(1));}
  }
  console.log('\nW=%d H=%d profile=%s  protoX span %s..%s (%s)  protoY span %s..%s (%s)',
    W,H,S.solverProfile,Math.min(...xs).toFixed(0),Math.max(...xs).toFixed(0),(Math.max(...xs)-Math.min(...xs)).toFixed(0),
    Math.min(...ys).toFixed(0),Math.max(...ys).toFixed(0),(Math.max(...ys)-Math.min(...ys)).toFixed(0));
  console.log('  ', P.map(p=>p.id+'('+p.x+','+p.y+')').join(' '));
  console.log('   circle-circle overlaps: %d  worst penetration %s  %s', ov, worst.toFixed(1), pairs.join(', '));
}
