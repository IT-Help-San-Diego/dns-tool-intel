import fs from 'node:fs';
const src = fs.readFileSync('verify-labelpipe.mjs','utf8').replace(/const sizes = [\s\S]*$/,'export { buildScene, runLabels };');
fs.writeFileSync('.mod-labelpipe.mjs', src);
const { buildScene, runLabels } = await import('./.mod-labelpipe.mjs');

let tot=0, bad1=0, badF=0, worsened=0, sepFired=0, clampFired=0, colCollapse=0, sizes=0;
let worstStage1=0, worstFinal=0, deltaSum=0, maxDelta=0;
const rowsColl=[], rowsSpread=[];
for (let W=420; W<=2200; W+=20) {
  for (const H of [700,750,800,900,1000,1100]) {
    const S = buildScene(W,H);
    const xs = S.PROTOCOLS.map(p=>p.x);
    const span = Math.max(...xs)-Math.min(...xs);
    let cc=0; for(let i=0;i<9;i++)for(let j=i+1;j<9;j++){ if(Math.hypot(S.PROTOCOLS[i].x-S.PROTOCOLS[j].x,S.PROTOCOLS[i].y-S.PROTOCOLS[j].y)<72) cc++; }
    const collapsed = span < 120;
    if (collapsed) colCollapse++;
    sizes++;
    const rows = runLabels(S);
    let b1=0,bF=0;
    for (const r of rows) {
      tot++;
      if (r.hitAfterNodes.pen>0){bad1++;b1++;}
      if (r.hitFinal.pen>0){badF++;bF++;}
      if (r.hitFinal.pen > r.hitAfterNodes.pen+0.01) worsened++;
      if (r.sepMoved>0.01) sepFired++;
      if (r.clampMoved>0.01) clampFired++;
      worstStage1 = Math.max(worstStage1, r.hitAfterNodes.pen);
      worstFinal = Math.max(worstFinal, r.hitFinal.pen);
      const d = r.hitFinal.pen - r.hitAfterNodes.pen;
      if (d>0){ deltaSum+=d; maxDelta=Math.max(maxDelta,d); }
    }
    (collapsed?rowsColl:rowsSpread).push({W,H,span:+span.toFixed(0),cc,b1,bF});
  }
}
const agg = a => ({n:a.length, badAfterStage1: a.reduce((s,r)=>s+r.b1,0), badFinal: a.reduce((s,r)=>s+r.bF,0), labels: a.length*7});
console.log('viewports tested: %d  (protocol column COLLAPSED in %d of them)', sizes, colCollapse);
console.log('label placements: %d', tot);
console.log('  overlapping a node AFTER STAGE 1 (node avoidance) alone : %d  (%s%%)', bad1, (100*bad1/tot).toFixed(1));
console.log('  overlapping a node AFTER ALL THREE STAGES                : %d  (%s%%)', badF, (100*badF/tot).toFixed(1));
console.log('  made WORSE by stage2/stage3                              : %d  (%s%%)', worsened, (100*worsened/tot).toFixed(1));
console.log('  stage2 (label-label sep) moved the pill at all           : %d  (%s%%)', sepFired, (100*sepFired/tot).toFixed(1));
console.log('  stage3 (viewport clamp) moved the pill at all            : %d  (%s%%)', clampFired, (100*clampFired/tot).toFixed(1));
console.log('  worst node penetration after stage1 = %spx ; after all stages = %spx', worstStage1.toFixed(1), worstFinal.toFixed(1));
console.log('  total extra penetration contributed by stages 2+3 = %spx across %d placements (max single %spx)', deltaSum.toFixed(1), tot, maxDelta.toFixed(1));
const c=agg(rowsColl), s=agg(rowsSpread);
console.log('\nSPLIT BY PROTOCOL-COLUMN STATE:');
console.log('  COLLAPSED column (%d viewports): %d/%d labels end up on a node (%s%%)', c.n, c.badFinal, c.labels, (100*c.badFinal/c.labels).toFixed(1));
console.log('  SPREAD ellipse  (%d viewports): %d/%d labels end up on a node (%s%%)', s.n, s.badFinal, s.labels, (100*s.badFinal/s.labels).toFixed(1));
