import fs from 'node:fs';
const src = fs.readFileSync('verify-labelpipe.mjs','utf8').replace(/const sizes = [\s\S]*$/,'export { buildScene };');
fs.writeFileSync('.mod-labelpipe.mjs', src);
const { buildScene } = await import('./.mod-labelpipe.mjs');
console.log('W     SCL   protoZone x1..x2   width  padX  tx2-tx1  X-rescale?  protoX span');
for (const W of [1000,1100,1233,1300,1400,1500,1600,1700,1800,1903,1950,2100]) {
  const S = buildScene(W,800);
  const pz = S.zones.protocol.bounds;
  const padX = 52*S.SCL;
  const inner = (pz.x2-padX)-(pz.x1+padX);
  const xs = S.PROTOCOLS.map(p=>p.x);
  console.log('%s %s %s..%s %s %s %s %s %s',
    String(W).padEnd(5), S.SCL.toFixed(3),
    pz.x1.toFixed(0).padStart(6), pz.x2.toFixed(0).padStart(6),
    (pz.x2-pz.x1).toFixed(0).padStart(6), padX.toFixed(0).padStart(5),
    inner.toFixed(0).padStart(8), (inner>40?'  YES     ':'  NO(skip)'),
    (Math.max(...xs)-Math.min(...xs)).toFixed(0).padStart(5));
}
