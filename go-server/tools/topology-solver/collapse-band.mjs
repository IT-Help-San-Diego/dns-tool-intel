import fs from 'node:fs';
let src = fs.readFileSync('verify-labelpipe.mjs','utf8').replace(/const sizes = [\s\S]*$/,'export { buildScene }; export function setFudge(f){ WIDTH_FUDGE=f; }');
fs.writeFileSync('.mod2.mjs', src);
const { buildScene, setFudge } = await import('./.mod2.mjs');
console.log('text-width fudge -> widths W where the 9 protocol circles collapse to a <120px-wide column (H=800)');
for (const f of [0.85,1.0,1.1,1.2,1.3]) {
  setFudge(f);
  const bad=[];
  for (let W=900; W<=2200; W+=25){ const S=buildScene(W,800); const xs=S.PROTOCOLS.map(p=>p.x); if (Math.max(...xs)-Math.min(...xs) < 120) bad.push(W); }
  console.log('  fudge %s : %s', f.toFixed(2), bad.length? (bad[0]+'..'+bad[bad.length-1]+'  ('+bad.length+' widths)') : 'none');
}
