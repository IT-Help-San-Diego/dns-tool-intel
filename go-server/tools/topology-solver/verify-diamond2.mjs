// True-geometry check: does the diamond AABB shortfall produce a REAL
// shape-level collision, and would the proposed fix change the layout?
// Diamond drawn region = rotated square of half-side s=0.75r  ==>  L1 ball
// {|dx|+|dy| <= s*sqrt(2) = 1.06066r}. Rect nodes = axis-aligned _boxW x _boxH.
import { estimateTextWidth } from './src/nodeMetrics.ts';
import desktop from './output/desktop-layout.json' with { type: 'json' };
import tablet from './output/tablet-layout.json' with { type: 'json' };
import mobile from './output/mobile-layout.json' with { type: 'json' };
import fs from 'node:fs';

const LAYOUTS = { desktop, tablet, mobile };
const spec = JSON.parse(fs.readFileSync(new URL('./fixtures/dns-topology-production.json', import.meta.url), 'utf8'));
const specById = Object.fromEntries(spec.nodes.map(n => [n.id, n]));

const DEF = [
  ['root','Root / TLD','IANA Root Zone\nTLD Registries','source',30,'rect'],
  ['rdap','RDAP / WHOIS','Registration Data\nAccess Protocol','source',30,'rect'],
  ['ct','CT / Subdomains','crt.sh · Certspotter\nTransparency Logs','source',30,'rect'],
  ['cisa','CISA / Threat','BOD 19-02\nIP Scanner Detection','source',30,'rect'],
  ['probes','Probe Fleet','SMTP · DANE · TLS\nNmap · testssl.sh','source',30,'rect'],
  ['hub','DNS Resolvers','Signal Aggregation','hub',44,'hub'],
  ['engine','ICIE','Analysis Engine','engine',54,undefined],
  ['ietf','IETF Metadata','RFC Status · Errata\nDraft Tracker','confidence',36,'rect'],
  ['icae','ICAE','Accuracy Audit','confidence',42,'diamond'],
  ['icuae','ICuAE','Currency Audit','confidence',42,'diamond'],
  ['ede','EDE','Epistemic\nDisclosure','confidence',48,'diamond'],
  ['postgres','PostgreSQL','Scan Results · History\nDrift · Analytics','storage',null,'cylinder'],
  ['fixtures','Golden Fixtures','Known-Good Baselines\nRFC Compliance Seeds','storage',null,'cylinder'],
  ['wayback','Internet Archive','Wayback Machine\nPermanent Record','storage',null,'cylinder'],
];
const PROTOS = ['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'];
// The client puts OUTPUTS in allLayoutNodes unconditionally (line 1053), even
// though SHOW_OUTPUTS is false and c4w is 0 — they participate in the pass.
const OUTS = [
  ['reports','Reports','Engineer · Executive\nRecon · Comparison'],
  ['jsonapi','JSON API','Analysis · Checksums\nSubdomains · Health'],
  ['seo','Schema.org','JSON-LD Structured Data\nGoogle · Rich Results'],
  ['badges','SVG Badges','Posture Indicators\nEmbeddable'],
];

function mkNodes() {
  const out = DEF.map(([id,label,sub,zone,radius,shape]) => ({
    id, label, sub, zone,
    radius: radius ?? specById[id].radius,
    shape: shape,
  }));
  for (const id of PROTOS) {
    const s = specById[id];
    out.push({ id, label: s.label, sub: null, zone: 'protocol', radius: s.radius, shape: 'circle' });
  }
  for (const [id,label,sub] of OUTS) {
    out.push({ id, label, sub, zone: 'output', radius: specById[id].radius, shape: specById[id].shape === 'circle' ? 'circle' : specById[id].shape });
  }
  return out;
}

function box(shape, radius, label, sub, scale, fL, fS, DIAK) {
  const labelW = estimateTextWidth(label, fL);
  let subW = 0, n = 0;
  if (sub) { const ls = sub.split('\n'); n = ls.length; for (const l of ls) subW = Math.max(subW, estimateTextWidth(l, fS)); }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  const subExtra = n > 1 ? (n - 1) * (fS + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius*2, contentW); h = radius*2; }
  else if (shape === 'diamond') { w = Math.max(radius*DIAK, contentW+8); h = radius*DIAK + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius*2, contentW); h = radius*2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius*2.4, contentW); h = radius*1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.4, 40*scale); }
  else { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.3, 40*scale + subExtra); }
  return { w, h, contentW, subLines: n };
}

function layout(W, H, DIAK) {
  const SCL = Math.max(0.65, Math.min(1.15, W/1400));
  const FL = Math.round(Math.max(10, Math.min(15, 13*SCL)));
  const FS = Math.round(Math.max(8, Math.min(12, 10*SCL)));
  const all = mkNodes();
  for (const n of all) {
    const b = box(n.shape, n.radius, n.label, n.sub, SCL, FL, FS, DIAK);
    n._boxW=b.w; n._boxH=b.h; n._halfW=b.w/2; n._halfH=b.h/2; n._subLines=b.subLines;
  }
  const titleSafe = Math.max(H*0.07, 42), legendSafe = H*0.95, usableH = legendSafe-titleSafe;
  const globeR = Math.min(W*0.13*SCL, H*0.25*SCL, 180);
  const globeCx = W*0.04 + globeR;
  const pipeStart = globeCx + globeR + W*0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W*0.99 - consoleReserve, pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal*0.01);
  const SRC = all.filter(n=>n.zone==='source'), HUB = all.find(n=>n.id==='hub');
  const CONF = all.filter(n=>n.zone==='confidence');
  const srcNeed = Math.max(...SRC.map(n=>n._boxW), HUB._boxW)+26;
  const confNeed = Math.max(...CONF.map(n=>n._boxW))+26;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal*0.13), pipeTotal*0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal*0.14), pipeTotal*0.24);
  const c3w = pipeTotal - c1w - c2w - colGap*2;
  const col1L=pipeStart, col1R=col1L+c1w, col2L=col1R+colGap, col2R=col2L+c2w;
  const col3L=col2R+colGap, col3R=col3L+c3w, col4R=pipeEnd;
  const zones = {
    source:{bounds:{x1:col1L,x2:col1R,y1:titleSafe,y2:legendSafe}},
    hub:{bounds:{x1:col1L,x2:col1R,y1:titleSafe+usableH*0.20,y2:titleSafe+usableH*0.70}},
    engine:{bounds:{x1:col2L,x2:col2R,y1:titleSafe,y2:titleSafe+usableH*0.30}},
    confidence:{bounds:{x1:col2L,x2:col2R,y1:titleSafe+usableH*0.25,y2:titleSafe+usableH*0.75}},
    storage:{bounds:{x1:col2L-c2w*0.3,x2:col2R+c2w*0.3,y1:titleSafe+usableH*0.68,y2:legendSafe}},
    protocol:{bounds:{x1:col3L,x2:col3R,y1:titleSafe,y2:titleSafe+usableH*0.88}},
    output:{bounds:{x1:col3R+colGap,x2:col4R,y1:titleSafe,y2:legendSafe}},
  };
  const globalBounds={x1:col1L,x2:col4R,y1:titleSafe,y2:legendSafe};
  // re-partition block
  (function(){
    const byZone={}; all.forEach(nd=>{const zk=nd.zone||nd.id;(byZone[zk]=byZone[zk]||[]).push(nd);});
    function shelfNeed(m,zw,pad){let rowW=0,rowH=0,needH=0,rows=0;m.forEach(nd=>{const w=(nd._halfW||nd.radius)*2,h=(nd._halfH||nd.radius)*2;if(rowW>0&&rowW+pad+w>zw){needH+=rowH;rows++;rowW=0;rowH=0;}rowW+=rowW>0?pad+w:w;if(h>rowH)rowH=h;});needH+=rowH;rows++;return needH+pad*(rows-1);}
    const keys=[];for(const zk in byZone) if(zones[zk]&&zones[zk].bounds) keys.push(zk); keys.sort();
    const grouped={};
    keys.forEach(ka=>{if(grouped[ka])return;const a=zones[ka].bounds;const stack=[ka];
      keys.forEach(kb=>{if(kb===ka||grouped[kb])return;const b=zones[kb].bounds;
        const xOver=Math.min(a.x2,b.x2)-Math.max(a.x1,b.x1),minW=Math.min(a.x2-a.x1,b.x2-b.x1);
        const contains=(a.y1<=b.y1&&a.y2>=b.y2)||(b.y1<=a.y1&&b.y2>=a.y2);
        if(xOver>minW*0.6&&!contains) stack.push(kb);});
      if(stack.length<2)return; stack.sort((x,y)=>zones[x].bounds.y1-zones[y].bounds.y1);
      const anyDeficit=stack.some(zk=>{const zb=zones[zk].bounds;return shelfNeed(byZone[zk],zb.x2-zb.x1,0)>zb.y2-zb.y1;});
      if(!anyDeficit)return;
      const top=zones[stack[0]].bounds.y1, bottom=zones[stack[stack.length-1]].bounds.y2;
      let needs=null,usedPad=0;
      for(const p of [14,8,4,0]){const n=stack.map(zk=>{const zb=zones[zk].bounds;return shelfNeed(byZone[zk],zb.x2-zb.x1,p);});
        const total=n.reduce((s,v)=>s+v,0)+p*(stack.length-1); if(total<=bottom-top){needs=n;usedPad=p;break;}}
      if(!needs)return;
      const leftover=(bottom-top)-needs.reduce((s,v)=>s+v,0)-usedPad*(stack.length-1), share=leftover/stack.length;
      let cursor=top; stack.forEach((zk,i)=>{zones[zk].bounds.y1=cursor;zones[zk].bounds.y2=cursor+needs[i]+share;cursor=zones[zk].bounds.y2+usedPad;grouped[zk]=true;});
    });
  })();
  const profile = W>1000?'desktop':(W>600?'tablet':'mobile');
  const data = LAYOUTS[profile].nodeCenters, ref = LAYOUTS[profile].canvas;
  const usableW = W - consoleReserve;
  for(const nd of all){ const pos=data[nd.id]; if(!pos) continue;
    nd.targetX=(pos.x/ref.width)*usableW; nd.targetY=titleSafe+(pos.y/ref.height)*(legendSafe-titleSafe);
    const z=zones[nd.zone||nd.id];
    if(z&&z.bounds){const zw=z.bounds.x2-z.bounds.x1,zh=z.bounds.y2-z.bounds.y1;
      const zpx=Math.min(30,zw*0.15),zpy=Math.min(20,zh*0.15);
      if(z.bounds.x1+zpx<z.bounds.x2-zpx) nd.targetX=Math.max(z.bounds.x1+zpx,Math.min(z.bounds.x2-zpx,nd.targetX));
      if(z.bounds.y1+zpy<z.bounds.y2-zpy) nd.targetY=Math.max(z.bounds.y1+zpy,Math.min(z.bounds.y2-zpy,nd.targetY));}
    nd.targetX=Math.max(globalBounds.x1+10,Math.min(globalBounds.x2-10,nd.targetX));
    nd.targetY=Math.max(globalBounds.y1+10,Math.min(globalBounds.y2-10,nd.targetY));
  }
  const P=all.filter(n=>n.zone==='protocol');
  const minPX=Math.min(...P.map(p=>p.targetX)),maxPX=Math.max(...P.map(p=>p.targetX));
  const minPY=Math.min(...P.map(p=>p.targetY)),maxPY=Math.max(...P.map(p=>p.targetY));
  const pz=zones.protocol.bounds,padX=52*SCL,padY=44*SCL;
  const tx1=pz.x1+padX,tx2=pz.x2-padX,ty1=pz.y1+padY,ty2=pz.y2-padY;
  if(maxPX-minPX>1&&tx2-tx1>40) P.forEach(p=>{p.targetX=tx1+((p.targetX-minPX)/(maxPX-minPX))*(tx2-tx1);});
  if(maxPY-minPY>1&&ty2-ty1>40) P.forEach(p=>{p.targetY=ty1+((p.targetY-minPY)/(maxPY-minPY))*(ty2-ty1);});
  const overlapPad=14;
  for(let op=0;op<40;op++){let any=false;
    for(let i=0;i<all.length;i++)for(let j=i+1;j<all.length;j++){
      const a=all[i],b=all[j];
      const ohw=(a._halfW||a.radius)+(b._halfW||b.radius)+overlapPad;
      const ohh=(a._halfH||a.radius)+(b._halfH||b.radius)+overlapPad;
      const dx=Math.abs(b.targetX-a.targetX),dy=Math.abs(b.targetY-a.targetY);
      if(dx<ohw&&dy<ohh){const oX=ohw-dx,oY=ohh-dy,ps=0.7;
        if(oX<oY){const sx=(b.targetX>=a.targetX?1:-1)*oX*ps;a.targetX-=sx;b.targetX+=sx;}
        else{const sy=(b.targetY>=a.targetY?1:-1)*oY*ps;a.targetY-=sy;b.targetY+=sy;}
        any=true;}}
    if(!any)break;
    all.forEach(nd=>{const z=zones[nd.zone||nd.id];
      if(z&&z.bounds){const hw=nd._halfW||nd.radius,hh=nd._halfH||nd.radius;
        nd.targetX=Math.max(z.bounds.x1+hw,Math.min(z.bounds.x2-hw,nd.targetX));
        nd.targetY=Math.max(z.bounds.y1+hh,Math.min(z.bounds.y2-hh,nd.targetY));}
      nd.targetX=Math.max(globalBounds.x1+10,Math.min(globalBounds.x2-10,nd.targetX));
      nd.targetY=Math.max(globalBounds.y1+10,Math.min(globalBounds.y2-10,nd.targetY));});
  }
  return { all, SCL, FL, FS, profile, zones };
}

const R1 = Math.SQRT2 * 0.75; // 1.06066
// true shape intersection tests
function diamondR(n){ return n.radius*R1 + 0.4; }
function interDD(a,b){ return (Math.abs(a.targetX-b.targetX)+Math.abs(a.targetY-b.targetY)) - (diamondR(a)+diamondR(b)); }
function interDRect(d,r){
  const dx=Math.max(0, Math.abs(d.targetX-r.targetX)-r._halfW);
  const dy=Math.max(0, Math.abs(d.targetY-r.targetY)-r._halfH);
  return (dx+dy) - diamondR(d);
}
function interDCircle(d,c){
  const dx=Math.abs(d.targetX-c.targetX), dy=Math.abs(d.targetY-c.targetY);
  const l1=dx+dy-diamondR(d);
  const dist = l1<=0?0:l1/Math.SQRT2;
  return dist - c.radius;
}
function pen(d, o){
  if(o.shape==='diamond') return interDD(d,o);
  if(o.shape==='circle') return interDCircle(d,o);
  return interDRect(d,o);
}

const cases = [[1950,1020],[1950,900],[1950,750],[1600,900],[1233,750],[1100,800],[800,900],[420,1780]];
for (const K of [1.7, 2.1214]) {
  console.log(`\n############ DIAMOND FORMULA CONSTANT = ${K} ############`);
  for (const [W,H] of cases) {
    const L = layout(W,H,K);
    const dia = L.all.filter(n=>n.shape==='diamond');
    const hits=[];
    for(const d of dia) for(const o of L.all){ if(o===d) continue;
      const p = pen(d,o); if(p < 0) hits.push(`${d.id}~${o.id} penetration ${(-p).toFixed(2)}px`); }
    const seen=new Set(), uniq=hits.filter(h=>{const k=h.split(' ')[0].split('~').sort().join('~');if(seen.has(k))return false;seen.add(k);return true;});
    console.log(`W=${W} H=${H} [${L.profile}] diamond positions: ` + dia.map(d=>`${d.id}(${d.targetX.toFixed(1)},${d.targetY.toFixed(1)})`).join(' '));
    console.log(`   TRUE shape collisions: ${uniq.length? uniq.join(' | ') : 'none'}`);
    const cb=L.zones.confidence.bounds;
    const need=dia.concat(L.all.filter(n=>n.zone==='confidence'&&n.shape!=='diamond')).reduce((s,n)=>s+n._halfH*2,0);
    console.log(`   confidence band h=${(cb.y2-cb.y1).toFixed(1)}  sum(box h)=${need.toFixed(1)}  ${need>cb.y2-cb.y1?'*** BAND TOO SHORT — clamp inverts ***':''}`);
  }
}

console.log('\n########## DETAIL: confidence column, W=800 H=900 (tablet) ##########');
for (const K of [1.7, 2.1214]) {
  const L = layout(800, 900, K);
  const cb = L.zones.confidence.bounds;
  console.log(`K=${K} zone x[${cb.x1.toFixed(1)},${cb.x2.toFixed(1)}] y[${cb.y1.toFixed(1)},${cb.y2.toFixed(1)}]`);
  for (const n of L.all.filter(n=>n.zone==='confidence')) {
    const xlo=cb.x1+n._halfW, xhi=cb.x2-n._halfW, ylo=cb.y1+n._halfH, yhi=cb.y2-n._halfH;
    console.log(`   ${n.id.padEnd(6)} ${String(n.shape).padEnd(8)} half=(${n._halfW.toFixed(2)},${n._halfH.toFixed(2)}) pos=(${n.targetX.toFixed(1)},${n.targetY.toFixed(1)}) xclamp=[${xlo.toFixed(1)},${xhi.toFixed(1)}]${xlo>xhi?' INVERTED':''} yclamp=[${ylo.toFixed(1)},${yhi.toFixed(1)}]${ylo>yhi?' INVERTED':''}`);
  }
}
console.log('\n########## DETAIL: confidence column, W=1600 H=900 ##########');
for (const K of [1.7, 2.1214]) {
  const L = layout(1600, 900, K);
  const cb = L.zones.confidence.bounds;
  console.log(`K=${K} zone x[${cb.x1.toFixed(1)},${cb.x2.toFixed(1)}] y[${cb.y1.toFixed(1)},${cb.y2.toFixed(1)}]`);
  for (const n of L.all.filter(n=>n.zone==='confidence')) {
    const xlo=cb.x1+n._halfW, xhi=cb.x2-n._halfW;
    console.log(`   ${n.id.padEnd(6)} half=(${n._halfW.toFixed(2)},${n._halfH.toFixed(2)}) pos=(${n.targetX.toFixed(1)},${n.targetY.toFixed(1)}) xclamp=[${xlo.toFixed(1)},${xhi.toFixed(1)}]${xlo>xhi?' INVERTED -> pinned':''}`);
  }
}

console.log('\n########## Does the 40-iteration overlap pass even CONVERGE? (K=1.7, shipped) ##########');
for (const [W,H] of [[1950,1020],[1950,900],[1600,900],[1233,750],[800,900],[420,1780]]) {
  const L = layout(W,H,1.7);
  const rem=[];
  for(let i=0;i<L.all.length;i++)for(let j=i+1;j<L.all.length;j++){
    const a=L.all[i],b=L.all[j];
    const ohw=a._halfW+b._halfW+14, ohh=a._halfH+b._halfH+14;
    const dx=Math.abs(a.targetX-b.targetX), dy=Math.abs(a.targetY-b.targetY);
    if(dx<ohw&&dy<ohh) rem.push(`${a.id}/${b.id}`);
  }
  const bare=[];
  for(let i=0;i<L.all.length;i++)for(let j=i+1;j<L.all.length;j++){
    const a=L.all[i],b=L.all[j];
    if(a.zone==='output'||b.zone==='output') continue;
    const dx=Math.abs(a.targetX-b.targetX), dy=Math.abs(a.targetY-b.targetY);
    if(dx<a._halfW+b._halfW && dy<a._halfH+b._halfH) bare.push(`${a.id}/${b.id}`);
  }
  console.log(`W=${W} H=${H}: unresolved pad-14 AABB pairs after 40 iters = ${rem.length}; HARD (pad-0, non-output) AABB overlaps = ${bare.length}${bare.length?' -> '+bare.join(', '):''}`);
}
