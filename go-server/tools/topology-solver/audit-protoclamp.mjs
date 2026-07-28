// Independent port of topology.js layoutAll() x-arithmetic (lines 910-1272)
// as of the current worktree. Written fresh from source to audit the
// "protocol x-clamp collapses to one column" claim.
import fs from 'node:fs';

let WIDTH_FUDGE = 1.0;
function estimateTextWidth(text, fontSize) {
  let total = 0;
  for (const ch of text) {
    if (ch === ' ') total += 0.28;
    else if (/[mwMW]/.test(ch)) total += 0.82;
    else if (/[iltfr!|'.,:;]/.test(ch)) total += 0.32;
    else if (/[A-Z]/.test(ch)) total += 0.72;
    else if (/[a-z]/.test(ch)) total += 0.52;
    else if (/\d/.test(ch)) total += 0.56;
    else total += 0.56;
  }
  return total * fontSize * WIDTH_FUDGE;
}

const LAYOUTS = {
  desktop: JSON.parse(fs.readFileSync(new URL('./output/desktop-layout.json', import.meta.url))),
  tablet:  JSON.parse(fs.readFileSync(new URL('./output/tablet-layout.json', import.meta.url))),
  mobile:  JSON.parse(fs.readFileSync(new URL('./output/mobile-layout.json', import.meta.url))),
};

const SHOW_OUTPUTS = false; // topology.js:2117

function mk() {
  const SOURCES = [
    { id:'root',  label:'Root / TLD',      sub:'IANA Root Zone\nTLD Registries' },
    { id:'rdap',  label:'RDAP / WHOIS',    sub:'Registration Data\nAccess Protocol' },
    { id:'ct',    label:'CT / Subdomains', sub:'crt.sh · Certspotter\nTransparency Logs' },
    { id:'cisa',  label:'CISA / Threat',   sub:'BOD 19-02\nIP Scanner Detection' },
    { id:'probes',label:'Probe Fleet',     sub:'SMTP · DANE · TLS\nNmap · testssl.sh' },
  ].map(s => ({...s, zone:'source', radius:30, shape:'rect'}));
  const HUB = { id:'hub', label:'DNS Resolvers', sub:'Signal Aggregation', zone:'hub', radius:44, shape:'hub' };
  const ENGINE = { id:'engine', label:'ICIE', sub:'Analysis Engine', zone:'engine', radius:54, shape:undefined };
  const CONFIDENCE = [
    { id:'ietf',  label:'IETF Metadata', sub:'RFC Status · Errata\nDraft Tracker' },
    { id:'icae',  label:'ICAE',  sub:'Accuracy Audit' },
    { id:'icuae', label:'ICuAE', sub:'Currency Audit' },
    { id:'ede',   label:'EDE',   sub:'Epistemic\nDisclosure' },
  ].map(c => ({...c, zone:'confidence',
        radius: c.id==='ede'?48 : c.id==='ietf'?36 : 42,
        shape:  c.id==='ietf'?'rect':'diamond'}));
  const STORAGE = [
    { id:'postgres', label:'PostgreSQL',       sub:'Scan Results · History\nDrift · Analytics' },
    { id:'fixtures', label:'Golden Fixtures',  sub:'Known-Good Baselines\nRFC Compliance Seeds' },
    { id:'wayback',  label:'Internet Archive', sub:'Wayback Machine\nPermanent Record' },
  ].map(s => ({...s, zone:'storage',
        radius: s.id==='postgres'?36 : s.id==='wayback'?32 : 34, shape:'cylinder'}));
  const PROTOCOLS = ['SPF','DKIM','DMARC','DNSSEC','DANE','MTA-STS','TLS-RPT','BIMI','CAA']
    .map((l,i) => ({ id:['spf','dkim','dmarc','dnssec','dane','mtasts','tlsrpt','bimi','caa'][i],
                     label:l, sub:null, zone:'protocol', radius:36, shape:'circle' }));
  const OUTPUTS = [
    { id:'reports', label:'Reports',    sub:'Engineer · Executive\nRecon · Comparison' },
    { id:'jsonapi', label:'JSON API',   sub:'Analysis · Checksums\nSubdomains · Health' },
    { id:'seo',     label:'Schema.org', sub:'JSON-LD Structured Data\nGoogle · Rich Results' },
    { id:'badges',  label:'SVG Badges', sub:'Posture Indicators\nEmbeddable' },
  ].map(o => ({...o, zone:'output', radius:36, shape:'hexagon'}));
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

// topology.js:677-718
function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub) {
  const labelW = estimateTextWidth(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const l of lines) { const sw = estimateTextWidth(l, fontSub); if (sw > subW) subW = sw; }
  }
  const contentW = Math.max(labelW, subW) + 24*scale;
  const subExtra = subLineCount > 1 ? (subLineCount-1)*(fontSub+2) : 0;
  let w, h;
  if (shape === 'circle')        { w = Math.max(radius*2, contentW);   h = radius*2; }
  else if (shape === 'diamond')  { w = Math.max(radius*1.7, contentW+8); h = radius*1.7 + subExtra; }
  else if (shape === 'hexagon')  { w = Math.max(radius*2, contentW);   h = radius*2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius*2.4, contentW); h = radius*1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.4, 40*scale); }
  else { w = Math.max(radius*2.4, contentW); h = Math.max(radius*1.3, 40*scale + (subLineCount>1 ? (subLineCount-1)*(fontSub+2) : 0)); }
  return { w, h, halfW: w/2, halfH: h/2 };
}

function build(W, H, opts = {}) {
  const N = mk();
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = N;

  const SCL = Math.max(0.65, Math.min(1.15, W/1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13*SCL)));
  const FONT_SUB   = Math.round(Math.max(8,  Math.min(12, 10*SCL)));
  const measure = n => { const b = computeNodeBox(n.shape, n.radius, n.label, n.sub||null, SCL, FONT_LABEL, FONT_SUB);
                         n._boxW=b.w; n._boxH=b.h; n._halfW=b.halfW; n._halfH=b.halfH; };

  const titleSafe = Math.max(H*0.07, 42);
  const legendSafe = H*0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W*0.13*SCL, H*0.25*SCL, 180);
  const globe = { R: globeR, cx: W*0.04 + globeR, cy: titleSafe + usableH*0.42 };

  const pipeStart = globe.cx + globeR + W*0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W*0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal*0.01);

  SOURCES.forEach(measure); measure(HUB); CONFIDENCE.forEach(measure);
  const srcNeed = Math.max(...SOURCES.map(n=>n._boxW), HUB._boxW) + 26;
  const confNeed = Math.max(...CONFIDENCE.map(n=>n._boxW)) + 26;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal*0.13), pipeTotal*0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal*0.14), pipeTotal*0.24);
  const c4w = SHOW_OUTPUTS ? pipeTotal*0.16 : 0;
  const c3w = pipeTotal - c1w - c2w - c4w - colGap*(SHOW_OUTPUTS?3:2);
  const col1L = pipeStart, col1R = col1L + c1w;
  const col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w;
  const col4L = col3R + colGap, col4R = pipeEnd;

  const srcCx = (col1L+col1R)/2;
  const srcSpacing = usableH/(SOURCES.length+1);
  SOURCES.forEach((s,i)=>{ s.targetX=srcCx; s.targetY=titleSafe+(i+1)*srcSpacing; });
  HUB.targetX=srcCx; HUB.targetY=globe.cy;
  const procCx = (col2L+col2R)/2;
  ENGINE.targetX=procCx; ENGINE.targetY=titleSafe+usableH*0.15;
  const confSpread = Math.max(40,(col2R-col2L)*0.32);
  const confY = titleSafe+usableH*0.42;
  CONFIDENCE[0].targetX=procCx;               CONFIDENCE[0].targetY=confY-usableH*0.06;
  CONFIDENCE[1].targetX=procCx-confSpread*0.5;CONFIDENCE[1].targetY=confY+usableH*0.06;
  CONFIDENCE[2].targetX=procCx+confSpread*0.5;CONFIDENCE[2].targetY=confY+usableH*0.06;
  CONFIDENCE[3].targetX=procCx;               CONFIDENCE[3].targetY=confY+usableH*0.18;
  const storeY = titleSafe+usableH*0.78;
  const storeSpread = Math.max(confSpread*0.8,60);
  STORAGE[0].targetX=procCx;              STORAGE[0].targetY=storeY;
  STORAGE[1].targetX=procCx-storeSpread;  STORAGE[1].targetY=storeY+usableH*0.10;
  STORAGE[2].targetX=procCx+storeSpread;  STORAGE[2].targetY=storeY+usableH*0.10;
  const protoCx=(col3L+col3R)/2, protoCy=titleSafe+usableH*0.42;
  const protoRx=(col3R-col3L)*0.38, protoRy=usableH*0.28;
  const angleMap=[-130,-90,-50,-10,30,70,110,150,190];
  const DEG=Math.PI/180;
  PROTOCOLS.forEach((p,i)=>{ const a=angleMap[i]*DEG;
    p.targetX=protoCx+protoRx*Math.cos(a); p.targetY=protoCy+protoRy*Math.sin(a); });
  const handAuthored = PROTOCOLS.map(p=>({id:p.id,x:p.targetX,y:p.targetY}));
  const outCx=(col4L+col4R)/2, outSpacing=usableH/(OUTPUTS.length+1);
  OUTPUTS.forEach((o,i)=>{ o.targetX=outCx; o.targetY=titleSafe+(i+1)*outSpacing; });

  const globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };
  const zones = {
    source:     { bounds:{x1:col1L,x2:col1R,y1:titleSafe,y2:legendSafe} },
    hub:        { bounds:{x1:col1L,x2:col1R,y1:titleSafe+usableH*0.20,y2:titleSafe+usableH*0.70} },
    engine:     { bounds:{x1:col2L,x2:col2R,y1:titleSafe,y2:titleSafe+usableH*0.30} },
    confidence: { bounds:{x1:col2L,x2:col2R,y1:titleSafe+usableH*0.25,y2:titleSafe+usableH*0.75} },
    storage:    { bounds:{x1:col2L-c2w*0.3,x2:col2R+c2w*0.3,y1:titleSafe+usableH*0.68,y2:legendSafe} },
    protocol:   { bounds:{x1:col3L,x2:col3R,y1:titleSafe,y2:titleSafe+usableH*0.88} },
    output:     { bounds:{x1:col4L,x2:col4R,y1:titleSafe,y2:legendSafe} },
  };

  const allLayoutNodes = SOURCES.concat([HUB,ENGINE],CONFIDENCE,STORAGE,PROTOCOLS,OUTPUTS);
  allLayoutNodes.forEach(measure);

  // ---- shelf re-partition block (topology.js:1069-1151) : y only ----
  (function(){
    const byZone={};
    allLayoutNodes.forEach(nd=>{ const zk=nd.zone||nd.id; (byZone[zk]=byZone[zk]||[]).push(nd); });
    function shelfNeed(members,zw,pad){
      let rowW=0,rowH=0,needH=0,rows=0;
      members.forEach(nd=>{ const w=(nd._halfW||nd.radius)*2, h=(nd._halfH||nd.radius)*2;
        if(rowW>0 && rowW+pad+w>zw){ needH+=rowH; rows++; rowW=0; rowH=0; }
        rowW += rowW>0 ? pad+w : w; if(h>rowH) rowH=h; });
      needH+=rowH; rows++; return needH+pad*(rows-1);
    }
    const keys=[]; for(const zk in byZone) if(zones[zk]&&zones[zk].bounds) keys.push(zk);
    keys.sort();
    const grouped={};
    keys.forEach(ka=>{
      if(grouped[ka]) return;
      const a=zones[ka].bounds; const stack=[ka];
      keys.forEach(kb=>{ if(kb===ka||grouped[kb]) return; const b=zones[kb].bounds;
        const xOver=Math.min(a.x2,b.x2)-Math.max(a.x1,b.x1);
        const minW=Math.min(a.x2-a.x1,b.x2-b.x1);
        const contains=(a.y1<=b.y1&&a.y2>=b.y2)||(b.y1<=a.y1&&b.y2>=a.y2);
        if(xOver>minW*0.6 && !contains) stack.push(kb); });
      if(stack.length<2) return;
      stack.sort((x,y)=>zones[x].bounds.y1-zones[y].bounds.y1);
      const anyDeficit=stack.some(zk=>{const zb=zones[zk].bounds; return shelfNeed(byZone[zk],zb.x2-zb.x1,0)>zb.y2-zb.y1;});
      if(!anyDeficit) return;
      const top=zones[stack[0]].bounds.y1, bottom=zones[stack[stack.length-1]].bounds.y2;
      let needs=null,usedPad=0;
      for(const p of [14,8,4,0]){
        const n=stack.map(zk=>{const zb=zones[zk].bounds; return shelfNeed(byZone[zk],zb.x2-zb.x1,p);});
        const total=n.reduce((s,v)=>s+v,0)+p*(stack.length-1);
        if(total<=bottom-top){ needs=n; usedPad=p; break; }
      }
      if(!needs) return;
      const leftover=(bottom-top)-needs.reduce((s,v)=>s+v,0)-usedPad*(stack.length-1);
      const share=leftover/stack.length;
      let cursor=top;
      stack.forEach((zk,i)=>{ zones[zk].bounds.y1=cursor; zones[zk].bounds.y2=cursor+needs[i]+share;
        cursor=zones[zk].bounds.y2+usedPad; grouped[zk]=true; });
    });
  })();

  const solverProfile = W>1000 ? 'desktop' : (W>600 ? 'tablet' : 'mobile');
  const L = LAYOUTS[solverProfile];
  const solverData = L.nodeCenters;
  const ref = { w: L.canvas.width, h: L.canvas.height };
  const usableW = W - consoleReserve;

  const preClamp = {}, postClamp = {};
  allLayoutNodes.forEach(nd=>{
    const pos = solverData[nd.id];
    if(!pos) return;
    nd.targetX = (pos.x/ref.w)*usableW;
    nd.targetY = titleSafe + (pos.y/ref.h)*(legendSafe-titleSafe);
    if (nd.zone==='protocol') preClamp[nd.id]=nd.targetX;
    const z = zones[nd.zone||nd.id];
    if(z&&z.bounds){
      const zw=z.bounds.x2-z.bounds.x1, zh=z.bounds.y2-z.bounds.y1;
      const zpx=Math.min(30,zw*0.15), zpy=Math.min(20,zh*0.15);
      if(z.bounds.x1+zpx < z.bounds.x2-zpx) nd.targetX=Math.max(z.bounds.x1+zpx,Math.min(z.bounds.x2-zpx,nd.targetX));
      if(z.bounds.y1+zpy < z.bounds.y2-zpy) nd.targetY=Math.max(z.bounds.y1+zpy,Math.min(z.bounds.y2-zpy,nd.targetY));
    }
    nd.targetX=Math.max(globalBounds.x1+10,Math.min(globalBounds.x2-10,nd.targetX));
    nd.targetY=Math.max(globalBounds.y1+10,Math.min(globalBounds.y2-10,nd.targetY));
    if (nd.zone==='protocol') postClamp[nd.id]=nd.targetX;
  });

  const pxs=PROTOCOLS.map(p=>p.targetX), pys=PROTOCOLS.map(p=>p.targetY);
  const minPX=Math.min(...pxs), maxPX=Math.max(...pxs);
  const minPY=Math.min(...pys), maxPY=Math.max(...pys);
  const pz=zones.protocol.bounds;
  const padX=52*SCL, padY=44*SCL;
  const tx1=pz.x1+padX, tx2=pz.x2-padX, ty1=pz.y1+padY, ty2=pz.y2-padY;
  const rescaleXRan = (maxPX-minPX>1 && tx2-tx1>40);
  if(rescaleXRan) PROTOCOLS.forEach(p=>{ p.targetX = tx1 + ((p.targetX-minPX)/(maxPX-minPX))*(tx2-tx1); });
  const rescaleYRan = (maxPY-minPY>1 && ty2-ty1>40);
  if(rescaleYRan) PROTOCOLS.forEach(p=>{ p.targetY = ty1 + ((p.targetY-minPY)/(maxPY-minPY))*(ty2-ty1); });

  const postRescale = PROTOCOLS.map(p=>({id:p.id,x:p.targetX,y:p.targetY}));

  // ---- overlap pass (topology.js:1233-1272) ----
  const overlapPad=14;
  let opUsed=0;
  for(let op=0;op<40;op++){
    opUsed=op+1;
    let anyOverlap=false;
    for(let oi=0;oi<allLayoutNodes.length;oi++) for(let oj=oi+1;oj<allLayoutNodes.length;oj++){
      const na=allLayoutNodes[oi], nb=allLayoutNodes[oj];
      const ohw=(na._halfW||na.radius)+(nb._halfW||nb.radius)+overlapPad;
      const ohh=(na._halfH||na.radius)+(nb._halfH||nb.radius)+overlapPad;
      const odx=Math.abs(nb.targetX-na.targetX), ody=Math.abs(nb.targetY-na.targetY);
      if(odx<ohw && ody<ohh){
        const overX=ohw-odx, overY=ohh-ody, pushStr=0.7;
        if(overX<overY){ const sx=(nb.targetX>=na.targetX?1:-1)*overX*pushStr; na.targetX-=sx; nb.targetX+=sx; }
        else { const sy=(nb.targetY>=na.targetY?1:-1)*overY*pushStr; na.targetY-=sy; nb.targetY+=sy; }
        anyOverlap=true;
      }
    }
    if(!anyOverlap) break;
    allLayoutNodes.forEach(nd=>{
      const z=zones[nd.zone||nd.id];
      if(z&&z.bounds){
        const zHw=nd._halfW||nd.radius, zHh=nd._halfH||nd.radius;
        nd.targetX=Math.max(z.bounds.x1+zHw,Math.min(z.bounds.x2-zHw,nd.targetX));
        nd.targetY=Math.max(z.bounds.y1+zHh,Math.min(z.bounds.y2-zHh,nd.targetY));
      }
      nd.targetX=Math.max(globalBounds.x1+10,Math.min(globalBounds.x2-10,nd.targetX));
      nd.targetY=Math.max(globalBounds.y1+10,Math.min(globalBounds.y2-10,nd.targetY));
    });
  }

  return { W,H,SCL,solverProfile,consoleReserve,usableW,ref,
           pipeStart,pipeEnd,col1L,col1R,col2L,col2R,col3L,col3R,col4R,
           c1w,c2w,srcNeed,confNeed,
           zpxProto: Math.min(30,(col3R-col3L)*0.15),
           preClamp,postClamp,minPX,maxPX,rescaleXRan,rescaleYRan,tx1,tx2,
           handAuthored, postRescale, opUsed,
           PROTOCOLS: PROTOCOLS.map(p=>({id:p.id,x:p.targetX,y:p.targetY,hw:p._halfW,hh:p._halfH})) };
}

function spread(a){ return Math.max(...a)-Math.min(...a); }
function distinct(a,tol=0.5){ const s=[]; a.forEach(v=>{ if(!s.some(u=>Math.abs(u-v)<tol)) s.push(v); }); return s.length; }

function report(W,H){
  const S = build(W,H);
  const pre = Object.values(S.preClamp), post = Object.values(S.postClamp);
  const lowBound = S.col3L + S.zpxProto, hiBound = S.col3R - S.zpxProto;
  const nAtLow = post.filter(v=>Math.abs(v-lowBound)<0.01).length;
  const fx = S.PROTOCOLS.map(p=>p.x), fy = S.PROTOCOLS.map(p=>p.y);
  let ov=0, worst=0;
  for(let i=0;i<S.PROTOCOLS.length;i++)for(let j=i+1;j<S.PROTOCOLS.length;j++){
    const a=S.PROTOCOLS[i],b=S.PROTOCOLS[j];
    const d=Math.hypot(a.x-b.x,a.y-b.y);
    if(d<72){ov++; if(72-d>worst)worst=72-d;}
  }
  console.log(`W=${W} H=${H} prof=${S.solverProfile} SCL=${S.SCL.toFixed(3)} res=${S.consoleReserve} usableW=${S.usableW}`);
  console.log(`  c1w=${S.c1w.toFixed(1)}(need ${S.srcNeed.toFixed(1)}) c2w=${S.c2w.toFixed(1)}(need ${S.confNeed.toFixed(1)}) col3=[${S.col3L.toFixed(1)},${S.col3R.toFixed(1)}] zw=${(S.col3R-S.col3L).toFixed(1)} clampWin=[${lowBound.toFixed(1)},${hiBound.toFixed(1)}]`);
  console.log(`  preClampX  span ${Math.min(...pre).toFixed(1)}..${Math.max(...pre).toFixed(1)}  #belowLow=${pre.filter(v=>v<lowBound).length}/9  #aboveHi=${pre.filter(v=>v>hiBound).length}/9`);
  console.log(`  postClampX distinct=${distinct(post)}  #atLowBound=${nAtLow}  spread=${spread(post).toFixed(2)}  rescaleX=${S.rescaleXRan} tx=[${S.tx1.toFixed(1)},${S.tx2.toFixed(1)}]`);
  console.log(`  postRescaleX distinct=${distinct(S.postRescale.map(p=>p.x))} spread=${spread(S.postRescale.map(p=>p.x)).toFixed(1)}`);
  console.log(`  FINAL(after ${S.opUsed} overlap iters) x span ${spread(fx).toFixed(1)} distinctX=${distinct(fx,4)}  y span ${spread(fy).toFixed(1)}  circleOverlaps=${ov}/36 worstPen=${worst.toFixed(1)}`);
  console.log(`  FINAL pts: ` + S.PROTOCOLS.map(p=>`${p.id}(${p.x.toFixed(0)},${p.y.toFixed(0)})`).join(' '));
  return { S, ov, worst, spreadX: spread(fx), nAtLow, preBelow: pre.filter(v=>v<lowBound).length };
}

const arg = process.argv[2];
if (arg === 'sweep') {
  console.log('W\tprof\tpreBelowLow\tpostDistinct\tpostSpread\trescaleX\tfinalXspread\tfinalDistinctX\tcircOverlaps\tworstPen');
  for(let W=700; W<=2000; W+=25){
    const S = build(W,900);
    const post = Object.values(S.postClamp);
    const pre = Object.values(S.preClamp);
    const lowBound = S.col3L + S.zpxProto, hiBound = S.col3R - S.zpxProto;
    const fx=S.PROTOCOLS.map(p=>p.x);
    let ov=0,worst=0;
    for(let i=0;i<9;i++)for(let j=i+1;j<9;j++){const a=S.PROTOCOLS[i],b=S.PROTOCOLS[j];
      const d=Math.hypot(a.x-b.x,a.y-b.y); if(d<72){ov++; if(72-d>worst)worst=72-d;}}
    console.log([W,S.solverProfile,pre.filter(v=>v<lowBound).length,distinct(post),spread(post).toFixed(1),
                 S.rescaleXRan,spread(fx).toFixed(1),distinct(fx,4),ov,worst.toFixed(1)].join('\t'));
  }
} else if (arg === 'fudge') {
  for (const f of [0.85,0.95,1.0,1.05,1.15,1.3]) {
    WIDTH_FUDGE = f;
    for (const [W,H] of [[1918,900],[1950,900],[1440,900],[1233,750],[800,750]]) {
      const S = build(W,H);
      const pre=Object.values(S.preClamp), post=Object.values(S.postClamp);
      const lowBound=S.col3L+S.zpxProto;
      const fx=S.PROTOCOLS.map(p=>p.x);
      let ov=0; for(let i=0;i<9;i++)for(let j=i+1;j<9;j++){const a=S.PROTOCOLS[i],b=S.PROTOCOLS[j];
        if(Math.hypot(a.x-b.x,a.y-b.y)<72) ov++;}
      console.log(`fudge=${f} W=${W} col3L=${S.col3L.toFixed(1)} low=${lowBound.toFixed(1)} preBelow=${pre.filter(v=>v<lowBound).length}/9 postDistinct=${distinct(post)} finalXspread=${spread(fx).toFixed(1)} circOv=${ov}`);
    }
    console.log('');
  }
} else {
  for (const [W,H] of [[1918,900],[1950,900],[1903,940],[1600,900],[1500,900],[1440,900],[1300,900],[1233,750],[1100,900],[1010,900],[800,750],[500,900]]) {
    report(W,H); console.log('');
  }
}
