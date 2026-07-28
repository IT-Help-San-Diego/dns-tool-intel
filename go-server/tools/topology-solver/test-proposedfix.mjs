/* Does the PROPOSED FIX change rendered output?
   Variant A = shipped code.
   Variant B = the proposal verbatim: the SAME three stages wrapped in a
               fixed-point loop (N=6). Node test stays point-based, exactly
               as the shipped loop at topology.js:1511-1535 is.
   Variant C = B, plus the proposal's rejection path (skip fillText+push when
               the label is still "not clear" by the code's own predicate).
   Variant D = the node test made RECT-aware (pill half-extents added), single
               pass, no other change.
   Variant E = rect-aware AND iterated to a fixed point.
   Metric: fraction of drawn labels whose pill ink overlaps a drawn node. */
import fs from 'node:fs';
const src = fs.readFileSync('verify-labelpipe.mjs','utf8').replace(/const sizes = [\s\S]*$/,'export { buildScene };');
fs.writeFileSync('.mod-labelpipe.mjs', src);
const { buildScene } = await import('./.mod-labelpipe.mjs');

const PROTO_EDGES = [
  { from:'dmarc', to:'spf',    type:'hard', label:'alignment',     labelT:0.45 },
  { from:'dmarc', to:'dkim',   type:'hard', label:'alignment',     labelT:0.45 },
  { from:'dane',  to:'dnssec', type:'hard', label:'requires',      labelT:0.35 },
  { from:'bimi',  to:'dmarc',  type:'hard', label:'p=quarantine+', labelT:0.5 },
  { from:'tlsrpt',to:'mtasts', type:'soft', label:'reports',       labelT:0.5 },
  { from:'tlsrpt',to:'dane',   type:'soft', label:'reports',       labelT:0.4 },
  { from:'caa',   to:'dnssec', type:'soft', label:'strengthens',   labelT:0.5 },
];
function estimateTextWidth(text, fontSize){let t=0;for(const ch of text){if(ch===' ')t+=0.28;else if(/[mwMW]/.test(ch))t+=0.82;else if(/[iltfr!|'.,:;]/.test(ch))t+=0.32;else if(/[A-Z]/.test(ch))t+=0.72;else if(/[a-z]/.test(ch))t+=0.52;else if(/\d/.test(ch))t+=0.56;else t+=0.56;}return t*fontSize;}
function curveOff(S,from,to,type){ if(type==='flow')return null; const ip=id=>S.PROTOCOLS.some(p=>p.id===id); if(!ip(from.id)||!ip(to.id))return null;
  const mx=(from.x+to.x)/2,my=(from.y+to.y)/2,edx=to.x-from.x,edy=to.y-from.y,el=Math.hypot(edx,edy)||1,px=-edy/el,py=edx/el;
  let bo=0,cl=Infinity; for(const pn of S.PROTOCOLS){ if(pn.id===from.id||pn.id===to.id)continue; const dx=pn.x-mx,dy=pn.y-my,d=Math.hypot(dx,dy);
    if(d<pn.radius+50&&d<cl){cl=d;bo=((dx*px+dy*py)>0?-1:1)*Math.max(40,pn.radius+20);} } if(bo===0)return null; return {cx:mx+px*bo,cy:my+py*bo}; }
function pen(lx,ly,pw,ph,n){ if(n.shape==='circle'){ const cx=Math.max(lx-pw/2,Math.min(lx+pw/2,n.x)),cy=Math.max(ly-ph/2,Math.min(ly+ph/2,n.y)); return n.radius-Math.hypot(cx-n.x,cy-n.y);} const hw=n._halfW||n.radius,hh=n._halfH||n.radius;
  const ox=Math.min(lx+pw/2,n.x+hw)-Math.max(lx-pw/2,n.x-hw), oy=Math.min(ly+ph/2,n.y+hh)-Math.max(ly-ph/2,n.y-hh); if(ox<=0||oy<=0)return -Math.max(-ox,-oy); return Math.min(ox,oy); }
function worst(S,lx,ly,pw,ph){ let b=-Infinity,id=null; for(const n of S.all){ if(n.zone==='output')continue; const p=pen(lx,ly,pw,ph,n); if(p>b){b=p;id=n.id;} } return {pen:b,id}; }

function nodeEscape(S,lx,ly,pad){ // pad = {w,h} pill half-extents added to the node box (0 for the shipped point test)
  for(const nn of S.all){
    const nhw=(nn._halfW||nn.radius)+12+pad.w, nhh=(nn._halfH||nn.radius)+12+pad.h;
    if(nn.shape==='circle'){
      const R=nn.radius+Math.max(pad.w,pad.h);
      const ldx=lx-nn.x,ldy=ly-nn.y,ld=Math.hypot(ldx,ldy);
      if(ld<R+24&&ld>0.1){ const k=(R+28)/ld; lx=nn.x+ldx*k; ly=nn.y+ldy*k; }
    } else {
      const ndx=lx-nn.x,ndy=ly-nn.y;
      if(Math.abs(ndx)<nhw&&Math.abs(ndy)<nhh){ if(Math.abs(ndx)/nhw>Math.abs(ndy)/nhh) lx=nn.x+(ndx>=0?1:-1)*(nhw+6); else ly=nn.y+(ndy>=0?1:-1)*(nhh+6); }
    }
  }
  return [lx,ly];
}
function labelSep(placed,lx,ly,pw,ph){ for(let p=0;p<3;p++){ let m=false; for(const pl of placed){
  const ox=Math.min(lx+pw/2,pl.x+pl.w/2)-Math.max(lx-pw/2,pl.x-pl.w/2), oy=Math.min(ly+ph/2,pl.y+pl.h/2)-Math.max(ly-ph/2,pl.y-pl.h/2);
  if(ox>0&&oy>0){ if(ox<oy) lx+=(lx>=pl.x?1:-1)*(ox+6); else ly+=(ly>=pl.y?1:-1)*(oy+6); m=true; } } if(!m)break; } return [lx,ly]; }
// the code's OWN clearance predicate (point vs inflated node box) -- what a
// "reject if not clear" path built on the existing test would actually check
function pointClear(S,lx,ly){ for(const nn of S.all){ const nhw=(nn._halfW||nn.radius)+12,nhh=(nn._halfH||nn.radius)+12;
  if(nn.shape==='circle'){ if(Math.hypot(lx-nn.x,ly-nn.y)<nn.radius+24) return false; } else if(Math.abs(lx-nn.x)<nhw&&Math.abs(ly-nn.y)<nhh) return false; } return true; }

function run(S,variant){
  const placed=[]; let drawn=0, onNode=0, suppressed=0;
  for(const e of PROTO_EDGES){
    const from=S.byId[e.from],to=S.byId[e.to],c=curveOff(S,from,to,e.type),t=e.labelT||0.5;
    let lx,ly;
    if(c){lx=(1-t)*(1-t)*from.x+2*(1-t)*t*c.cx+t*t*to.x; ly=(1-t)*(1-t)*from.y+2*(1-t)*t*c.cy+t*t*to.y;}
    else {lx=from.x+(to.x-from.x)*t; ly=from.y+(to.y-from.y)*t;}
    ly-=8*S.SCL;
    const fs2=Math.max(8,S.FONT_SUB-1), pw=estimateTextWidth(e.label,fs2)+10*S.SCL, ph=fs2+8*S.SCL;
    const zeroPad={w:0,h:0}, rectPad={w:pw/2,h:ph/2};
    const clamp=()=>{ ly=Math.max(20,Math.min(S.H-20,ly)); lx=Math.max(30,Math.min(S.W-30,lx)); };
    if(variant==='A'){ [lx,ly]=nodeEscape(S,lx,ly,zeroPad); [lx,ly]=labelSep(placed,lx,ly,pw,ph); clamp(); }
    else if(variant==='B'||variant==='C'){
      for(let it=0;it<6;it++){ const px=lx,py=ly; [lx,ly]=nodeEscape(S,lx,ly,zeroPad); [lx,ly]=labelSep(placed,lx,ly,pw,ph); clamp(); if(Math.hypot(lx-px,ly-py)<0.01)break; }
    }
    else if(variant==='D'){ [lx,ly]=nodeEscape(S,lx,ly,rectPad); [lx,ly]=labelSep(placed,lx,ly,pw,ph); clamp(); }
    else if(variant==='E'){ for(let it=0;it<6;it++){ const px=lx,py=ly; [lx,ly]=nodeEscape(S,lx,ly,rectPad); [lx,ly]=labelSep(placed,lx,ly,pw,ph); clamp(); if(Math.hypot(lx-px,ly-py)<0.01)break; } }
    else if(variant==='F'){ for(let it=0;it<6;it++){ const px=lx,py=ly; [lx,ly]=nodeEscape(S,lx,ly,zeroPad); if(Math.hypot(lx-px,ly-py)<0.01)break; } [lx,ly]=labelSep(placed,lx,ly,pw,ph); clamp(); }
    if(variant==='C' && !pointClear(S,lx,ly)){ suppressed++; continue; }
    drawn++; if(worst(S,lx,ly,pw,ph).pen>0) onNode++;
    placed.push({x:lx,y:ly,w:pw,h:ph});
  }
  return {drawn,onNode,suppressed};
}

const res={};
for(const v of ['A','B','C','D','E','F']) res[v]={drawn:0,onNode:0,suppressed:0};
const split={}; for(const v of ['A','B','F']) split[v]={coll:[0,0],spread:[0,0]};
let n=0;
for(let W=420;W<=2200;W+=20) for(const H of [700,750,800,900,1000,1100]){
  n++;
  for(const v of ['A','B','C','D','E','F']){ const S=buildScene(W,H); const r=run(S,v); res[v].drawn+=r.drawn; res[v].onNode+=r.onNode; res[v].suppressed+=r.suppressed;
    if(split[v]){ const xs=S.PROTOCOLS.map(p=>p.x); const k=(Math.max(...xs)-Math.min(...xs))<120?'coll':'spread'; split[v][k][0]+=r.drawn; split[v][k][1]+=r.onNode; } }
}
console.log('%d viewports, 7 labels each = %d placements\n', n, n*7);
const names={A:'A shipped (1-pass node, sep, clamp)          ',
             B:'B PROPOSED fixed-point loop, N=6 (no reject) ',
             C:'C PROPOSED loop + PROPOSED reject-if-not-clear',
             D:'D node test made RECT-aware (1 pass)          ',
             E:'E rect-aware + fixed-point loop               ',
             F:'F iterate ONLY stage1 (node escape), rest once'};
for(const v of ['A','B','C','D','E','F']){
  const r=res[v];
  console.log(names[v]+' drawn '+String(r.drawn).padStart(4)+'  suppressed '+String(r.suppressed).padStart(4)+
    '  pill-on-node '+String(r.onNode).padStart(4)+'  ('+(100*r.onNode/Math.max(1,r.drawn)).toFixed(1)+'% of drawn)');
}
console.log('\nSPLIT collapsed-protocol-column vs spread-ellipse (pill-on-node % of drawn):');
for(const v of ['A','B','F']){ const c=split[v].coll, s2=split[v].spread;
  console.log('  '+v+'  collapsed '+(100*c[1]/c[0]).toFixed(1)+'%  ('+c[1]+'/'+c[0]+')   spread '+(100*s2[1]/s2[0]).toFixed(1)+'%  ('+s2[1]+'/'+s2[0]+')'); }
