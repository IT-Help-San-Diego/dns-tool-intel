// Adversarial verification of the "diamond AABB is 20% short" claim.
// Continues audit-client.mjs's replication of layoutAll() through the solver
// remap, the protocol rescale, and the 40-iteration overlap pass, then
// compares each diamond's MEASURED AABB against its DRAWN rotated-square ink.
import { run } from './audit-client.mjs';
import desktop from './output/desktop-layout.json' with { type: 'json' };
import tablet from './output/tablet-layout.json' with { type: 'json' };
import mobile from './output/mobile-layout.json' with { type: 'json' };

const LAYOUTS = { desktop, tablet, mobile };

function layout(W, H) {
  const r = run(W, H);
  const { zones, globalBounds, all, titleSafe, legendSafe, SCL } = r;
  const profile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
  const data = LAYOUTS[profile].nodeCenters;
  const ref = { w: LAYOUTS[profile].canvas.width, h: LAYOUTS[profile].canvas.height };
  const usableW = W - r.consoleReserve;

  for (const nd of all) {
    const pos = data[nd.id];
    if (!pos) continue;
    nd.targetX = (pos.x / ref.w) * usableW;
    nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
    const z = zones[nd.zone || nd.id];
    if (z && z.bounds) {
      const zw = z.bounds.x2 - z.bounds.x1, zh = z.bounds.y2 - z.bounds.y1;
      const zpx = Math.min(30, zw * 0.15), zpy = Math.min(20, zh * 0.15);
      if (z.bounds.x1 + zpx < z.bounds.x2 - zpx)
        nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
      if (z.bounds.y1 + zpy < z.bounds.y2 - zpy)
        nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
    }
    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
  }

  // protocol ellipse rescale
  const P = all.filter(n => n.zone === 'protocol');
  const minPX = Math.min(...P.map(p => p.targetX)), maxPX = Math.max(...P.map(p => p.targetX));
  const minPY = Math.min(...P.map(p => p.targetY)), maxPY = Math.max(...P.map(p => p.targetY));
  const pz = zones.protocol.bounds;
  const padX = 52 * SCL, padY = 44 * SCL;
  const tx1 = pz.x1 + padX, tx2 = pz.x2 - padX, ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
  if (maxPX - minPX > 1 && tx2 - tx1 > 40) P.forEach(p => { p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1); });
  if (maxPY - minPY > 1 && ty2 - ty1 > 40) P.forEach(p => { p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1); });

  // overlap pass, verbatim
  const overlapPad = 14;
  let iters = 0;
  for (let op = 0; op < 40; op++) {
    iters = op + 1;
    let anyOverlap = false;
    for (let oi = 0; oi < all.length; oi++) {
      for (let oj = oi + 1; oj < all.length; oj++) {
        const na = all[oi], nb = all[oj];
        const ohw = (na._halfW || na.radius) + (nb._halfW || nb.radius) + overlapPad;
        const ohh = (na._halfH || na.radius) + (nb._halfH || nb.radius) + overlapPad;
        const odx = Math.abs(nb.targetX - na.targetX), ody = Math.abs(nb.targetY - na.targetY);
        if (odx < ohw && ody < ohh) {
          const overX = ohw - odx, overY = ohh - ody, pushStr = 0.7;
          if (overX < overY) {
            const sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr;
            na.targetX -= sx; nb.targetX += sx;
          } else {
            const sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr;
            na.targetY -= sy; nb.targetY += sy;
          }
          anyOverlap = true;
        }
      }
    }
    if (!anyOverlap) break;
    all.forEach(nd => {
      const z = zones[nd.zone || nd.id];
      if (z && z.bounds) {
        const zHw = nd._halfW || nd.radius, zHh = nd._halfH || nd.radius;
        nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
        nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));
      }
      nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
      nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
    });
  }
  return { r, all, iters, profile, zones };
}

// Drawn ink half-extents, read off the draw functions.
const K = Math.SQRT2 * 0.75; // rotated-square half-extent factor = 1.06066
function drawnHalf(n, SCL, FONT_SUB) {
  if (n.shape === 'diamond') {
    const stroke = 0.8 / 2;
    // shape ink
    let hx = n.radius * K + stroke, hy = n.radius * K + stroke;
    // text ink: label at y - (subLines>1?8:5)*SCL, subs at y + 6*SCL + i*(FONT_SUB+2)
    const subLines = n.sub ? n.sub.split('\n').length : 0;
    const textBottom = 6 * SCL + (subLines - 1) * (FONT_SUB + 2) + FONT_SUB / 2;
    hy = Math.max(hy, textBottom);
    return { hx, hy };
  }
  return { hx: n._halfW, hy: n._halfH };
}

for (const [W, H] of [[1950, 900], [1950, 1050], [1233, 750], [800, 900], [420, 1780]]) {
  const { r, all, iters, profile } = layout(W, H);
  const SCL = r.SCL, FS = r.FONT_SUB;
  const dia = all.filter(n => n.shape === 'diamond');
  console.log(`\n===== W=${W} H=${H}  profile=${profile} SCL=${SCL.toFixed(3)} fonts=${r.FONT_LABEL}/${FS} overlapIters=${iters} c2w=${r.c2w.toFixed(1)} col2=[${r.col2L.toFixed(0)},${r.col2R.toFixed(0)}]`);
  for (const n of dia) {
    const d = drawnHalf(n, SCL, FS);
    console.log(`  ${n.id.padEnd(6)} r=${n.radius} pos=(${n.targetX.toFixed(1)},${n.targetY.toFixed(1)}) AABB half=(${n._halfW.toFixed(2)},${n._halfH.toFixed(2)})  drawn half=(${d.hx.toFixed(2)},${d.hy.toFixed(2)})  deficit=(${(d.hx - n._halfW).toFixed(2)},${(d.hy - n._halfH).toFixed(2)})`);
  }
  // pairwise: does DRAWN ink of any diamond collide with DRAWN ink of any other node?
  console.log('  -- pairwise drawn-ink AABB overlap involving a diamond --');
  let found = 0;
  for (const a of dia) {
    for (const b of all) {
      if (a === b) continue;
      if (b.zone === 'protocol' || b.zone === 'output') { /* different column, still check */ }
      const da = drawnHalf(a, SCL, FS), db = drawnHalf(b, SCL, FS);
      const ox = (da.hx + db.hx) - Math.abs(a.targetX - b.targetX);
      const oy = (da.hy + db.hy) - Math.abs(a.targetY - b.targetY);
      if (ox > 0 && oy > 0) {
        // also report what the MEASURED boxes said
        const mx = (a._halfW + b._halfW) - Math.abs(a.targetX - b.targetX);
        const my = (a._halfH + b._halfH) - Math.abs(a.targetY - b.targetY);
        console.log(`    ${a.id} x ${b.id}: drawn overlap ox=${ox.toFixed(2)} oy=${oy.toFixed(2)} | measured-AABB ox=${mx.toFixed(2)} oy=${my.toFixed(2)} (${mx > 0 && my > 0 ? 'ALSO overlapping by AABB' : 'AABBs are clear'})`);
        found++;
      }
    }
  }
  if (!found) console.log('    none');
}
