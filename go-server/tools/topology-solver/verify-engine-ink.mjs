// Ink-vs-ink check: does the ENGINE's drawn circle actually intersect the
// ICAE/ICuAE diamonds' drawn ink, or is the AABB shortfall only bookkeeping?
//
// ENGINE ink   : circle centred (0,0), radius 54 + 3 (pulse) + 0.6 (half stroke) = 57.6
// diamond ink  : drawConfidenceNode translates to (dx,dy), rotates 45 deg, rects
//                (-s,-s,2s,2s) with s = radius*0.75.  In world space that is the
//                region |x-dx| + |y-dy| <= s*sqrt(2), plus half of lineWidth 0.8.
//
// Distance from origin to that diamond region, exact.
function distPointToDiamond(cx, cy, half) {
  // diamond region: |x-cx| + |y-cy| <= half   (L1 ball)
  const u = Math.abs(0 - cx), v = Math.abs(0 - cy);
  if (u + v <= half) return 0;                       // origin inside
  // nearest point on the L1 ball boundary in the (u,v) first-quadrant frame:
  // the boundary segment is u' + v' = half with u',v' >= 0.
  // Project onto the line, clamp to the segment endpoints (half,0) and (0,half).
  const t = (u + v - half) / 2;
  let pu = u - t, pv = v - t;
  if (pu < 0) { pu = 0; pv = half; }
  if (pv < 0) { pv = 0; pu = half; }
  return Math.hypot(u - pu, v - pv);
}

const ENGINE_INK = 54 + 3 + 0.6;

// (dx, dy) of ICAE relative to ENGINE, produced by verify-engine-box.mjs
const cases = [
  ['W=1950 H=1000 shipped', 34.5, 95.2, 42],
  ['W=1950 H=750  shipped', 34.5, 81.6, 42],
  ['W=1233 H=750  shipped', -19.5, 84.7, 42],
  ['W=1400 H=900  shipped', -14.6, 84.8, 42],
  ['W=800  H=750  shipped', -25.6, 84.8, 42],
  ['W=1950 H=1000 shape:circle', 34.5, 104.4, 42],
  ['W=1950 H=750  shape:circle', 34.5, 93.2, 42],
  ['W=1233 H=750  shape:circle', -8.7, 96.3, 42],
  ['W=1400 H=900  shape:circle', -3.8, 103.7, 42],
  ['W=800  H=750  shape:circle', -22.0, 97.6, 42],
];

console.log('ENGINE drawn ink radius:', ENGINE_INK.toFixed(2));
for (const [name, dx, dy, r] of cases) {
  const halfDiag = r * 0.75 * Math.SQRT2 + 0.4;   // + half of lineWidth 0.8
  const d = distPointToDiamond(dx, dy, halfDiag);
  const pen = ENGINE_INK - d;
  console.log(
    `${name.padEnd(28)} ICAE at (${dx}, ${dy})  diamond half-diagonal ${halfDiag.toFixed(2)}` +
    `  nearest-ink distance ${d.toFixed(2)}  =>  ${pen > 0 ? 'OVERLAP ' + pen.toFixed(2) + 'px' : 'clear by ' + (-pen).toFixed(2) + 'px'}`
  );
}

console.log('\nFor reference, ICAE diamond own AABB vs own ink:');
console.log('  measured halfH = max(42*1.7, ...) / 2 = 35.70 ; drawn half-extent = 42*0.75*sqrt(2) = ' + (42 * 0.75 * Math.SQRT2).toFixed(2));
console.log('  => the diamond ALSO overshoots its own AABB by ' + (42 * 0.75 * Math.SQRT2 - 35.7).toFixed(2) + 'px on each axis.');
