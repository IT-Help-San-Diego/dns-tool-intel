import { estimateTextWidth } from './src/nodeMetrics.js';

const LABELS = ['alignment', 'requires', 'p=quarantine+', 'reports', 'strengthens'];

function scaling(W: number) {
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const edgeFontSize = Math.max(8, FONT_SUB - 1);
  return { SCL, FONT_SUB, edgeFontSize };
}

for (const W of [1950, 1233, 800]) {
  const { SCL, FONT_SUB, edgeFontSize } = scaling(W);
  console.log(`\n=== W=${W}  SCL=${SCL.toFixed(4)} FONT_SUB=${FONT_SUB} edgeFont=${edgeFontSize} ===`);
  const ph = edgeFontSize + 8 * SCL;
  console.log(`pill height ph = ${ph.toFixed(2)}  -> max single label-label push = ph+6 = ${(ph + 6).toFixed(2)}`);
  // circle test: node-avoidance pushes label CENTRE to distance radius+28 from centre
  const R = 36;
  const cleared = R + 28;
  for (const L of LABELS) {
    const tw = estimateTextWidth(L, edgeFontSize);
    const pw = tw + 10 * SCL;
    const half = pw / 2;
    const gap = cleared - half - R; // >=0 means pill edge clears circle edge
    console.log(
      `  ${L.padEnd(14)} tw=${tw.toFixed(1).padStart(6)} pw=${pw.toFixed(1).padStart(6)} pw/2=${half.toFixed(1).padStart(5)}` +
      `  centre@${cleared} -> pill edge at ${(cleared - half).toFixed(1).padStart(6)} vs circle r=${R}` +
      `  => ${gap >= 0 ? 'clears by ' + gap.toFixed(1) : 'OVERLAPS by ' + (-gap).toFixed(1)}`
    );
  }
}
