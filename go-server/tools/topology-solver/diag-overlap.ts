import { readFileSync } from 'node:fs';
import { solveLayout } from './src/layoutSolver.js';
import { compileConstraints } from './src/constraintCompiler.js';
import type { LayoutSpec } from './src/types.js';

const spec: LayoutSpec = JSON.parse(readFileSync('fixtures/dns-topology-production.json', 'utf-8'));

for (const profileId of ['desktop', 'tablet', 'mobile']) {
  const profile = spec.viewportProfiles[profileId];
  const compiled = compileConstraints(spec, profile);
  const result = solveLayout(spec, { profileId });
  console.log(`\n=== ${profileId}: overlaps=${result.metrics.nodeOverlaps}`);
  const ids = spec.nodes.map((n) => n.id).sort((a, b) => a.localeCompare(b));
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = ids[i], b = ids[j];
      const boxA = compiled.nodeBoxes[a];
      const boxB = compiled.nodeBoxes[b];
      const ca = result.nodeCenters[a];
      const cb = result.nodeCenters[b];
      const dx = Math.abs(ca.x - cb.x);
      const dy = Math.abs(ca.y - cb.y);
      const ox = boxA.halfW + boxB.halfW - dx;
      const oy = boxA.halfH + boxB.halfH - dy;
      if (ox > 0 && oy > 0) {
        console.log(
          `OVERLAP ${a} <-> ${b}: ox=${ox.toFixed(1)} oy=${oy.toFixed(1)}\n` +
          `  ${a}: x=${ca.x.toFixed(1)} y=${ca.y.toFixed(1)} halfW=${boxA.halfW.toFixed(1)} halfH=${boxA.halfH.toFixed(1)}\n` +
          `  ${b}: x=${cb.x.toFixed(1)} y=${cb.y.toFixed(1)} halfW=${boxB.halfW.toFixed(1)} halfH=${boxB.halfH.toFixed(1)}`
        );
      }
    }
  }
}
