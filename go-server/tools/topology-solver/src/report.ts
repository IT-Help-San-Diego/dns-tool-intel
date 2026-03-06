import type { MetricsReport } from './types.js';

interface BenchmarkRun {
  solverId: string;
  fixtureId: string;
  viewportId: string;
  perturbationId: string;
  seed: number | null;
  metrics: MetricsReport;
  elapsedMs: number;
}

interface MetricDef {
  id: string;
  target: string;
  accept?: number;
}

const METRIC_KEYS: Array<keyof MetricsReport> = [
  'nodeOverlaps',
  'labelOverlaps',
  'flowCrossings',
  'totalCrossings',
  'edgeNodeIntersections',
  'flowMonotonicityViolations',
  'bendsTotal',
  'averageAngularResolution',
  'area',
  'stress',
];

export function generateCsvSummary(runs: BenchmarkRun[]): string {
  const header = [
    'solver',
    'fixture',
    'viewport',
    'perturbation',
    'seed',
    ...METRIC_KEYS,
    'elapsed_ms',
  ].join(',');

  const rows = runs.map((r) => {
    const vals = METRIC_KEYS.map((k) => r.metrics[k] ?? '');
    return [
      r.solverId,
      r.fixtureId,
      r.viewportId,
      r.perturbationId,
      r.seed ?? '',
      ...vals,
      r.elapsedMs.toFixed(1),
    ].join(',');
  });

  return [header, ...rows].join('\n') + '\n';
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function iqr(values: number[]): number {
  if (values.length < 4) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const q1Idx = Math.floor(sorted.length * 0.25);
  const q3Idx = Math.floor(sorted.length * 0.75);
  return sorted[q3Idx] - sorted[q1Idx];
}

interface AggregatedMetrics {
  solverId: string;
  viewportId: string;
  perturbationId: string;
  count: number;
  metrics: Record<string, { median: number; iqr: number; min: number; max: number }>;
}

function aggregateRuns(runs: BenchmarkRun[]): AggregatedMetrics[] {
  const groups = new Map<string, BenchmarkRun[]>();
  for (const r of runs) {
    const key = `${r.solverId}|${r.viewportId}|${r.perturbationId}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(r);
  }

  const results: AggregatedMetrics[] = [];
  for (const [, group] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const first = group[0];
    const agg: AggregatedMetrics = {
      solverId: first.solverId,
      viewportId: first.viewportId,
      perturbationId: first.perturbationId,
      count: group.length,
      metrics: {},
    };

    for (const key of METRIC_KEYS) {
      const values = group.map((r) => (r.metrics[key] as number) ?? 0);
      agg.metrics[key] = {
        median: median(values),
        iqr: iqr(values),
        min: Math.min(...values),
        max: Math.max(...values),
      };
    }

    results.push(agg);
  }

  return results;
}

export function generateMarkdownReport(runs: BenchmarkRun[], metricDefs: MetricDef[]): string {
  const lines: string[] = [];
  lines.push('# Topology Solver Benchmark Report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Total runs: ${runs.length}`);
  lines.push('');

  const aggregated = aggregateRuns(runs);
  const solverIds = [...new Set(runs.map((r) => r.solverId))].sort();

  lines.push('## Summary by Solver');
  lines.push('');
  lines.push('| Solver | Runs | Median Overlaps | Median Stress | Median Crossings | Median Flow Violations |');
  lines.push('|--------|------|----------------|---------------|-----------------|----------------------|');

  for (const solverId of solverIds) {
    const solverRuns = runs.filter((r) => r.solverId === solverId);
    const overlaps = median(solverRuns.map((r) => r.metrics.nodeOverlaps));
    const stress = median(solverRuns.map((r) => r.metrics.stress));
    const crossings = median(solverRuns.map((r) => r.metrics.totalCrossings));
    const flowViol = median(solverRuns.map((r) => r.metrics.flowMonotonicityViolations));
    lines.push(`| ${solverId} | ${solverRuns.length} | ${overlaps} | ${stress.toFixed(1)} | ${crossings} | ${flowViol} |`);
  }
  lines.push('');

  lines.push('## Per-Metric Winners');
  lines.push('');
  for (const md of metricDefs) {
    const metricKey = mapMetricId(md.id);
    if (!metricKey) continue;

    let bestSolver = '';
    let bestVal = md.target === 'max' ? -Infinity : Infinity;
    for (const solverId of solverIds) {
      const solverRuns = runs.filter((r) => r.solverId === solverId);
      const values = solverRuns.map((r) => (r.metrics[metricKey as keyof MetricsReport] as number) ?? 0);
      const med = median(values);

      if (md.target === 'max' && med > bestVal) {
        bestVal = med;
        bestSolver = solverId;
      } else if (md.target === 'min' && med < bestVal) {
        bestVal = med;
        bestSolver = solverId;
      } else if (md.target === 'mid') {
        bestVal = med;
        bestSolver = solverId;
      }
    }
    lines.push(`- **${md.id}**: winner = ${bestSolver || 'N/A'} (median = ${typeof bestVal === 'number' ? bestVal.toFixed(2) : bestVal})`);
  }
  lines.push('');

  lines.push('## Failure Cases');
  lines.push('');
  const failures = runs.filter(
    (r) => r.metrics.nodeOverlaps > 0 || r.metrics.flowMonotonicityViolations > 0,
  );
  if (failures.length === 0) {
    lines.push('No critical failures detected.');
  } else {
    lines.push(`${failures.length} runs with critical metric failures:`);
    lines.push('');
    for (const f of failures.slice(0, 20)) {
      lines.push(`- solver=${f.solverId} viewport=${f.viewportId} perturbation=${f.perturbationId}: overlaps=${f.metrics.nodeOverlaps} flow_violations=${f.metrics.flowMonotonicityViolations}`);
    }
    if (failures.length > 20) {
      lines.push(`- ... and ${failures.length - 20} more`);
    }
  }
  lines.push('');

  lines.push('## Detailed Aggregation');
  lines.push('');
  lines.push('| Solver | Viewport | Perturbation | N | Overlaps (med) | Stress (med) | Crossings (med) |');
  lines.push('|--------|----------|-------------|---|---------------|-------------|----------------|');
  for (const a of aggregated) {
    const ov = a.metrics['nodeOverlaps'];
    const st = a.metrics['stress'];
    const cr = a.metrics['totalCrossings'];
    lines.push(`| ${a.solverId} | ${a.viewportId} | ${a.perturbationId} | ${a.count} | ${ov?.median ?? '-'} | ${st?.median?.toFixed(1) ?? '-'} | ${cr?.median ?? '-'} |`);
  }
  lines.push('');

  return lines.join('\n');
}

function mapMetricId(id: string): string | null {
  const mapping: Record<string, string> = {
    node_overlap_ratio: 'nodeOverlaps',
    label_overlap_ratio: 'labelOverlaps',
    edge_crossings_total: 'totalCrossings',
    edge_crossings_flow_flow: 'flowCrossings',
    edge_node_intersections: 'edgeNodeIntersections',
    flow_x_monotonicity_violations: 'flowMonotonicityViolations',
    flow_stress: 'stress',
    bend_count_total: 'bendsTotal',
    angular_resolution_min: 'averageAngularResolution',
    layout_bbox_area_ratio: 'area',
  };
  return mapping[id] ?? null;
}
