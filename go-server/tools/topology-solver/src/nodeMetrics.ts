import type { NodeShape, NodeBox } from './types.js';

export interface NodeMetricsInput {
  shape: NodeShape | 'hub';
  radius: number;
  label: string;
  sub?: string | null;
  scale: number;
  fontLabel: number;
  fontSub: number;
}

export type MeasureTextFn = (text: string, fontSize: number) => number;

export function estimateTextWidth(text: string, fontSize: number): number {
  let total = 0;
  for (const ch of text) {
    if (ch === ' ') {
      total += 0.28;
    } else if (/[mwMW]/.test(ch)) {
      total += 0.82;
    } else if (/[iltfr!|'.,:;]/.test(ch)) {
      total += 0.32;
    } else if (/[A-Z]/.test(ch)) {
      total += 0.72;
    } else if (/[a-z]/.test(ch)) {
      total += 0.52;
    } else if (/\d/.test(ch)) {
      total += 0.56;
    } else if (ch === '·' || ch === '—' || ch === '–') {
      total += 0.56;
    } else {
      total += 0.56;
    }
  }
  return total * fontSize;
}

export const SHAPE_FORMULAS = {
  CIRCLE_W: (radius: number, contentW: number) => Math.max(radius * 2, contentW),
  CIRCLE_H: (radius: number) => radius * 2,

  DIAMOND_W: (radius: number, contentW: number) => Math.max(radius * 1.7, contentW + 8),
  DIAMOND_H: (radius: number, subExtra: number) => radius * 1.7 + subExtra,

  HEXAGON_W: (radius: number, contentW: number) => Math.max(radius * 2, contentW),
  HEXAGON_H: (radius: number, subExtra: number) => radius * 2 + subExtra,

  CYLINDER_W: (radius: number, contentW: number) => Math.max(radius * 2.4, contentW),
  CYLINDER_H: (radius: number, subExtra: number) => radius * 1.5 + 16 + subExtra,

  HUB_W: (radius: number, contentW: number) => Math.max(radius * 2.4, contentW),
  HUB_H: (radius: number, scale: number) => Math.max(radius * 1.4, 40 * scale),

  RECT_W: (radius: number, contentW: number) => Math.max(radius * 2.4, contentW),
  RECT_H: (radius: number, scale: number, subLineCount: number, fontSub: number) =>
    Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0)),
} as const;

export function computeNodeBox(
  input: NodeMetricsInput,
  measureText: MeasureTextFn,
): NodeBox & { contentW: number; subLineCount: number } {
  const { shape, radius, label, sub, scale, fontLabel, fontSub } = input;

  const labelW = measureText(label, fontLabel);
  let subW = 0;
  let subLineCount = 0;
  if (sub) {
    const lines = sub.split('\n');
    subLineCount = lines.length;
    for (const line of lines) {
      const sw = measureText(line, fontSub);
      if (sw > subW) subW = sw;
    }
  }
  const contentW = Math.max(labelW, subW) + 24 * scale;
  // Extra height for wrapped sub-text. Diamonds, hexagons, and cylinders
  // draw a multi-line sub below the label just like rects do, so their
  // heights must include it — the client's computeNodeBox in topology.js
  // is the reference; the two must agree or the precomputed layouts place
  // neighbours inside the drawn text.
  const subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;

  let width: number;
  let height: number;

  switch (shape) {
    case 'circle':
      width = SHAPE_FORMULAS.CIRCLE_W(radius, contentW);
      height = SHAPE_FORMULAS.CIRCLE_H(radius);
      break;
    case 'diamond':
      width = SHAPE_FORMULAS.DIAMOND_W(radius, contentW);
      height = SHAPE_FORMULAS.DIAMOND_H(radius, subExtra);
      break;
    case 'hexagon':
      width = SHAPE_FORMULAS.HEXAGON_W(radius, contentW);
      height = SHAPE_FORMULAS.HEXAGON_H(radius, subExtra);
      break;
    case 'cylinder':
      width = SHAPE_FORMULAS.CYLINDER_W(radius, contentW);
      height = SHAPE_FORMULAS.CYLINDER_H(radius, subExtra);
      break;
    case 'hub':
    case 'roundRect':
      width = SHAPE_FORMULAS.HUB_W(radius, contentW);
      height = SHAPE_FORMULAS.HUB_H(radius, scale);
      break;
    default:
      width = SHAPE_FORMULAS.RECT_W(radius, contentW);
      height = SHAPE_FORMULAS.RECT_H(radius, scale, subLineCount, fontSub);
      break;
  }

  return {
    id: '',
    width,
    height,
    halfW: width / 2,
    halfH: height / 2,
    contentW,
    subLineCount,
  };
}
