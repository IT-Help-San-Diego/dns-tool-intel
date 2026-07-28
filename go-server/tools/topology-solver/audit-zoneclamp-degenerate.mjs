// Adversarial audit of the claim about topology.js:1266 (overlap-pass zone
// clamp missing the degenerate-band guard that line 1194 has).
//
// Ports the EXACT client math from go-server/static/js/topology.js:
//   computeScaling (668), computeNodeBox (677), layoutAll column setup (910-1051)
// Text widths use the solver's estimateTextWidth (an approximation of canvas
// measureText). Every conclusion drawn from a shape's radius floor
// (e.g. ENGINE w >= 54*2.4 = 129.6) is text-INDEPENDENT and therefore exact.

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
  return total * fontSize;
}

function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, measureFn) {
  let labelW = measureFn(label, fontLabel);
  let subW = 0, subLineCount = 0;
  if (sub) {
    let lines = sub.split('\n');
    subLineCount = lines.length;
    for (let i = 0; i < lines.length; i++) {
      let sw = measureFn(lines[i], fontSub);
      if (sw > subW) subW = sw;
    }
  }
  let contentW = Math.max(labelW, subW) + 24 * scale;
  let subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
  let w, h;
  if (shape === 'circle') { w = Math.max(radius * 2, contentW); h = radius * 2; }
  else if (shape === 'diamond') { w = Math.max(radius * 1.7, contentW + 8); h = radius * 1.7 + subExtra; }
  else if (shape === 'hexagon') { w = Math.max(radius * 2, contentW); h = radius * 2 + subExtra; }
  else if (shape === 'cylinder') { w = Math.max(radius * 2.4, contentW); h = radius * 1.5 + 16 + subExtra; }
  else if (shape === 'hub' || shape === 'roundRect') { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.4, 40 * scale); }
  else { w = Math.max(radius * 2.4, contentW); h = Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0)); }
  return { w, h, halfW: w / 2, halfH: h / 2, contentW, subLineCount };
}

function nodes() {
  const SOURCES = [
    { id: 'root', label: 'Root / TLD', sub: 'IANA Root Zone\nTLD Registries', zone: 'source' },
    { id: 'rdap', label: 'RDAP / WHOIS', sub: 'Registration Data\nAccess Protocol', zone: 'source' },
    { id: 'ct', label: 'CT / Subdomains', sub: 'crt.sh · Certspotter\nTransparency Logs', zone: 'source' },
    { id: 'cisa', label: 'CISA / Threat', sub: 'BOD 19-02\nIP Scanner Detection', zone: 'source' },
    { id: 'probes', label: 'Probe Fleet', sub: 'SMTP · DANE · TLS\nNmap · testssl.sh', zone: 'source' },
  ].map(s => ({ ...s, radius: 30, shape: 'rect' }));
  const HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', zone: 'hub', radius: 44, shape: 'hub' };
  const ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', zone: 'engine', radius: 54, shape: undefined };
  const CONFIDENCE = [
    { id: 'ietf', label: 'IETF Metadata', sub: 'RFC Status · Errata\nDraft Tracker' },
    { id: 'icae', label: 'ICAE', sub: 'Accuracy Audit' },
    { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit' },
    { id: 'ede', label: 'EDE', sub: 'Epistemic\nDisclosure' },
  ].map(c => ({ ...c, zone: 'confidence', radius: c.id === 'ede' ? 48 : c.id === 'ietf' ? 36 : 42, shape: c.id === 'ietf' ? 'rect' : 'diamond' }));
  const STORAGE = [
    { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results · History\nDrift · Analytics', radius: 36 },
    { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', radius: 34 },
    { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', radius: 32 },
  ].map(s => ({ ...s, zone: 'storage', shape: 'cylinder' }));
  const PROTOCOLS = ['SPF', 'DKIM', 'DMARC', 'DNSSEC', 'DANE', 'MTA-STS', 'TLS-RPT', 'BIMI', 'CAA']
    .map(l => ({ id: l.toLowerCase(), label: l, sub: null, zone: 'protocol', radius: 36, shape: 'circle' }));
  const OUTPUTS = [
    { id: 'reports', label: 'Reports', sub: 'Engineer · Executive\nRecon · Comparison' },
    { id: 'jsonapi', label: 'JSON API', sub: 'Analysis · Checksums\nSubdomains · Health' },
    { id: 'seo', label: 'Schema.org', sub: 'JSON-LD Structured Data\nGoogle · Rich Results' },
    { id: 'badges', label: 'SVG Badges', sub: 'Posture Indicators\nEmbeddable' },
  ].map(o => ({ ...o, zone: 'output', radius: 36, shape: 'hexagon' }));
  return { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS };
}

function layout(W, H, SHOW_OUTPUTS = true) {
  const SCL = Math.max(0.65, Math.min(1.15, W / 1400));
  const FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
  const FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
  const { SOURCES, HUB, ENGINE, CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS } = nodes();
  const all = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
  all.forEach(n => {
    const b = computeNodeBox(n.shape, n.radius, n.label, n.sub, SCL, FONT_LABEL, FONT_SUB, estimateTextWidth);
    n._boxW = b.w; n._boxH = b.h; n._halfW = b.halfW; n._halfH = b.halfH;
  });

  const titleSafe = Math.max(H * 0.07, 42);
  const legendSafe = H * 0.95;
  const usableH = legendSafe - titleSafe;
  const globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
  const globeCx = W * 0.04 + globeR;
  const globeCy = titleSafe + usableH * 0.42;
  const pipeStart = globeCx + globeR + W * 0.02;
  const consoleReserve = W >= 1000 ? 386 : 0;
  const pipeEnd = W * 0.99 - consoleReserve;
  const pipeTotal = pipeEnd - pipeStart;
  const colGap = Math.max(4, pipeTotal * 0.01);
  const srcNeed = Math.max(...SOURCES.map(n => n._boxW), HUB._boxW) + 26;
  const confNeed = Math.max(...CONFIDENCE.map(n => n._boxW)) + 26;
  const c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
  const c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
  const c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
  const c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
  const col1L = pipeStart, col1R = col1L + c1w;
  const col2L = col1R + colGap, col2R = col2L + c2w;
  const col3L = col2R + colGap, col3R = col3L + c3w;
  const col4L = col3R + colGap, col4R = pipeEnd;
  const storeY = 0; // unused here

  const zones = {
    source: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe },
    hub: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 },
    engine: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 },
    confidence: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 },
    storage: { x1: col2L - c2w * 0.3, x2: col2R + c2w * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe },
    protocol: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 },
    output: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe },
  };
  return { W, H, SCL, FONT_LABEL, FONT_SUB, globeR, pipeStart, pipeEnd, pipeTotal, colGap,
           srcNeed, confNeed, c1w, c2w, c3w, c4w, zones, all, titleSafe, legendSafe, usableH,
           globalBounds: { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe } };
}

function report(W, H, SHOW_OUTPUTS = true) {
  const L = layout(W, H, SHOW_OUTPUTS);
  const degX = [], degY = [], tight = [];
  L.all.forEach(n => {
    const z = L.zones[n.zone];
    if (!z) return;
    const zw = z.x2 - z.x1, zh = z.y2 - z.y1;
    const slackX = zw - 2 * n._halfW;
    const slackY = zh - 2 * n._halfH;
    if (slackX < 0) degX.push(`${n.id}(w=${n._boxW.toFixed(1)} band=${zw.toFixed(1)} over=${(-slackX).toFixed(1)})`);
    else if (slackX < 30) tight.push(`${n.id}(slackX=${slackX.toFixed(1)})`);
    if (slackY < 0) degY.push(`${n.id}(h=${n._boxH.toFixed(1)} band=${zh.toFixed(1)} over=${(-slackY).toFixed(1)})`);
  });
  console.log(`\n=== W=${W} H=${H} outputs=${SHOW_OUTPUTS} ===`);
  console.log(` SCL=${L.SCL.toFixed(4)} fonts=${L.FONT_LABEL}/${L.FONT_SUB} globeR=${L.globeR.toFixed(1)} pipe=[${L.pipeStart.toFixed(1)},${L.pipeEnd.toFixed(1)}] total=${L.pipeTotal.toFixed(1)}`);
  console.log(` srcNeed=${L.srcNeed.toFixed(1)} confNeed=${L.confNeed.toFixed(1)} | c1w=${L.c1w.toFixed(1)} c2w=${L.c2w.toFixed(1)} c3w=${L.c3w.toFixed(1)} c4w=${L.c4w.toFixed(1)} colGap=${L.colGap.toFixed(2)}`);
  console.log(` band widths: engine/conf=${(L.zones.engine.x2 - L.zones.engine.x1).toFixed(1)} storage=${(L.zones.storage.x2 - L.zones.storage.x1).toFixed(1)} proto=${(L.zones.protocol.x2 - L.zones.protocol.x1).toFixed(1)} output=${(L.zones.output.x2 - L.zones.output.x1).toFixed(1)}`);
  console.log(` X-DEGENERATE (2*halfW > bandW): ${degX.length ? degX.join(' ') : 'none'}`);
  console.log(` Y-DEGENERATE (2*halfH > bandH): ${degY.length ? degY.join(' ') : 'none'}`);
  console.log(` tight-but-feasible x: ${tight.length ? tight.join(' ') : 'none'}`);
  return L;
}

for (const [w, h] of [[1950, 900], [1950, 1100], [1600, 900], [1440, 900], [1400, 900], [1300, 800], [1233, 750], [1100, 800], [1024, 768], [1000, 800], [999, 800], [900, 700], [800, 600], [600, 900], [420, 800]]) {
  report(w, h, true);
}
console.log('\n\n########## SHOW_OUTPUTS = false ##########');
for (const [w, h] of [[1950, 900], [1233, 750], [800, 600]]) report(w, h, false);

// Sweep: find the exact W range where the engine zone is x-degenerate.
console.log('\n\n########## sweep: engine x-degeneracy vs W (H=900) ##########');
let prev = null;
for (let W = 320; W <= 2600; W += 1) {
  const L = layout(W, 900, true);
  const e = L.all.find(n => n.id === 'engine');
  const zw = L.zones.engine.x2 - L.zones.engine.x1;
  const d = 2 * e._halfW > zw;
  if (prev === null || d !== prev) { console.log(` W=${W}: degenerate=${d} (engineW=${(2 * e._halfW).toFixed(1)} band=${zw.toFixed(1)})`); prev = d; }
}
