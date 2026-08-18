    (function() {
        'use strict';

        let SOLVER_LAYOUTS = window.__TOPO_SOLVER;
        let SOLVER_ACTIVE = false;

        let canvas = document.getElementById('topoCanvas');
        let wrap = document.getElementById('topoWrap');
        // The console's beside cost: 360px card + 13px margins each side.
        // Shared by the flow-switch threshold and the beside-mode reserve —
        // one number, one meaning.
        let CONSOLE_BESIDE_W = 386;
        if (!canvas || !wrap) return;
        let ctx = canvas.getContext('2d');
        let dpr = window.devicePixelRatio || 1;
        let W, H;
        let SCL = 1;
        // Which axis the pipeline flows along, re-derived on every layout.
        let VERTICAL_FLOW = false;
        // Height the vertical flow needs; resize() grows the canvas to it.
        let VERTICAL_NEEDED_H = 0;
        // Single source of truth for node separation, shared by the vertical
        // shelf packer and the overlap-resolution pass.
        let overlapPadValue = 14;
        let FONT_LABEL = 13;
        let FONT_SUB = 10;
        let FONT_TAG = 13;
        let MIN_SPACING = 8;

        let COLORS = {
            email: '#4fc3f7',
            transport: '#81c784',
            policy: '#ffb74d',
            brand: '#ce93d8',
            source: '#5c6bc0',
            intel: '#78909c',
            engine: '#e0e0e0',
            storage: '#ff8a65',
            output: '#90caf9'
        };

        let GC = globalThis.GlobeCore;
        if (!GC) return;
        let DEG = GC.DEG;

        function hexToRgba(hex, a) { return GC.hexToRgba(hex, a); }
        function roundRect(x, y, w, h, r) { GC.roundRect(ctx, x, y, w, h, r); }

        let TOPO_META = {
            'CF-San Francisco': { ip: '1.1.1.1', ipAlt: '1.0.0.1', country: 'US', asn: 13335, asOrg: 'Cloudflare Inc.', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'Primary US West PoP' },
            'CF-London': { ip: '1.1.1.1', ipAlt: '1.0.0.1', country: 'GB', asn: 13335, asOrg: 'Cloudflare Inc.', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'EMEA hub' },
            'CF-Tokyo': { ip: '1.1.1.1', ipAlt: '1.0.0.1', country: 'JP', asn: 13335, asOrg: 'Cloudflare Inc.', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'APAC hub' },
            'CF-Singapore': { ip: '1.1.1.1', ipAlt: '1.0.0.1', country: 'SG', asn: 13335, asOrg: 'Cloudflare Inc.', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'SEA PoP' },
            'CF-S\u00e3o Paulo': { ip: '1.1.1.1', ipAlt: '1.0.0.1', country: 'BR', asn: 13335, asOrg: 'Cloudflare Inc.', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'LATAM hub' },
            'G-Council Bluffs': { ip: '8.8.8.8', ipAlt: '8.8.4.4', country: 'US', asn: 15169, asOrg: 'Google LLC', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'core-dc', note: 'US Central DC' },
            'G-Dublin': { ip: '8.8.8.8', ipAlt: '8.8.4.4', country: 'IE', asn: 15169, asOrg: 'Google LLC', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'core-dc', note: 'EU DC' },
            'G-Sydney': { ip: '8.8.8.8', ipAlt: '8.8.4.4', country: 'AU', asn: 15169, asOrg: 'Google LLC', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'core-dc', note: 'Oceania DC' },
            'G-Taipei': { ip: '8.8.8.8', ipAlt: '8.8.4.4', country: 'TW', asn: 15169, asOrg: 'Google LLC', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'APAC cache' },
            'Q9-Zurich': { ip: '9.9.9.9', ipAlt: '149.112.112.112', country: 'CH', asn: 19281, asOrg: 'QUAD9-AS-1', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'core-dc', note: 'Swiss HQ, threat-blocking' },
            'Q9-Frankfurt': { ip: '9.9.9.9', ipAlt: '149.112.112.112', country: 'DE', asn: 19281, asOrg: 'QUAD9-AS-1', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'DE-CIX peered' },
            'Q9-Singapore': { ip: '9.9.9.9', ipAlt: '149.112.112.112', country: 'SG', asn: 19281, asOrg: 'QUAD9-AS-1', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'SEA PoP' },
            'OD-San Jose': { ip: '208.67.222.222', ipAlt: '208.67.220.220', country: 'US', asn: 36692, asOrg: 'Cisco OpenDNS LLC', transport: 'anycast', protocol: 'DoH/UDP', pipelineRole: 'resolver', hopType: 'core-dc', note: 'Cisco Umbrella HQ' },
            'OD-London': { ip: '208.67.222.222', ipAlt: '208.67.220.220', country: 'GB', asn: 36692, asOrg: 'Cisco OpenDNS LLC', transport: 'anycast', protocol: 'DoH/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'EMEA PoP' },
            'OD-Hong Kong': { ip: '208.67.222.222', ipAlt: '208.67.220.220', country: 'HK', asn: 36692, asOrg: 'Cisco OpenDNS LLC', transport: 'anycast', protocol: 'DoH/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'APAC PoP' },
            'EU-Brussels': { ip: 'dns4eu.eu', ipAlt: 'n/a', country: 'BE', asn: 0, asOrg: 'EU Digital Sovereignty', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'EU HQ, sovereign DNS' },
            'EU-Paris': { ip: 'dns4eu.eu', ipAlt: 'n/a', country: 'FR', asn: 0, asOrg: 'EU Digital Sovereignty', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'France PoP' },
            'EU-Berlin': { ip: 'dns4eu.eu', ipAlt: 'n/a', country: 'DE', asn: 0, asOrg: 'EU Digital Sovereignty', transport: 'anycast', protocol: 'DoH/DoT/UDP', pipelineRole: 'resolver', hopType: 'edge-pop', note: 'Germany PoP' }
        };

        let RESOLVER_POPS = GC.RESOLVER_POPS.map(function(p) {
            let key = p.tag + '-' + p.city;
            let meta = TOPO_META[key] || {};
            return Object.assign({}, p, meta);
        });

        let LAND = [
            [[72,-78],[72,-100],[71,-152],[68,-165],[63,-167],[60,-140],[56,-132],[52,-127],[49,-124],[46,-124],[42,-124],[38,-123],[34,-120],[32,-117],[28,-115],[24,-110],[22,-106],[20,-97],[18,-96],[18,-88],[16,-87],[14,-84],[10,-84],[8,-81],[9,-78],[10,-76],[12,-72],[15,-76],[18,-77],[20,-76],[22,-80],[25,-80],[28,-82],[30,-82],[33,-80],[35,-76],[38,-75],[40,-74],[42,-70],[44,-66],[45,-61],[47,-53],[44,-60],[43,-66],[41,-71],[38,-70],[36,-76],[30,-82],[28,-77],[26,-80],[22,-88],[18,-88],[20,-90],[22,-97],[26,-110],[32,-117],[38,-123],[48,-124],[55,-130],[58,-136],[60,-140],[64,-162],[68,-165],[70,-152],[73,-94],[72,-78]],
            [[12,-72],[11,-74],[10,-76],[8,-77],[5,-77],[2,-80],[-1,-80],[-3,-80],[-5,-81],[-8,-79],[-12,-77],[-14,-76],[-18,-70],[-20,-70],[-23,-68],[-23,-44],[-28,-49],[-33,-52],[-35,-57],[-38,-56],[-41,-64],[-46,-67],[-52,-69],[-55,-68],[-55,-64],[-52,-72],[-47,-76],[-42,-65],[-38,-57],[-34,-53],[-28,-48],[-23,-44],[-18,-40],[-13,-39],[-8,-35],[-5,-35],[-2,-50],[2,-55],[5,-60],[8,-63],[10,-68],[12,-72]],
            [[36,-10],[38,-10],[40,-9],[42,-9],[43,-4],[44,-1],[46,0],[47,1],[48,2],[50,2],[51,4],[52,5],[54,9],[56,8],[56,10],[58,6],[60,5],[61,5],[63,10],[65,14],[68,16],[70,20],[71,28],[71,30],[70,32],[68,28],[66,26],[64,28],[62,18],[60,19],[58,18],[56,12],[54,10],[52,14],[50,14],[48,17],[46,16],[44,12],[42,24],[41,29],[40,26],[38,24],[37,23],[36,22],[36,14],[36,-6],[36,-10]],
            [[37,10],[35,0],[34,-5],[32,-8],[30,-10],[28,-14],[25,-17],[22,-17],[20,-17],[15,-17],[12,-16],[8,-14],[5,-10],[5,-4],[5,1],[5,10],[2,10],[0,10],[-5,12],[-8,14],[-12,14],[-18,12],[-22,14],[-25,17],[-28,17],[-30,18],[-34,18],[-34,20],[-33,26],[-31,28],[-28,32],[-25,35],[-20,39],[-15,41],[-12,44],[-5,40],[0,42],[5,43],[10,44],[12,45],[15,42],[20,40],[25,37],[28,35],[30,32],[32,35],[35,35],[37,10]],
            [[42,28],[44,30],[48,32],[52,36],[55,40],[57,42],[60,44],[62,50],[63,60],[65,70],[68,72],[70,80],[72,100],[72,125],[70,135],[68,140],[64,136],[62,140],[58,140],[55,135],[52,130],[48,132],[45,135],[42,132],[38,128],[35,129],[32,121],[30,120],[28,110],[25,100],[22,96],[20,93],[18,80],[15,80],[12,80],[10,78],[8,78],[6,100],[4,104],[2,104],[-1,104],[-5,106],[-7,106],[-8,110],[-7,115],[-2,118],[0,120],[1,104],[4,104],[6,100],[10,100],[15,100],[20,105],[22,107],[25,102],[28,97],[30,80],[32,60],[35,55],[37,50],[38,44],[40,40],[42,28]],
            [[-14,129],[-12,131],[-12,136],[-14,137],[-16,137],[-19,144],[-21,149],[-25,153],[-29,153],[-33,152],[-35,148],[-38,146],[-38,140],[-36,137],[-34,135],[-32,133],[-30,130],[-28,115],[-25,114],[-22,114],[-19,117],[-16,123],[-14,129]],
            [[60,-44],[63,-42],[65,-40],[68,-30],[72,-22],[76,-20],[78,-22],[80,-30],[82,-40],[83,-45],[82,-55],[80,-62],[78,-68],[76,-72],[73,-58],[70,-52],[68,-50],[64,-50],[60,-44]],
            [[31,130],[33,132],[35,134],[37,137],[40,140],[42,144],[43,145],[42,143],[40,140],[37,137],[35,134],[33,131],[31,130]]
        ];

        let globe = GC.createGlobeState();
        GC.loadTexture(globe);

        const OWN_PROBES = GC.OWN_PROBES;

        function projectPt(lat, lon) {
            return GC.projectPt(globe, lat, lon);
        }

        function drawGlobeSphere() {
            GC.drawGlobeSphere(ctx, globe);
        }

        let convergePt = { x: 0, y: 0 };
        let signalParticles = [];

        function initSignalParticles() {
            signalParticles = GC.initSignalParticles(RESOLVER_POPS);
        }

        function drawSignalArcs(time) {
            let tgtX = HUB.x - (HUB._drawW || 88) / 2;
            let tgtY = HUB.y;
            for (let i = 0; i < RESOLVER_POPS.length; i++) {
                let pop = RESOLVER_POPS[i];
                let p = projectPt(pop.lat, pop.lon);
                if (!p.vis) continue;

                let cpx = p.x + (tgtX - p.x) * 0.5 + (p.y - tgtY) * 0.12;
                let cpy = p.y + (tgtY - p.y) * 0.5;

                ctx.beginPath();
                ctx.moveTo(p.x, p.y);
                ctx.quadraticCurveTo(cpx, cpy, tgtX, tgtY);
                ctx.strokeStyle = hexToRgba(pop.color, 0.12 + p.depth * 0.06);
                ctx.lineWidth = 0.8;
                ctx.stroke();
            }

            for (let si = 0; si < signalParticles.length; si++) {
                let sp = signalParticles[si];
                let pop2 = RESOLVER_POPS[sp.popIdx];
                let p2 = projectPt(pop2.lat, pop2.lon);
                if (!p2.vis) continue;

                let t = sp.t;
                let cpx2 = p2.x + (tgtX - p2.x) * 0.5 + (p2.y - tgtY) * 0.12;
                let cpy2 = p2.y + (tgtY - p2.y) * 0.5;
                let mt = 1 - t;
                let px = mt * mt * p2.x + 2 * mt * t * cpx2 + t * t * tgtX;
                let py = mt * mt * p2.y + 2 * mt * t * cpy2 + t * t * tgtY;

                ctx.beginPath();
                ctx.arc(px, py, sp.size, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(pop2.color, 0.5 + t * 0.3);
                ctx.fill();
            }
        }

        let hoveredPop = null;
        let allLayoutNodes = [];
        let popHitAreas = [];

        let _resolverLabelCache = {};
        let _probeLabelCache = {};
        let _prevVisibleSet = '';
        let _prevProbeVisSet = '';
        let _labelFrameCount = 0;
        let LABEL_LERP = 0.12;
        // Frame cap, kept as a safety net for when the globe is not turning at
        // all (rotation paused ⇒ no angular delta ⇒ no re-solve would ever fire).
        let RELAYOUT_INTERVAL = 120;
        // Labels are solved against collisions once, then merely TRANSLATED with
        // their dots until the next re-solve. Under orthographic projection the
        // on-screen x-separation of two points scales with cos(lon): two dots 15°
        // apart span 0.259R at the centre but only 0.034R at 75°. So labels that
        // were genuinely clean when solved get squeezed into each other purely by
        // rotation, and nothing re-checks. Gating on frames meant 101 of every 120
        // frames — 84% — applied no collision test at all, which is why the
        // European cluster piles up and then stays piled. Gate on how far the
        // globe has actually turned instead. At 4.8°/s (see rotLon, ~:2240) 2.5°
        // is a re-solve roughly every half second.
        let RELAYOUT_DEG = 2.5;
        let _lastLayoutLon = null;
        let _periodicRelayout = false;

        function drawResolverMarkers(returnBoxes) {
            let visiblePops = [];
            for (let i = 0; i < RESOLVER_POPS.length; i++) {
                let pop = RESOLVER_POPS[i];
                let p = projectPt(pop.lat, pop.lon);
                if (p.vis) {
                    visiblePops.push({ pop: pop, p: p, idx: i });
                }
            }

            visiblePops.sort(function(a, b) { return a.p.depth - b.p.depth; });

            _labelFrameCount++;
            let visIds = visiblePops.map(function(v) { return v.idx; }).slice().sort(function(a,b){ return a-b; });
            let visKey = visIds.join(',');
            // Shortest signed arc since the last solve, so wrapping past 360 does
            // not read as a full revolution.
            let rotDelta = _lastLayoutLon === null
                ? 360
                : Math.abs(((globe.rotLon - _lastLayoutLon + 540) % 360) - 180);
            _periodicRelayout = rotDelta >= RELAYOUT_DEG || (_labelFrameCount % RELAYOUT_INTERVAL === 0);
            let visChanged = visKey !== _prevVisibleSet || _periodicRelayout;
            _prevVisibleSet = visKey;
            // Measure from the last actual re-solve, not the last frame — a
            // visible-set change re-solves too, and resetting here keeps the two
            // triggers from double-counting the same rotation.
            if (visChanged) _lastLayoutLon = globe.rotLon;

            let placedBoxes = [];
            globeInkCurrent = [];
            allLayoutNodes.forEach(function(nd) {
                if (!nd._boxW) measureNodeBox(nd);
                let hw = nd._halfW || nd.radius;
                let hh = nd._halfH || nd.radius;
                placedBoxes.push({ x: nd.x - hw, y: nd.y - hh, w: hw * 2, h: hh * 2 });
            });
            popHitAreas = [];
            let cityLabeled = {};
            // Dots that already carry a label this frame, so a cluster too tight
            // to label legibly can fall back to dots. visiblePops is sorted by
            // depth, so the frontmost dot in a cluster is the one that keeps its
            // label.
            let labeledDots = [];

            let labelGap = 12 * SCL;
            let labelBand = 190 * SCL;
            let maxLabelRight = globe.cx + globe.R + labelBand + labelGap;
            let maxLabelLeft = globe.cx - globe.R - labelBand - labelGap;
            let maxLabelTop = globe.cy - globe.R - labelBand;
            let maxLabelBottom = globe.cy + globe.R + labelBand;

            for (let vi = 0; vi < visiblePops.length; vi++) {
                let vp = visiblePops[vi];
                let pop2 = vp.pop;
                let p2 = vp.p;
                let alpha = 0.4 + p2.depth * 0.6;
                let isHovered = hoveredPop === vp.idx;

                ctx.beginPath();
                ctx.arc(p2.x, p2.y, isHovered ? 9 : 7, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(pop2.color, (isHovered ? 0.3 : 0.15) * alpha);
                ctx.fill();

                ctx.beginPath();
                ctx.arc(p2.x, p2.y, isHovered ? 5 : 4, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(pop2.color, (isHovered ? 1 : 0.85) * alpha);
                ctx.fill();

                // Two resolvers sharing a PoP city (CF+OD London, CF+Q9
                // Singapore) used to fight for the same spot with duplicate
                // tags \u2014 one label per city is enough; the dot still renders
                // and hover still identifies the specific resolver.
                if (!isHovered && cityLabeled[pop2.city]) {
                    popHitAreas.push({ x: p2.x - 8, y: p2.y - 8, w: 16, h: 16, dotX: p2.x, dotY: p2.y, idx: vp.idx });
                    continue;
                }

                let label = isHovered ? (pop2.tag + ' \u00b7 ' + pop2.city) : pop2.city;
                ctx.font = (isHovered ? 'bold ' : '') + FONT_TAG + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                let tw = ctx.measureText(label).width;
                let tagW = tw + 18 * SCL;
                let tagH = Math.round(20 * SCL + 2);

                // Orthographic projection compresses x-separation by cos(lon):
                // two dots 15 degrees apart span 0.259R at the centre but only
                // 0.034R at 75 degrees. Near the limb a whole cluster \u2014 Dublin,
                // London, Paris, Brussels \u2014 lands inside a few pixels, and no
                // placement can separate four ~100px tags from anchors that
                // close. Solving more often just recomputes an impossible
                // problem; the escape is to stop asking for four labels.
                //
                // Same rule as the shared-city case above: label the frontmost
                // and leave the rest as dots. The dot still renders and its hit
                // area still resolves on hover, so nothing becomes unreachable \u2014
                // which is the line between suppressing a LABEL and suppressing
                // a RESOLVER. Never do the latter.
                let tooClose = false;
                if (!isHovered) {
                    for (let li = 0; li < labeledDots.length; li++) {
                        let ld = labeledDots[li];
                        let dx = p2.x - ld.x;
                        let dy = p2.y - ld.y;
                        if (dx * dx + dy * dy < ld.minSep * ld.minSep) { tooClose = true; break; }
                    }
                }
                // Portrait phone: the canvas is ~400px and carries the whole
                // pipeline stacked vertically. There is no free corridor left for
                // globe text, so every candidate collides and the fallback parks
                // the tag on top of a node box — San Francisco over Root/TLD,
                // Berlin over RDAP/WHOIS. Raising the type floors made the boxes
                // bigger and the collision worse, which is the honest trade.
                //
                // Same rule as the limb cluster and the shared-city case: the DOT
                // still renders and its hit area still resolves, so no resolver
                // becomes unreachable. Only the label is withheld, and only where
                // it could not have been legible anyway.
                if (VERTICAL_FLOW || tooClose) {
                    popHitAreas.push({ x: p2.x - 8, y: p2.y - 8, w: 16, h: 16, dotX: p2.x, dotY: p2.y, idx: vp.idx });
                    continue;
                }
                cityLabeled[pop2.city] = true;
                // Tags stack vertically when they cannot sit side by side, so the
                // pitch that matters is tag height, not width. 1.5x leaves normal
                // spacing (San Jose / San Francisco sit ~46px apart and both keep
                // their labels) while catching genuine limb pile-ups.
                labeledDots.push({ x: p2.x, y: p2.y, minSep: tagH * 1.5 });

                let cacheKey = 'r' + vp.idx;
                let cached = _resolverLabelCache[cacheKey];
                let idealX, idealY;

                if (!cached || visChanged) {
                    let baseAngle = Math.atan2(p2.y - globe.cy, p2.x - globe.cx);
                    let bestX2 = null, bestY2 = null, bestScore = Infinity;
                    let candidateAngles = [0, 15, -15, 30, -30, 45, -45, 60, -60, 75, -75, 90, -90, 105, -105, 120, -120, 135, -135, 150, -150, 165, -165, 180];
                    let candidateDists = [globe.R * 0.15 + labelGap, globe.R * 0.25 + labelGap, globe.R * 0.35 + labelGap,
                                          globe.R * 0.5 + labelGap, globe.R * 0.68 + labelGap, globe.R * 0.88 + labelGap];
                    for (let di = 0; di < candidateDists.length; di++) {
                    for (let ci = 0; ci < candidateAngles.length; ci++) {
                        let ca = baseAngle + candidateAngles[ci] * DEG;
                        let dist = candidateDists[di];
                        let cx2 = p2.x + Math.cos(ca) * dist;
                        let cy2 = p2.y + Math.sin(ca) * dist;
                        if (Math.cos(ca) < 0) cx2 -= tagW;
                        // REJECT candidates that do not fit; never CLAMP them.
                        // Clamping was the pile-up. maxLabelLeft evaluates to
                        // about -150 at every viewport (there is only 41-77px
                        // of canvas west of the globe against a ~104px tag), so
                        // Math.max(4, maxLabelLeft) collapsed every westward
                        // candidate onto x=4 — where they all "fit", stacked on
                        // each other. Rejecting instead pushes the search into
                        // the corridors that genuinely are free: above and
                        // below the globe.
                        if (cx2 < 4 || cx2 + tagW > maxLabelRight) continue;
                        if (cy2 < 4 || cy2 + tagH > maxLabelBottom) continue;
                        let hasCollision = false;
                        for (let pi = 0; pi < placedBoxes.length; pi++) {
                            let pb = placedBoxes[pi];
                            if (cx2 < pb.x + pb.w + 3 && cx2 + tagW > pb.x - 3 &&
                                cy2 < pb.y + pb.h + 3 && cy2 + tagH > pb.y - 3) {
                                hasCollision = true;
                                break;
                            }
                        }
                        let distFromDot = Math.sqrt((cx2 + tagW / 2 - p2.x) * (cx2 + tagW / 2 - p2.x) + (cy2 + tagH / 2 - p2.y) * (cy2 + tagH / 2 - p2.y));
                        let score = (hasCollision ? 10000 : 0) + distFromDot;
                        if (score < bestScore) { bestScore = score; bestX2 = cx2; bestY2 = cy2; }
                    }
                    }
                    // No candidate fitted at all — park it in the corridor
                    // below the globe rather than leaving it at the last
                    // clamped position.
                    if (bestX2 === null) {
                        bestX2 = Math.min(Math.max(4, p2.x - tagW / 2), maxLabelRight - tagW);
                        bestY2 = Math.min(globe.cy + globe.R + 16 * SCL, maxLabelBottom - tagH);
                        bestScore = 10000;
                    }
                    if (bestScore >= 10000) {
                        for (let ri = 0; ri < 8; ri++) {
                            let shifted = false;
                            for (let pi2 = 0; pi2 < placedBoxes.length; pi2++) {
                                let pb2 = placedBoxes[pi2];
                                let ovX = Math.min(bestX2 + tagW, pb2.x + pb2.w) - Math.max(bestX2, pb2.x);
                                let ovY = Math.min(bestY2 + tagH, pb2.y + pb2.h) - Math.max(bestY2, pb2.y);
                                if (ovX > 0 && ovY > 0) {
                                    if (ovY < ovX) { bestY2 += (bestY2 < pb2.y ? -(ovY + 4) : (ovY + 4)); }
                                    else { bestX2 += (bestX2 < pb2.x ? -(ovX + 4) : (ovX + 4)); }
                                    shifted = true;
                                }
                            }
                            if (!shifted) break;
                        }
                        bestX2 = Math.max(4, Math.min(bestX2, maxLabelRight - tagW));
                        bestY2 = Math.max(4, Math.min(bestY2, maxLabelBottom - tagH));
                    }
                    idealX = bestX2;
                    idealY = bestY2;
                    _resolverLabelCache[cacheKey] = { idealX: idealX, idealY: idealY, curX: cached ? cached.curX : idealX, curY: cached ? cached.curY : idealY };
                    cached = _resolverLabelCache[cacheKey];
                } else {
                    let offsetX = p2.x - cached._lastDotX;
                    let offsetY = p2.y - cached._lastDotY;
                    cached.idealX += offsetX;
                    cached.idealY += offsetY;
                    cached.curX += offsetX;
                    cached.curY += offsetY;
                }
                cached._lastDotX = p2.x;
                cached._lastDotY = p2.y;
                cached.curX += (cached.idealX - cached.curX) * LABEL_LERP;
                cached.curY += (cached.idealY - cached.curY) * LABEL_LERP;

                let rawTagX = cached.curX;
                let rawTagY = cached.curY;
                // Placement obstacles use the IDEAL position — the box this
                // label is travelling to — so later labels avoid its
                // destination, not a transient mid-lerp spot they would
                // collide with on arrival. Ink registers the DRAWN position:
                // what is actually on screen this frame. Two consumers, two
                // truths; conflating them was why registered boxes trailed
                // drawn ones during motion.
                placedBoxes.push({ x: cached.idealX, y: cached.idealY, w: tagW, h: tagH });
                globeInkCurrent.push({ kind: 'cityLabel', id: cacheKey, x: rawTagX, y: rawTagY, w: tagW, h: tagH });
                popHitAreas.push({ x: rawTagX, y: rawTagY, w: tagW, h: tagH, dotX: p2.x, dotY: p2.y, idx: vp.idx });

                // The leader is the whole point of a floating tag: it must
                // visibly pin to a physical place. Attach to the point on the
                // tag rectangle CLOSEST to the dot, so the line always lands on
                // the tag edge instead of a fixed left/right midpoint that can
                // leave a visible gap. Alpha carries a floor as well, because
                // scaling it by limb depth faded near-horizon leaders to
                // roughly 0.12 — technically drawn, effectively invisible.
                let anchorX = Math.max(rawTagX, Math.min(p2.x, rawTagX + tagW));
                let anchorY = Math.max(rawTagY, Math.min(p2.y, rawTagY + tagH));
                ctx.beginPath();
                ctx.moveTo(p2.x, p2.y);
                ctx.lineTo(anchorX, anchorY);
                ctx.strokeStyle = hexToRgba(pop2.color, isHovered ? 0.85 : Math.max(0.4, 0.6 * alpha));
                ctx.lineWidth = (isHovered ? 1.4 : 1) * Math.max(1, SCL);
                ctx.stroke();

                // A hard pin-head at the ground end: unambiguous that the tag
                // refers to THIS coordinate, not merely near it.
                ctx.beginPath();
                ctx.arc(p2.x, p2.y, (isHovered ? 2.6 : 2) * Math.max(1, SCL), 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(pop2.color, isHovered ? 1 : Math.max(0.6, alpha));
                ctx.fill();

                roundRect(rawTagX, rawTagY, tagW, tagH, 4);
                ctx.fillStyle = 'rgba(0,0,0,' + (isHovered ? 0.6 : 0.5 * alpha) + ')';
                ctx.fill();
                roundRect(rawTagX, rawTagY, tagW, tagH, 4);
                ctx.fillStyle = hexToRgba(pop2.color, isHovered ? 0.4 : 0.55 * alpha);
                ctx.fill();
                ctx.strokeStyle = hexToRgba(pop2.color, isHovered ? 0.9 : 0.7 * alpha);
                ctx.lineWidth = isHovered ? 1.2 : 0.8;
                ctx.stroke();

                ctx.fillStyle = 'rgba(255,255,255,' + (isHovered ? 0.98 : 0.95 * alpha) + ')';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.fillText(label, rawTagX + 9 * SCL, rawTagY + tagH / 2);
            }
            return placedBoxes;
        }

        function drawPopTooltip() {
            if (hoveredPop === null) return;
            let pop = RESOLVER_POPS[hoveredPop];
            if (!pop) return;
            let p = projectPt(pop.lat, pop.lon);
            if (!p.vis) { hoveredPop = null; return; }

            let lines = [
                pop.resolver + ' \u2014 ' + pop.city + ', ' + pop.country,
                'IP: ' + pop.ip + (pop.ipAlt !== 'n/a' ? ' / ' + pop.ipAlt : ''),
                'AS' + (pop.asn > 0 ? pop.asn : 'N/A') + ' (' + pop.asOrg + ')',
                'Protocol: ' + pop.protocol + ' (' + pop.transport + ')',
                'Type: ' + pop.hopType.replace('-', ' '),
                pop.note
            ];

            ctx.font = '12px -apple-system, BlinkMacSystemFont, sans-serif';
            let maxW = 0;
            for (let i = 0; i < lines.length; i++) {
                let lw = ctx.measureText(lines[i]).width;
                if (lw > maxW) maxW = lw;
            }

            let tipW = maxW + 24;
            let lineH = 18;
            let tipH = lines.length * lineH + 16;
            let tipX = p.x + 18;
            let tipY = p.y - tipH / 2;

            if (tipX + tipW > globe.cx + globe.R + 60) {
                tipX = p.x - tipW - 18;
            }
            if (tipY < 10) tipY = 10;
            if (tipY + tipH > H - 10) tipY = H - tipH - 10;

            ctx.save();
            ctx.shadowColor = 'rgba(0,0,0,0.6)';
            ctx.shadowBlur = 12;
            ctx.shadowOffsetX = 2;
            ctx.shadowOffsetY = 2;
            roundRect(tipX, tipY, tipW, tipH, 6);
            ctx.fillStyle = 'rgba(12, 16, 28, 0.95)';
            ctx.fill();
            ctx.restore();

            roundRect(tipX, tipY, tipW, tipH, 6);
            ctx.strokeStyle = hexToRgba(pop.color, 0.5);
            ctx.lineWidth = 1;
            ctx.stroke();

            let headerH = lineH + 4;
            roundRect(tipX, tipY, tipW, headerH, 6);
            ctx.fillStyle = hexToRgba(pop.color, 0.15);
            ctx.fill();

            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            ctx.font = 'bold 12px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = hexToRgba(pop.color, 0.95);
            ctx.fillText(lines[0], tipX + 12, tipY + headerH / 2);

            ctx.font = '11px -apple-system, BlinkMacSystemFont, monospace';
            for (let j = 1; j < lines.length; j++) {
                ctx.fillStyle = j === lines.length - 1 ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,0.7)';
                if (j === lines.length - 1) ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.fillText(lines[j], tipX + 12, tipY + headerH + (j - 1) * lineH + lineH / 2 + 4);
            }
        }

        function drawProbeMarkers(placedBoxes) {
            let labelGap = 12 * SCL;
            let labelBand = 190 * SCL;
            let pCandidateAngles = [0, 20, -20, 40, -40, 60, -60, 80, -80, 100, -100, 120, -120, 140, -140, 160, -160, 180];
            let pCandidateDists = [globe.R * 0.18 + labelGap, globe.R * 0.28 + labelGap, globe.R * 0.38 + labelGap];

            let probeVisIds = [];
            for (let pvi = 0; pvi < OWN_PROBES.length; pvi++) {
                let pvp = projectPt(OWN_PROBES[pvi].lat, OWN_PROBES[pvi].lon);
                if (pvp.vis) probeVisIds.push(pvi);
            }
            let probeVisKey = probeVisIds.join(',');
            let probeVisChanged = probeVisKey !== _prevProbeVisSet;
            _prevProbeVisSet = probeVisKey;
            // Same trigger as the city tags. drawResolverMarkers runs first in
            // drawGlobe and computes it, so probe tags and city tags re-solve on
            // the same frames and against the same placedBoxes.
            let visChanged = probeVisChanged || _periodicRelayout;

            for (let pi = 0; pi < OWN_PROBES.length; pi++) {
                let probe = OWN_PROBES[pi];
                // See the note in drawResolverMarkers: on a portrait phone the
                // probe tags are the widest text on the globe and have nowhere to
                // sit. Dot and hover stay; the tag does not.
                let suppressProbeLabel = VERTICAL_FLOW;
                let pp = projectPt(probe.lat, probe.lon);
                if (!pp.vis) continue;
                let pAlpha = 0.4 + pp.depth * 0.6;
                let now = performance.now();
                let pulse = 0.5 + 0.5 * Math.sin(now / 600);

                ctx.beginPath();
                ctx.arc(pp.x, pp.y, 12, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(probe.color, 0.08 * pAlpha * pulse);
                ctx.fill();

                ctx.beginPath();
                ctx.arc(pp.x, pp.y, 8, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(probe.color, 0.15 * pAlpha);
                ctx.fill();
                ctx.strokeStyle = hexToRgba(probe.color, 0.5 * pAlpha);
                ctx.lineWidth = 1.2;
                ctx.stroke();

                ctx.save();
                ctx.translate(pp.x, pp.y);
                ctx.rotate(Math.PI / 4);
                ctx.fillStyle = hexToRgba(probe.color, 0.95 * pAlpha);
                ctx.fillRect(-3.5, -3.5, 7, 7);
                ctx.restore();

                // The marker above is drawn; only the text tag is withheld. Skip
                // before any measuring or placement so a suppressed label costs
                // nothing and, crucially, never enters placedBoxes — a tag that is
                // not drawn must not push the ones that are.
                if (suppressProbeLabel) continue;

                let pLabel = probe.label;
                ctx.font = FONT_TAG + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                let ptw = ctx.measureText(pLabel).width;
                let pTagW = ptw + 18 * SCL;
                let pTagH = Math.round(20 * SCL + 2);

                let pCacheKey = 'p' + pi;
                let pCached = _probeLabelCache[pCacheKey];

                let pIdealPos;
                if (!pCached || visChanged) {
                    pIdealPos = GC.placeLabel({ dotX: pp.x, dotY: pp.y, tagW: pTagW, tagH: pTagH, globeCx: globe.cx, globeCy: globe.cy, globeR: globe.R, placedBoxes: placedBoxes, labelGap: labelGap, labelBand: labelBand, candidateAngles: pCandidateAngles, candidateDists: pCandidateDists });
                    _probeLabelCache[pCacheKey] = { idealX: pIdealPos.x, idealY: pIdealPos.y, curX: pCached ? pCached.curX : pIdealPos.x, curY: pCached ? pCached.curY : pIdealPos.y, _lastDotX: pp.x, _lastDotY: pp.y };
                    pCached = _probeLabelCache[pCacheKey];
                } else {
                    let pOffX = pp.x - pCached._lastDotX;
                    let pOffY = pp.y - pCached._lastDotY;
                    pCached.idealX += pOffX;
                    pCached.idealY += pOffY;
                    pCached.curX += pOffX;
                    pCached.curY += pOffY;
                }
                pCached._lastDotX = pp.x;
                pCached._lastDotY = pp.y;
                pCached.curX += (pCached.idealX - pCached.curX) * LABEL_LERP;
                pCached.curY += (pCached.idealY - pCached.curY) * LABEL_LERP;

                let pPos = { x: pCached.curX, y: pCached.curY };
                // Same split as the city tags: obstacles at the destination,
                // ink at the drawn position.
                placedBoxes.push({ x: pCached.idealX, y: pCached.idealY, w: pTagW, h: pTagH });
                globeInkCurrent.push({ kind: 'probeTag', id: pCacheKey, x: pPos.x, y: pPos.y, w: pTagW, h: pTagH });

                // Same pinning rule as the resolver leaders: land on the
                // nearest point of the tag, keep a visible alpha floor, and
                // put a pin-head on the coordinate itself.
                let pAnchorX = Math.max(pPos.x, Math.min(pp.x, pPos.x + pTagW));
                let pAnchorY = Math.max(pPos.y, Math.min(pp.y, pPos.y + pTagH));
                ctx.beginPath();
                ctx.moveTo(pp.x, pp.y);
                ctx.lineTo(pAnchorX, pAnchorY);
                ctx.strokeStyle = hexToRgba(probe.color, Math.max(0.4, 0.6 * pAlpha));
                ctx.lineWidth = Math.max(1, SCL);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(pp.x, pp.y, 2 * Math.max(1, SCL), 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(probe.color, Math.max(0.6, pAlpha));
                ctx.fill();

                roundRect(pPos.x, pPos.y, pTagW, pTagH, 4);
                ctx.fillStyle = hexToRgba(probe.color, 0.18 * pAlpha);
                ctx.fill();
                ctx.strokeStyle = hexToRgba(probe.color, 0.6 * pAlpha);
                ctx.lineWidth = 0.8;
                ctx.stroke();

                ctx.fillStyle = 'rgba(255,255,255,' + (0.9 * pAlpha) + ')';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.fillText(pLabel, pPos.x + 9 * SCL, pPos.y + pTagH / 2);
            }
        }

        function drawGlobe(time) {
            drawGlobeSphere();
            drawSignalArcs(time);
            let boxes = drawResolverMarkers();
            drawProbeMarkers(boxes);

            ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = 'rgba(255,255,255,0.2)';
            ctx.fillText('Orthographic Projection', globe.cx, globe.cy + globe.R + 8 * SCL);
            let snapLon = Math.round(globe.rotLon * 2) / 2;
            let degLabel = ((-snapLon % 360) + 360) % 360;
            if (degLabel > 180) degLabel -= 360;
            ctx.fillText(degLabel.toFixed(0) + '\u00b0 longitude center', globe.cx, globe.cy + globe.R + 20 * SCL);
            if (GlobeCore.subsolarPoint) {
                // The instrument declares its own state: the terminator shown
                // is computed for this moment, not asserted.
                let now = new Date();
                let sp = GlobeCore.subsolarPoint(now);
                let latTxt = Math.abs(sp.latDeg).toFixed(1) + '\u00b0' + (sp.latDeg >= 0 ? 'N' : 'S');
                let lonTxt = Math.abs(sp.lonDeg).toFixed(1) + '\u00b0' + (sp.lonDeg >= 0 ? 'E' : 'W');
                let hh = String(now.getUTCHours()).padStart(2, '0');
                let mm = String(now.getUTCMinutes()).padStart(2, '0');
                ctx.fillText('Subsolar ' + latTxt + ' ' + lonTxt + ' \u00b7 terminator for ' + hh + ':' + mm + ' UTC', globe.cx, globe.cy + globe.R + 32 * SCL);
            }
        }

        let SOURCES = [
            { id: 'root',  label: 'Root / TLD',      sub: 'IANA Root Zone\nTLD Registries',       color: COLORS.source, zone: 'source' },
            { id: 'rdap',  label: 'RDAP / WHOIS',    sub: 'Registration Data\nAccess Protocol',   color: COLORS.intel,  zone: 'source' },
            { id: 'ct',    label: 'CT / Subdomains',  sub: 'crt.sh \u00b7 Certspotter\nTransparency Logs', color: COLORS.intel,  zone: 'source' },
            { id: 'cisa',  label: 'CISA / Threat',    sub: 'BOD 19-02\nIP Scanner Detection',     color: COLORS.intel,  zone: 'source' },
            { id: 'probes', label: 'Probe Fleet',     sub: 'SMTP \u00b7 DANE \u00b7 TLS\nNmap \u00b7 testssl.sh', color: COLORS.source, zone: 'source' }
        ];

        let HUB = { id: 'hub', label: 'DNS Resolvers', sub: 'Signal Aggregation', color: COLORS.source, zone: 'hub', x: 0, y: 0, targetX: 0, targetY: 0, radius: 44, _initialized: false, shape: 'hub' };

        // shape MUST be declared: measureNodeBox falls through to the rect
        // formula without it, measuring ICIE as a ~70px-tall box while
        // drawEngineNode draws a 108px circle. Every spacing pass then works
        // from a box 38px shorter than the ink.
        let ENGINE = { id: 'engine', label: 'ICIE', sub: 'Analysis Engine', color: COLORS.engine, zone: 'engine', shape: 'circle', x: 0, y: 0, targetX: 0, targetY: 0, radius: 54, _initialized: false };

        let CONFIDENCE = [
            { id: 'ietf',  label: 'IETF Metadata',   sub: 'RFC Status \u00b7 Errata\nDraft Tracker',  color: COLORS.intel,  zone: 'confidence' },
            { id: 'icae',  label: 'ICAE',  sub: 'Accuracy Audit',   color: '#ef9a9a', zone: 'confidence' },
            { id: 'icuae', label: 'ICuAE', sub: 'Currency Audit',   color: '#a5d6a7', zone: 'confidence' },
            { id: 'ede',   label: 'EDE',   sub: 'Epistemic\nDisclosure', color: '#ffab91', zone: 'confidence' }
        ];

        let STORAGE = [
            { id: 'postgres', label: 'PostgreSQL', sub: 'Scan Results \u00b7 History\nDrift \u00b7 Analytics', color: COLORS.storage, zone: 'storage' },
            { id: 'fixtures', label: 'Golden Fixtures', sub: 'Known-Good Baselines\nRFC Compliance Seeds', color: '#ffcc80', zone: 'storage' },
            { id: 'wayback', label: 'Internet Archive', sub: 'Wayback Machine\nPermanent Record', color: '#81c784', zone: 'storage' }
        ];

        let PROTOCOLS = [
            { id: 'spf',    label: 'SPF',     rfc: '7208',  cat: 'email' },
            { id: 'dkim',   label: 'DKIM',    rfc: '6376',  cat: 'email' },
            { id: 'dmarc',  label: 'DMARC',   rfc: '7489',  cat: 'email' },
            { id: 'dnssec', label: 'DNSSEC',  rfc: '4035',  cat: 'policy' },
            { id: 'dane',   label: 'DANE',    rfc: '6698',  cat: 'transport' },
            { id: 'mtasts', label: 'MTA-STS', rfc: '8461',  cat: 'transport' },
            { id: 'tlsrpt', label: 'TLS-RPT', rfc: '8460',  cat: 'transport' },
            { id: 'bimi',   label: 'BIMI',    rfc: 'draft', cat: 'brand' },
            { id: 'caa',    label: 'CAA',     rfc: '8659',  cat: 'policy' }
        ];

        let OUTPUTS = [
            { id: 'reports', label: 'Reports',    sub: 'Engineer \u00b7 Executive\nRecon \u00b7 Comparison', color: COLORS.output, zone: 'output' },
            { id: 'jsonapi', label: 'JSON API',   sub: 'Analysis \u00b7 Checksums\nSubdomains \u00b7 Health', color: COLORS.output, zone: 'output' },
            { id: 'seo',    label: 'Schema.org',  sub: 'JSON-LD Structured Data\nGoogle \u00b7 Rich Results', color: COLORS.output, zone: 'output' },
            { id: 'badges', label: 'SVG Badges',  sub: 'Posture Indicators\nEmbeddable', color: COLORS.output, zone: 'output' }
        ];

        let PROTO_EDGES = [
            { from: 'dmarc', to: 'spf',    type: 'hard',  label: 'alignment',     labelT: 0.45 },
            { from: 'dmarc', to: 'dkim',   type: 'hard',  label: 'alignment',     labelT: 0.45 },
            { from: 'dane',  to: 'dnssec', type: 'hard',  label: 'requires',      labelT: 0.35 },
            { from: 'bimi',  to: 'dmarc',  type: 'hard',  label: 'p=quarantine+', labelT: 0.5 },
            { from: 'tlsrpt', to: 'mtasts', type: 'soft', label: 'reports',       labelT: 0.5 },
            { from: 'tlsrpt', to: 'dane',  type: 'soft',  label: 'reports',       labelT: 0.4 },
            { from: 'caa',   to: 'dnssec', type: 'soft',  label: 'strengthens',   labelT: 0.5 }
        ];

        let allNodes = {};

        SOURCES.forEach(function(s) {
            s.x = 0; s.y = 0; s.targetX = 0; s.targetY = 0;
            s.radius = 30; s._initialized = false; s.shape = 'rect';
            allNodes[s.id] = s;
        });
        allNodes[HUB.id] = HUB;
        allNodes[ENGINE.id] = ENGINE;

        CONFIDENCE.forEach(function(c) {
            c.x = 0; c.y = 0; c.targetX = 0; c.targetY = 0;
            c.radius = (c.id === 'ede') ? 48 : (c.id === 'ietf') ? 36 : 42;
            c._initialized = false; c.shape = (c.id === 'ietf') ? 'rect' : 'diamond';
            allNodes[c.id] = c;
        });

        STORAGE.forEach(function(s) {
            s.x = 0; s.y = 0; s.targetX = 0; s.targetY = 0;
            s.radius = (s.id === 'postgres') ? 36 : (s.id === 'wayback') ? 32 : 34;
            s._initialized = false; s.shape = 'cylinder';
            allNodes[s.id] = s;
        });

        PROTOCOLS.forEach(function(p) {
            p.x = 0; p.y = 0; p.targetX = 0; p.targetY = 0;
            p.radius = 36; p.color = COLORS[p.cat]; p.shape = 'circle';
            p._initialized = false; p.zone = 'protocol';
            allNodes[p.id] = p;
        });

        OUTPUTS.forEach(function(o) {
            o.x = 0; o.y = 0; o.targetX = 0; o.targetY = 0;
            o.radius = 36; o._initialized = false; o.shape = 'hexagon';
            allNodes[o.id] = o;
        });

        let FLOW_EDGES = [];
        FLOW_EDGES.push({ from: 'hub', to: 'engine', type: 'flow', label: '' });
        SOURCES.forEach(function(s) {
            FLOW_EDGES.push({ from: s.id, to: 'hub', type: 'flow', label: '' });
        });
        FLOW_EDGES.push({ from: 'ietf', to: 'engine', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'ietf', to: 'icae', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'ietf', to: 'icuae', type: 'flow', label: 'informs' });
        FLOW_EDGES.push({ from: 'engine', to: 'icae', type: 'flow', label: '' });
        FLOW_EDGES.push({ from: 'engine', to: 'icuae', type: 'flow', label: '' });
        FLOW_EDGES.push({ from: 'icae', to: 'ede', type: 'flow', label: 'discloses' });
        FLOW_EDGES.push({ from: 'icuae', to: 'ede', type: 'flow', label: 'discloses' });
        FLOW_EDGES.push({ from: 'engine', to: 'postgres', type: 'flow', label: 'persist' });
        FLOW_EDGES.push({ from: 'postgres', to: 'fixtures', type: 'flow', label: 'seeds' });
        FLOW_EDGES.push({ from: 'postgres', to: 'wayback', type: 'flow', label: 'archives' });
        PROTOCOLS.forEach(function(p) {
            FLOW_EDGES.push({ from: 'engine', to: p.id, type: 'flow', label: '' });
        });
        OUTPUTS.forEach(function(o) {
            FLOW_EDGES.push({ from: 'engine', to: o.id, type: 'flow', label: '' });
        });
        FLOW_EDGES.push({ from: 'postgres', to: 'reports', type: 'flow', label: 'history' });

        function effRadius(n) {
            let hw = (n._drawW || n.radius * 2.2) / 2;
            let hh = (n._drawH || n.radius * 1.4) / 2;
            return Math.max(hw, hh, n.radius) + 6;
        }

        function computeScaling() {
            SCL = Math.max(0.65, Math.min(1.15, W / 1400));
            // SCL scales GEOMETRY to the canvas, which is right: boxes have to
            // fit. Type is a different question — a smaller screen is not a
            // further-away viewer, so text should stop shrinking well before the
            // layout does. These floors already existed; they were simply set
            // below the readable line. At the iPad's SCL of 0.737 the old values
            // produced 10px labels and 8px sub-labels while a desktop at SCL 1.15
            // showed 15px and 12px — the same text at 64% the size, which is why
            // the tablet had to be zoomed by hand. Apple's floor is 11pt.
            // Node boxes are measured from their text (measureNodeBox), so the
            // boxes grow with the type and the solver keeps laying out against
            // real dimensions rather than assumed ones.
            FONT_LABEL = Math.round(Math.max(12, Math.min(15, 13 * SCL)));
            FONT_SUB = Math.round(Math.max(10, Math.min(12, 10 * SCL)));
            FONT_TAG = Math.round(Math.max(12, Math.min(15, 13 * SCL)));
            MIN_SPACING = Math.round(Math.max(5, 8 * SCL));
            clearTextWidthCache();
        }

        function computeNodeBox(shape, radius, label, sub, scale, fontLabel, fontSub, measureFn) {
            let labelW = measureFn(label, fontLabel);
            let subW = 0;
            let subLineCount = 0;
            if (sub) {
                let lines = sub.split('\n');
                subLineCount = lines.length;
                for (let i = 0; i < lines.length; i++) {
                    let sw = measureFn(lines[i], fontSub);
                    if (sw > subW) subW = sw;
                }
            }
            let contentW = Math.max(labelW, subW) + 24 * scale;
            // Extra height for wrapped sub-text. Only the default branch used
            // to account for this, so cylinders and diamonds — which DO draw a
            // multi-line sub below the label — measured shorter than they
            // render. Their AABBs then cleared each other while the drawn text
            // collided, which is why the storage stack looked overlapped while
            // the overlap pass reported nothing to fix.
            let subExtra = subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0;
            let w, h;
            if (shape === 'circle') {
                w = Math.max(radius * 2, contentW);
                h = radius * 2;
            } else if (shape === 'diamond') {
                w = Math.max(radius * 1.7, contentW + 8);
                h = radius * 1.7 + subExtra;
            } else if (shape === 'hexagon') {
                w = Math.max(radius * 2, contentW);
                h = radius * 2 + subExtra;
            } else if (shape === 'cylinder') {
                w = Math.max(radius * 2.4, contentW);
                // A cylinder is the one shape whose sub-text is drawn OUTSIDE
                // its body: drawStorageNode anchors it at drumBottom +
                // 12*scale, so that ink is below the drum by construction.
                // Measuring only the drum under-reported the node by ~34px at
                // SCL 1.15 and let the next cylinder's box sit inside this
                // one's text — measured live: 22.4px vertical intrusion while
                // the overlap pass correctly reported nothing to fix.
                // The box therefore spans cap + drum + cap + sub-below, and
                // drawStorageNode positions the drum from the box top so the
                // two agree by construction. cylinderParts() is the single
                // source of truth for both.
                let parts = cylinderParts(radius, scale, fontSub, subLineCount);
                h = parts.total;
            } else if (shape === 'hub' || shape === 'roundRect') {
                w = Math.max(radius * 2.4, contentW);
                h = Math.max(radius * 1.4, 40 * scale);
            } else {
                w = Math.max(radius * 2.4, contentW);
                h = Math.max(radius * 1.3, 40 * scale + (subLineCount > 1 ? (subLineCount - 1) * (fontSub + 2) : 0));
            }
            return { w: w, h: h, halfW: w / 2, halfH: h / 2, contentW: contentW, subLineCount: subLineCount };
        }

        // Memoised: ctx.font assignment re-parses the font string and
        // measureText re-shapes the run, together ~1-5us per call. This is hit
        // once per label per frame from the globe marker code, which made it
        // the single largest per-frame cost on this canvas — an order of
        // magnitude above the layout solver it was blamed on. Cleared whenever
        // scaling changes.
        let _textWidthCache = new Map();
        function clearTextWidthCache() { _textWidthCache.clear(); }
        function canvasMeasureText(text, fontSize) {
            let key = fontSize + '|' + text;
            let hit = _textWidthCache.get(key);
            if (hit !== undefined) return hit;
            ctx.font = fontSize + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            let w = ctx.measureText(text).width;
            _textWidthCache.set(key, w);
            return w;
        }

        // Geometry of a drawn cylinder, shared by the measurer and the
        // renderer so a cylinder's box always covers its ink. capH is the
        // end-cap ellipse that overhangs the drum at both ends (it was a raw
        // unscaled 7 in the draw and absent from the measure); subBelow is the
        // sub-text drawn under the drum, including the last line's descent.
        function cylinderParts(radius, scale, fontSub, subLineCount) {
            let capH = 7 * scale;
            let drumH = radius * 1.5 + 16;
            let subBelow = subLineCount > 0
                ? 12 * scale + (subLineCount - 1) * (fontSub + 2) + fontSub * 0.6
                : 0;
            return { capH: capH, drumH: drumH, subBelow: subBelow, total: drumH + 2 * capH + subBelow };
        }

        function measureNodeBox(n) {
            // Reading-line captions are measured at construction (measureText
            // against their own font) — remeasuring here with node fonts would
            // corrupt the box the solve already honored.
            if (n.shape === 'caption') return;
            let box = computeNodeBox(n.shape, n.radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB, canvasMeasureText);
            n._boxW = box.w;
            n._boxH = box.h;
            n._halfW = box.halfW;
            n._halfH = box.halfH;
            return { w: box.w, h: box.h };
        }

        function aabbOverlap(a, b) {
            let ax1 = a.x - a.hw, ax2 = a.x + a.hw;
            let ay1 = a.y - a.hh, ay2 = a.y + a.hh;
            let bx1 = b.x - b.hw, bx2 = b.x + b.hw;
            let by1 = b.y - b.hh, by2 = b.y + b.hh;
            let ox = Math.min(ax2, bx2) - Math.max(ax1, bx1);
            let oy = Math.min(ay2, by2) - Math.max(ay1, by1);
            if (ox > 0 && oy > 0) return { ox: ox, oy: oy };
            return null;
        }

        function forceDirectedLayout(nodes, edges, zones, globalBounds, maxIter) {
            let n = nodes.length;
            if (n === 0) return;
            let area = (globalBounds.x2 - globalBounds.x1) * (globalBounds.y2 - globalBounds.y1);
            let k = Math.sqrt(area / n) * 0.8;
            let kSq = k * k;

            let dispX = new Float64Array(n);
            let dispY = new Float64Array(n);

            let idxMap = {};
            for (let i = 0; i < n; i++) idxMap[nodes[i].id] = i;

            let boxes = [];
            for (let i = 0; i < n; i++) boxes[i] = measureNodeBox(nodes[i]);

            let T0 = Math.max(globalBounds.x2 - globalBounds.x1, globalBounds.y2 - globalBounds.y1) * 0.1;
            let iter = maxIter || 80;

            for (let it = 0; it < iter; it++) {
                let temp = T0 * (1 - it / iter);
                if (temp < 0.1) break;

                for (let i = 0; i < n; i++) { dispX[i] = 0; dispY[i] = 0; }

                for (let i = 0; i < n; i++) {
                    let ni = nodes[i];
                    let bwi = (boxes[i].w / 2 + MIN_SPACING);
                    let bhi = (boxes[i].h / 2 + MIN_SPACING);
                    for (let j = i + 1; j < n; j++) {
                        let nj = nodes[j];
                        let dx = ni.targetX - nj.targetX;
                        let dy = ni.targetY - nj.targetY;

                        let bwj = (boxes[j].w / 2 + MIN_SPACING);
                        let bhj = (boxes[j].h / 2 + MIN_SPACING);
                        let minSepX = bwi + bwj;
                        let minSepY = bhi + bhj;

                        let normDx = minSepX > 0 ? dx / minSepX : dx;
                        let normDy = minSepY > 0 ? dy / minSepY : dy;
                        let normDist = Math.sqrt(normDx * normDx + normDy * normDy);
                        if (normDist < 0.01) {
                            normDx = (Math.random() - 0.5) * 0.1;
                            normDy = (Math.random() - 0.5) * 0.1;
                            normDist = Math.sqrt(normDx * normDx + normDy * normDy);
                        }

                        let repulse = kSq / (normDist * normDist + 0.01);
                        if (normDist < 1.5) repulse *= 3.0;
                        let fx = (normDx / normDist) * repulse;
                        let fy = (normDy / normDist) * repulse;
                        dispX[i] += fx; dispY[i] += fy;
                        dispX[j] -= fx; dispY[j] -= fy;
                    }
                }

                for (let ei = 0; ei < edges.length; ei++) {
                    let e = edges[ei];
                    let si = idxMap[e.from];
                    let ti = idxMap[e.to];
                    if (si === undefined || ti === undefined) continue;
                    let dx = nodes[si].targetX - nodes[ti].targetX;
                    let dy = nodes[si].targetY - nodes[ti].targetY;
                    let dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 0.01) continue;
                    let idealLen = k * 1.8;
                    let attract = (dist - idealLen) / dist * 0.3;
                    let fx = dx * attract;
                    let fy = dy * attract;
                    dispX[si] -= fx; dispY[si] -= fy;
                    dispX[ti] += fx; dispY[ti] += fy;
                }

                for (let i = 0; i < n; i++) {
                    let ni = nodes[i];
                    let z = zones[ni.zone || ni.id];
                    if (z && z.gx !== undefined) {
                        let gdx = z.gx - ni.targetX;
                        let gdy = z.gy - ni.targetY;
                        let gStr = z.gravity || 0.15;
                        dispX[i] += gdx * gStr;
                        dispY[i] += gdy * gStr;
                    }
                }

                let maxDisp = 0;
                for (let i = 0; i < n; i++) {
                    let ni = nodes[i];
                    let dLen = Math.sqrt(dispX[i] * dispX[i] + dispY[i] * dispY[i]);
                    if (dLen > 0) {
                        let capped = Math.min(dLen, temp);
                        ni.targetX += (dispX[i] / dLen) * capped;
                        ni.targetY += (dispY[i] / dLen) * capped;
                        if (capped > maxDisp) maxDisp = capped;
                    }

                    let z = zones[ni.zone || ni.id];
                    if (z && z.bounds) {
                        let hw = boxes[i].w / 2 + 4;
                        let hh = boxes[i].h / 2 + 4;
                        ni.targetX = Math.max(z.bounds.x1 + hw, Math.min(z.bounds.x2 - hw, ni.targetX));
                        ni.targetY = Math.max(z.bounds.y1 + hh, Math.min(z.bounds.y2 - hh, ni.targetY));
                    }
                }

                if (maxDisp < 0.5 && it > 10) break;
            }

            for (let pass = 0; pass < 12; pass++) {
                let hasOverlap = false;
                for (let i = 0; i < n; i++) {
                    boxes[i] = measureNodeBox(nodes[i]);
                }
                for (let i = 0; i < n; i++) {
                    let ni = nodes[i];
                    let bwi = boxes[i].w / 2 + MIN_SPACING;
                    let bhi = boxes[i].h / 2 + MIN_SPACING;
                    for (let j = i + 1; j < n; j++) {
                        let nj = nodes[j];
                        let bwj = boxes[j].w / 2 + MIN_SPACING;
                        let bhj = boxes[j].h / 2 + MIN_SPACING;
                        let ov = aabbOverlap(
                            { x: ni.targetX, y: ni.targetY, hw: bwi, hh: bhi },
                            { x: nj.targetX, y: nj.targetY, hw: bwj, hh: bhj }
                        );
                        if (ov) {
                            hasOverlap = true;
                            let pushStr = 0.55 + pass * 0.08;
                            if (ov.ox < ov.oy) {
                                let px = ov.ox * pushStr + 3;
                                if (ni.targetX <= nj.targetX) { ni.targetX -= px; nj.targetX += px; }
                                else { ni.targetX += px; nj.targetX -= px; }
                            } else {
                                let py = ov.oy * pushStr + 3;
                                if (ni.targetY <= nj.targetY) { ni.targetY -= py; nj.targetY += py; }
                                else { ni.targetY += py; nj.targetY -= py; }
                            }
                        }
                    }
                    let z = zones[ni.zone || ni.id];
                    if (z && z.bounds) {
                        let hw = boxes[i].w / 2 + 4;
                        let hh = boxes[i].h / 2 + 4;
                        ni.targetX = Math.max(z.bounds.x1 + hw, Math.min(z.bounds.x2 - hw, ni.targetX));
                        ni.targetY = Math.max(z.bounds.y1 + hh, Math.min(z.bounds.y2 - hh, ni.targetY));
                    }
                }
                if (!hasOverlap) break;
            }
        }

        function layoutAll() {
            computeScaling();

            // Which axis the pipeline flows along is MEASURED, not guessed from
            // a breakpoint. The horizontal flow needs the globe plus four
            // columns of real measured content plus gaps; if that does not fit
            // the canvas we actually have, the flow runs vertically instead.
            //
            // Deriving it means rotation is free: layoutAll() re-runs on every
            // resize, and a phone going 393x852 -> 852x393 re-decides from the
            // new numbers rather than from a remembered mode. A fixed 700px
            // cliff would have called landscape-phone "desktop" and portrait
            // iPad "phone", both wrong.
            SOURCES.forEach(measureNodeBox);
            measureNodeBox(HUB);
            CONFIDENCE.forEach(measureNodeBox);
            PROTOCOLS.forEach(measureNodeBox);
            let widest = function(list) {
                return Math.max.apply(null, list.map(function(n) { return n._boxW; }));
            };
            let srcNeed = Math.max(widest(SOURCES), HUB._boxW) + 26;
            let confNeed = widest(CONFIDENCE) + 26;
            // Protocols carry the relationship graph: two abreast is the least
            // that reads as a graph rather than a list.
            let protoNeed = widest(PROTOCOLS) * 2 + 26;
            let horizontalNeed = 2 * Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180)
                + srcNeed + confNeed + protoNeed + 40;
            // Beside-mode is satisfiable only when the graph fits NEXT TO the
            // console: the old test ignored the console's own beside cost
            // (386 = 360px card + margins), which created the 577-1000 band
            // where beside-mode ran with zero reserve and nodes slid under
            // the console overlay (the popover bug's family, ledger g2 spec:
            // "the FLOW switches, not the console"). The threshold is
            // measured content need + measured console cost — never a
            // media-query guess.
            let besideFits = W >= horizontalNeed + CONSOLE_BESIDE_W;
            VERTICAL_FLOW = W > 0 && !besideFits;
            // CSS follows the MEASURED mode: .topo-vertical carries the
            // console-above treatment at whatever width the measurement
            // says (the <=576px media block remains as no-JS first-paint
            // fallback). Toggle before any console measurement below so
            // consoleBox sees the post-switch geometry.
            if (wrap) wrap.classList.toggle('topo-vertical', VERTICAL_FLOW);

            // Portrait reserves space ABOVE the graph for the console instead of
            // beside it; the console is full-width at these sizes.
            // Portrait reserves space ABOVE the graph for the console instead of
            // beside it. min(190, H*0.30) was a guess, and on a phone it reserved
            // 190px for a console that is far shorter when idle — a visible empty
            // band between the search box and the globe. The console is a DOM
            // element; measure it. Read once per layout (resize), not per frame.
            let consoleTopReserve = 0;
            if (VERTICAL_FLOW) {
                let cEl = document.getElementById('topoScanConsole');
                let cH = cEl ? cEl.getBoundingClientRect().height : 0;
                // 66px is the console's own top offset in the <=576px rule.
                consoleTopReserve = cH > 0
                    ? Math.min(H * 0.42, cH + 66 + 12)
                    : Math.min(190, H * 0.30);
            }
            // These two reserves are not additive: the title band and the console
            // both start at the TOP of the canvas and overlap each other, so the
            // flow must clear whichever reaches lower — not their sum. Adding them
            // is what put a visible empty band between the search box and the
            // globe on a phone. In horizontal flow consoleTopReserve is 0 and this
            // reduces to the title band exactly as before.
            let titleSafe = Math.max(Math.max(H * 0.07, 42), consoleTopReserve);
            let legendSafe = H * 0.95;
            _legendSafeY = legendSafe;
            let usableH = legendSafe - titleSafe;

            let globeR = VERTICAL_FLOW
                ? Math.min(W * 0.30 * SCL, H * 0.13 * SCL, 120)
                : Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
            globe.R = globeR;
            // Portrait: the globe heads the flow, centred, rather than sitting
            // to the left of columns that no longer exist.
            globe.cx = VERTICAL_FLOW ? W * 0.5 : W * 0.04 + globeR;
            globe.cy = VERTICAL_FLOW ? titleSafe + globeR + 8 : titleSafe + usableH * 0.42;

            let pipeStart = globe.cx + globeR + W * 0.02;
            // The scan console is a fixed 360px card pinned top-right. Treat it
            // as occupied space rather than letting the graph run underneath
            // it — that is what put the console on top of DANE and TLS-RPT.
            // Below 1000px the console goes near-full-width and overlaying is
            // unavoidable, so reserve nothing and let it sit above.
            // Reserve whenever beside-mode runs — the mode IS the condition.
            // The old `W >= 1000` proxy left 577-1000 beside-mode widths with
            // zero reserve (nodes under the console); that band is now
            // VERTICAL_FLOW by measurement, and every remaining beside width
            // reserves.
            let consoleReserve = VERTICAL_FLOW ? 0 : CONSOLE_BESIDE_W;
            let pipeEnd = W * 0.99 - consoleReserve;
            let pipeTotal = pipeEnd - pipeStart;
            let colGap = Math.max(4, pipeTotal * 0.01);
            // Size the source and confidence columns to what they ACTUALLY
            // contain rather than to fixed fractions. The source tags carry two
            // lines of sub-text and measured ~170px against a 13% column of
            // ~100px, so they overflowed their zone and collided with the
            // confidence diamonds no matter how the clamping was tuned.
            // srcNeed / confNeed are measured above, where the flow axis is decided.

            let c1w = Math.min(Math.max(srcNeed, pipeTotal * 0.13), pipeTotal * 0.30);
            let c2w = Math.min(Math.max(confNeed, pipeTotal * 0.14), pipeTotal * 0.24);
            let c4w = SHOW_OUTPUTS ? pipeTotal * 0.16 : 0;
            // Protocols take everything left over: they carry the relationship
            // graph and benefit most from width.
            let c3w = pipeTotal - c1w - c2w - c4w - colGap * (SHOW_OUTPUTS ? 3 : 2);
            let col1L = pipeStart;
            let col1R = col1L + c1w;
            let col2L = col1R + colGap;
            let col2R = col2L + c2w;
            let col3L = col2R + colGap;
            let col3R = col3L + c3w;
            let col4L = col3R + colGap;
            let col4R = pipeEnd;

            let srcCx = (col1L + col1R) / 2;
            convergePt.x = srcCx;
            convergePt.y = globe.cy;

            let srcSpacing = usableH / (SOURCES.length + 1);
            SOURCES.forEach(function(s, i) {
                s.targetX = srcCx;
                s.targetY = titleSafe + (i + 1) * srcSpacing;
            });

            HUB.targetX = srcCx;
            HUB.targetY = globe.cy;

            let procCx = (col2L + col2R) / 2;
            ENGINE.targetX = procCx;
            ENGINE.targetY = titleSafe + usableH * 0.15;

            let confSpread = Math.max(40, (col2R - col2L) * 0.32);
            let confY = titleSafe + usableH * 0.42;
            CONFIDENCE[0].targetX = procCx;
            CONFIDENCE[0].targetY = confY - usableH * 0.06;
            CONFIDENCE[1].targetX = procCx - confSpread * 0.5;
            CONFIDENCE[1].targetY = confY + usableH * 0.06;
            CONFIDENCE[2].targetX = procCx + confSpread * 0.5;
            CONFIDENCE[2].targetY = confY + usableH * 0.06;
            CONFIDENCE[3].targetX = procCx;
            CONFIDENCE[3].targetY = confY + usableH * 0.18;

            // Storage is the persistence layer BENEATH the pipeline, not a
            // stage between confidence and output. Stacked vertically in a
            // column the three cylinders need 382px inside a 222px band
            // (measured at W=1873) — infeasible at every padding, which is why
            // they overlapped no matter how the bands were re-partitioned.
            // Side by side they need ~474px of width and one cylinder of
            // height, and the canvas has that along the bottom in abundance.
            // Laid out as an explicit foundation row: deterministic, and it
            // reads as the substrate the rest of the graph sits on.
            STORAGE.forEach(measureNodeBox);
            let storeGap = 18 * SCL;
            let storeRowW = STORAGE.reduce(function(s, n) { return s + n._boxW; }, 0) + storeGap * (STORAGE.length - 1);
            let storeRowH = Math.max.apply(null, STORAGE.map(function(n) { return n._boxH; }));
            let storeBandH = storeRowH + 20 * SCL;
            let storeBandY1 = legendSafe - storeBandH;
            let storeY = storeBandY1 + storeBandH / 2;
            // The console is a RECT, not a full-height strip: measure its
            // real extent (the popover/rl05 pattern; the post-restore
            // relayout kicks guarantee a settled console by the final pass).
            // consoleReserve is a proxy that overclaims everything BELOW the
            // console's actual bottom — at 1180 it starved this row into the
            // postgres×fixtures pile-up and called wayback's legal position
            // an intrusion at two widths (probe-measured, baseline-matched).
            let consoleBox = null;
            if (consoleReserve > 0) {
                let cEl2 = document.getElementById('topoScanConsole');
                let cvs2 = ctx.canvas.getBoundingClientRect();
                if (cEl2 && cvs2.width > 0 && cvs2.height > 0) {
                    let cb = cEl2.getBoundingClientRect();
                    if (cb.width > 0 && cb.height > 0) {
                        consoleBox = {
                            x1: (cb.left - cvs2.left) * (W / cvs2.width),
                            y1: (cb.top - cvs2.top) * (H / cvs2.height),
                            x2: (cb.right - cvs2.left) * (W / cvs2.width),
                            y2: (cb.bottom - cvs2.top) * (H / cvs2.height)
                        };
                    }
                }
                // Unmeasurable console: the strip stands, fail-conservative.
                if (!consoleBox) {
                    consoleBox = { x1: W - consoleReserve, y1: titleSafe, x2: W, y2: legendSafe };
                }
            }
            // The console joins the pairwise solve as an anchored rect —
            // band-as-rect per the g2 spec: the solve, not just the clamps,
            // keeps nodes out of it, and the verifier measures the same box.
            if (!VERTICAL_FLOW && consoleBox) {
                allLayoutNodes.push({
                    id: 'consolerect', shape: 'rect', zone: null,
                    _anchored: true,
                    targetX: (consoleBox.x1 + consoleBox.x2) / 2,
                    targetY: (consoleBox.y1 + consoleBox.y2) / 2,
                    x: (consoleBox.x1 + consoleBox.x2) / 2,
                    y: (consoleBox.y1 + consoleBox.y2) / 2,
                    _halfW: (consoleBox.x2 - consoleBox.x1) / 2,
                    _halfH: (consoleBox.y2 - consoleBox.y1) / 2
                });
            }
            // When the console's bottom clears this band, the band may use
            // the full pipe width — the space under the console is real.
            let storeRight = col4R;
            if (consoleBox && consoleBox.y2 + 24 * SCL < storeBandY1) {
                storeRight = W * 0.99;
            }
            // Centre the row on the processing column, but keep it clear of
            // the source column: col1 runs the full height, so a row that
            // starts west of col1R lands on the bottom source tag (measured:
            // root <-> postgres, 98px x 37px).
            let storeRowL = Math.max(col1R + storeGap, Math.min(storeRight - storeRowW, procCx - storeRowW / 2));
            let storeCursor = storeRowL;
            STORAGE.forEach(function(s) {
                s.targetX = storeCursor + s._boxW / 2;
                s.targetY = storeY;
                // The foundation row is deterministic SUBSTRATE — it is
                // already exempt from solver mapping, but the pairwise solve
                // could still jiggle it: at 1180 the source column's bottom
                // node pushed postgres into fixtures at the row's packed
                // minimum (probe-measured). Anchored, the row never moves and
                // intruders yield — space comes from the graph, never the
                // foundation.
                s._anchored = true;
                storeCursor += s._boxW + storeGap;
            });
            let storeBandX1 = storeRowL - storeGap;
            let storeBandX2 = storeRowL + storeRowW + storeGap;

            let protoCx = (col3L + col3R) / 2;
            let protoCy = titleSafe + usableH * 0.42;
            let protoRx = (col3R - col3L) * 0.38;
            let protoRy = usableH * 0.28;
            let angleMap = [-130, -90, -50, -10, 30, 70, 110, 150, 190];
            PROTOCOLS.forEach(function(p, i) {
                let a = angleMap[i] * DEG;
                p.targetX = protoCx + protoRx * Math.cos(a);
                p.targetY = protoCy + protoRy * Math.sin(a);
            });

            let outCx = (col4L + col4R) / 2;
            let outSpacing = usableH / (OUTPUTS.length + 1);
            OUTPUTS.forEach(function(o, i) {
                o.targetX = outCx;
                o.targetY = titleSafe + (i + 1) * outSpacing;
            });

            let globalBounds = { x1: col1L, x2: col4R, y1: titleSafe, y2: legendSafe };

            let zones = {
                'source': {
                    gx: srcCx, gy: titleSafe + usableH * 0.5,
                    gravity: 0.35,
                    bounds: { x1: col1L, x2: col1R, y1: titleSafe, y2: legendSafe }
                },
                'hub': {
                    gx: srcCx, gy: globe.cy,
                    gravity: 0.6,
                    bounds: { x1: col1L, x2: col1R, y1: titleSafe + usableH * 0.20, y2: titleSafe + usableH * 0.70 }
                },
                'engine': {
                    gx: procCx, gy: titleSafe + usableH * 0.15,
                    gravity: 0.6,
                    bounds: { x1: col2L, x2: col2R, y1: titleSafe, y2: titleSafe + usableH * 0.30 }
                },
                'confidence': {
                    gx: procCx, gy: confY + usableH * 0.06,
                    gravity: 0.30,
                    bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: storeBandY1 - 14 }
                },
                // A wide, short band along the bottom — see the foundation-row
                // placement above. Every other zone that shares its x range
                // must now stop above it, or the overlap pass spends its
                // iterations pushing protocol circles out of the substrate.
                'storage': {
                    gx: procCx, gy: storeY,
                    gravity: 0.35,
                    bounds: { x1: storeBandX1, x2: storeBandX2, y1: storeBandY1, y2: legendSafe }
                },
                'protocol': {
                    gx: protoCx, gy: protoCy,
                    gravity: 0.18,
                    bounds: { x1: col3L, x2: col3R, y1: titleSafe,
                              y2: (col3L < storeBandX2 && col3R > storeBandX1)
                                    ? Math.min(titleSafe + usableH * 0.88, storeBandY1 - 14)
                                    : titleSafe + usableH * 0.88 }
                },
                'output': {
                    gx: outCx, gy: titleSafe + usableH * 0.5,
                    gravity: 0.35,
                    bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe }
                }
            };

            // Nodes that are never drawn must never occupy layout space. With
            // SHOW_OUTPUTS false the four output hexagons are not rendered,
            // not hit-tested and their edges are skipped — but they stayed in
            // the layout set, so the overlap pass kept shoving real nodes away
            // from four invisible boxes. Worse, with c4w=0 the output zone is
            // arithmetically inverted (x1 > x2 by exactly colGap), so all four
            // pinned to a single x just inside the pipeline and pushed the
            // protocol circles left. Measured live at W=1873: output zone
            // width -10px, all four nodes at x=1458.
            let layoutOutputs = (SHOW_OUTPUTS && !HUD_ACTIVE) ? OUTPUTS : [];
            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, layoutOutputs);

            // ---- Vertical flow -------------------------------------------------
            // Portrait: the pipeline runs top-to-bottom in reading order, each
            // stage a full-width band sized to its measured content and its
            // members shelf-packed inside it. Deterministic — no ellipse, no
            // columns, no solver remap, because the solver's mobile profile is a
            // fixed 420x1780 and these bands are sized from the canvas in hand.
            //
            // Rotation needs nothing special: this runs inside layoutAll(), which
            // resize() calls, so 852x393 re-derives from scratch.
            if (VERTICAL_FLOW) {
                // Portrait is a column you TRAVEL THROUGH, not a canvas you take in
                // at once, so it is ordered by what the reader came for rather than
                // by data lineage. On a wide canvas source -> hub -> engine ->
                // confidence -> storage -> protocol -> output reads correctly
                // because it is all visible simultaneously; stacked on a phone the
                // same order buries the verdicts — SPF, DKIM, DMARC, DNSSEC, DANE —
                // six bands down, below PostgreSQL and the Internet Archive.
                //
                // Answer first, then what produced it, then where it came from:
                // protocols, engine, confidence, hub, sources, storage, outputs.
                // Horizontal flow is untouched.
                let order = [
                    // The hub leads because the globe leads: those dots ARE the
                    // resolver fleet, so DNS Resolvers is the globe's caption. Five
                    // bands of separation left the globe arriving unexplained.
                    { key: 'hub', members: [HUB] },
                    { key: 'protocol', members: PROTOCOLS },
                    { key: 'engine', members: [ENGINE] },
                    { key: 'confidence', members: CONFIDENCE },
                    { key: 'source', members: SOURCES },
                    { key: 'storage', members: STORAGE },
                    { key: 'output', members: layoutOutputs }
                ].filter(function(s) { return s.members.length > 0; });

                allLayoutNodes.forEach(measureNodeBox);
                let padX = Math.max(8, W * 0.03);
                let bandW = W - padX * 2;
                // MUST exceed overlapPad (14) used by the resolution pass, or
                // that pass reads our own shelf gaps as overlaps, pushes the
                // nodes apart, and the zone clamp pulls them back — the same
                // pad-mismatch that jammed the storage column. Measured: 30
                // residual overlaps at gap=12*SCL (7.8px at the SCL floor).
                let gap = Math.max(overlapPadValue + 3, 12 * SCL);

                // Shelf-pack a band's members into rows of bandW; returns the
                // rows so the height is known before anything is placed.
                function shelvesFor(members) {
                    let rows = [], row = [], rowW = 0, rowH = 0;
                    members.forEach(function(n) {
                        let w = n._boxW, h = n._boxH;
                        if (row.length && rowW + gap + w > bandW) {
                            rows.push({ items: row, w: rowW, h: rowH });
                            row = []; rowW = 0; rowH = 0;
                        }
                        rowW += row.length ? gap + w : w;
                        row.push(n);
                        if (h > rowH) rowH = h;
                    });
                    if (row.length) rows.push({ items: row, w: rowW, h: rowH });
                    return rows;
                }

                let plans = order.map(function(s) {
                    let rows = shelvesFor(s.members);
                    let h = rows.reduce(function(a, r) { return a + r.h; }, 0) + gap * (rows.length - 1);
                    return { key: s.key, rows: rows, need: h };
                });
                let totalNeed = plans.reduce(function(a, p) { return a + p.need; }, 0) + gap * (plans.length - 1);

                // Grow the canvas when the flow is taller than the viewport —
                // scrolling a phone is native and expected, and squeezing seven
                // stages into one screen is what made the labels collide.
                // In portrait the globe sits at the TOP: globe.cy is
                // titleSafe + globeR + 8, so it occupies from titleSafe down to
                // titleSafe + 2*globeR + 8. The bands used to start stacking at
                // titleSafe — the same y the globe starts at — which drew the
                // source band (Root/TLD, RDAP/WHOIS, CT/Subdomains, CISA/Threat)
                // and the hub band straight over it.
                //
                // Horizontal flow reserves the globe on the X axis via pipeStart
                // (globe.cx + globeR + W*0.02). When the axis flips, the reserve
                // has to flip with it; it did not. Same defect as a reserve
                // measured on the axis the layout no longer uses.
                // The globe's footprint is not just its circle: three caption
                // lines are drawn beneath it at globe.R + 8/20/32 * SCL (see the
                // fillText calls in drawGlobe). Reserving only to the circle left
                // "Orthographic Projection / Subsolar ... / terminator" printed
                // across Root/TLD and RDAP/WHOIS. 40*SCL covers the deepest
                // baseline plus descenders.
                let captionDepth = 40 * SCL;
                let flowTop = titleSafe + globe.R * 2 + 8 + captionDepth + gap;

                VERTICAL_NEEDED_H = Math.ceil(flowTop + totalNeed + gap * 2 + (H - legendSafe));

                let avail = legendSafe - flowTop;
                let slack = Math.max(0, avail - totalNeed);
                let share = plans.length ? slack / plans.length : 0;
                let cursor = flowTop;
                plans.forEach(function(p) {
                    let bandH = p.need + share;
                    let z = zones[p.key];
                    if (z) {
                        z.bounds = { x1: padX, x2: padX + bandW, y1: cursor, y2: cursor + bandH };
                        z.gx = W * 0.5;
                        z.gy = cursor + bandH / 2;
                    }
                    // Centre each shelf inside the band.
                    let inner = cursor + (bandH - p.need) / 2;
                    p.rows.forEach(function(r) {
                        let x = padX + (bandW - r.w) / 2;
                        r.items.forEach(function(n) {
                            n.targetX = x + n._boxW / 2;
                            n.targetY = inner + r.h / 2;
                            x += n._boxW + gap;
                        });
                        inner += r.h + gap;
                    });
                    cursor += bandH + gap;
                });
            }
            // ---- end vertical flow ---------------------------------------------

            let allLayoutEdges = FLOW_EDGES.concat(PROTO_EDGES);

            allLayoutNodes.forEach(function(nd) {
                measureNodeBox(nd);
            });

            // The engine/confidence/storage zones stack in one column, and
            // at narrow viewports the hand-set bands partition that column
            // wrongly: storage measures 236px of content in a 211px band
            // while engine sits on 128px of slack. No placement exists
            // inside a too-small band, so the overlap pass jams — push
            // apart, clamp back, 40 times. The content DOES fit the column
            // (589px bare in 660px, measured at 1233x750), so re-partition
            // the stacked bands by measured shelf-fit need before the pass
            // runs. Zones outside a deficient stack keep their bands.
            (function() {
                let byZone = {};
                allLayoutNodes.forEach(function(nd) {
                    let zk = nd.zone || nd.id;
                    (byZone[zk] = byZone[zk] || []).push(nd);
                });
                // Shelf-fit: members packed into rows of the band's width;
                // returns the height the zone actually needs at a given pad.
                function shelfNeed(members, zw, pad) {
                    let rowW = 0, rowH = 0, needH = 0, rows = 0;
                    members.forEach(function(nd) {
                        let w = (nd._halfW || nd.radius) * 2;
                        let h = (nd._halfH || nd.radius) * 2;
                        if (rowW > 0 && rowW + pad + w > zw) {
                            needH += rowH;
                            rows++;
                            rowW = 0;
                            rowH = 0;
                        }
                        rowW += rowW > 0 ? pad + w : w;
                        if (h > rowH) rowH = h;
                    });
                    needH += rowH;
                    rows++;
                    return needH + pad * (rows - 1);
                }
                // Group zones into vertical stacks: mutual x-overlap with
                // neither band containing the other (source contains hub by
                // design — leave containment pairs alone).
                let keys = [];
                for (let zk in byZone) {
                    if (zones[zk] && zones[zk].bounds) keys.push(zk);
                }
                keys.sort();
                let grouped = {};
                keys.forEach(function(ka) {
                    if (grouped[ka]) return;
                    let a = zones[ka].bounds;
                    let stack = [ka];
                    keys.forEach(function(kb) {
                        if (kb === ka || grouped[kb]) return;
                        let b = zones[kb].bounds;
                        let xOver = Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1);
                        let minW = Math.min(a.x2 - a.x1, b.x2 - b.x1);
                        let contains = (a.y1 <= b.y1 && a.y2 >= b.y2) || (b.y1 <= a.y1 && b.y2 >= a.y2);
                        if (xOver > minW * 0.6 && !contains) stack.push(kb);
                    });
                    if (stack.length < 2) return;
                    stack.sort(function(x, y) { return zones[x].bounds.y1 - zones[y].bounds.y1; });
                    // Only re-partition when a member measurably cannot fit
                    // its band; feasible stacks keep their designed bands.
                    let anyDeficit = stack.some(function(zk) {
                        let zb = zones[zk].bounds;
                        return shelfNeed(byZone[zk], zb.x2 - zb.x1, 0) > zb.y2 - zb.y1;
                    });
                    if (!anyDeficit) return;
                    let top = zones[stack[0]].bounds.y1;
                    let bottom = zones[stack[stack.length - 1]].bounds.y2;
                    // Stage the pad down until the stack's needs fit its span;
                    // pixel-clearance (pad 0) is the floor.
                    let needs = null, usedPad = 0;
                    let pads = [14, 8, 4, 0];
                    for (let pi = 0; pi < pads.length; pi++) {
                        let p = pads[pi];
                        let n = stack.map(function(zk) {
                            let zb = zones[zk].bounds;
                            return shelfNeed(byZone[zk], zb.x2 - zb.x1, p);
                        });
                        let total = n.reduce(function(s, v) { return s + v; }, 0) + p * (stack.length - 1);
                        if (total <= bottom - top) { needs = n; usedPad = p; break; }
                    }
                    // If no pad tier fits, the column is genuinely too short for
                    // its honestly-measured contents — at W=1873, 695px of
                    // column against 830px of need. Keep the designed bands.
                    // Proportional redistribution was tried and measured worse
                    // (AABB overlaps 1 -> 6): it relieves the starved zone by
                    // starving its neighbours, so the deficit spreads instead
                    // of resolving. An infeasible column needs a real decision
                    // — more width for the storage shelf, shorter sub-text, or
                    // its own column — not a redistribution that hides it.
                    if (!needs) return;
                    let leftover = (bottom - top) - needs.reduce(function(s, v) { return s + v; }, 0) - usedPad * (stack.length - 1);
                    if (leftover < 0) leftover = 0;
                    let share = leftover / stack.length;
                    let cursor = top;
                    stack.forEach(function(zk, i) {
                        zones[zk].bounds.y1 = cursor;
                        zones[zk].bounds.y2 = cursor + needs[i] + share;
                        cursor = zones[zk].bounds.y2 + usedPad;
                        grouped[zk] = true;
                    });
                });
            })();

            let solverProfile = W > 1000 ? 'desktop' : (W > 600 ? 'tablet' : 'mobile');
            let solverData = null;
            try {
                if (SOLVER_LAYOUTS && SOLVER_LAYOUTS[solverProfile] && SOLVER_LAYOUTS[solverProfile].nodeCenters) {
                    solverData = SOLVER_LAYOUTS[solverProfile].nodeCenters;
                }
            } catch (e) { solverData = null; }

            if (solverData && !VERTICAL_FLOW) {
                SOLVER_ACTIVE = true;
                console.log('Topology: using hybrid solver (' + solverProfile + ')');
                let solverRef = { desktop: { w: 1600, h: 900 }, tablet: { w: 1100, h: 940 }, mobile: { w: 420, h: 1700 } };
                let ref = solverRef[solverProfile] || solverRef.desktop;
                // The layout JSON carries the canvas it was solved for.
                // Prefer it: remapping through a stale hardcoded copy
                // silently skews every position when a profile is re-sized.
                try {
                    let refCanvas = SOLVER_LAYOUTS[solverProfile].canvas;
                    if (refCanvas && refCanvas.width > 0 && refCanvas.height > 0) {
                        ref = { w: refCanvas.width, h: refCanvas.height };
                    }
                } catch (e) { /* keep fallback */ }
                // Map solver coordinates into the width actually available to
                // the graph, not the raw canvas width. Reserving the console's
                // width narrowed every zone's bounds while these positions
                // still scaled to full W, so nodes landed outside their zone
                // and were clamped — several to the SAME edge, which is what
                // stacked the protocol circles and drove the confidence column
                // left into CISA/Threat and DNS Resolvers.
                // Map each zone's OWN solver extent onto that zone's client
                // bounds — an affine map per zone, not one global scale.
                //
                // The previous map was `targetX = (pos.x / ref.w) * usableW`:
                // a pure scale about x=0, which silently drops the graph's
                // left origin. Solver content starts at the profile's left
                // margin (desktop: x=430 of a 1600 canvas) while the client's
                // pipeline starts at pipeStart, so every node landed left of
                // its own column and was clamped to the column edge. When
                // several nodes in one zone all land left of it they clamp to
                // the SAME edge — which is exactly how nine protocol circles
                // became one vertical stack. The ellipse rescale that used to
                // follow could not undo it either: it computed minPX/maxPX
                // AFTER the clamp, so its `maxPX - minPX > 1` guard skipped
                // the rescale precisely when the ellipse had collapsed.
                //
                // Mapping per zone makes a node land inside its column by
                // construction, so the clamp becomes a backstop instead of the
                // thing that decides the layout — and the protocol ellipse
                // fills its zone without a special case.
                function mapSpan(v, s1, s2, d1, d2) {
                    if (!(s2 - s1 > 1e-6)) return (d1 + d2) / 2;
                    return d1 + ((v - s1) / (s2 - s1)) * (d2 - d1);
                }
                let zoneExtent = {};
                allLayoutNodes.forEach(function(nd) {
                    let pos = solverData[nd.id];
                    if (!pos) return;
                    let zk = nd.zone || nd.id;
                    let e = zoneExtent[zk];
                    if (!e) { e = zoneExtent[zk] = { x1: pos.x, x2: pos.x, y1: pos.y, y2: pos.y }; return; }
                    if (pos.x < e.x1) e.x1 = pos.x;
                    if (pos.x > e.x2) e.x2 = pos.x;
                    if (pos.y < e.y1) e.y1 = pos.y;
                    if (pos.y > e.y2) e.y2 = pos.y;
                });
                let usableW = W - consoleReserve;
                allLayoutNodes.forEach(function(nd) {
                    let pos = solverData[nd.id];
                    if (!pos) return;
                    // Storage keeps its explicit foundation-row placement. The
                    // solver arranges these three vertically for a tall narrow
                    // zone; mapping that onto a wide short band would spread
                    // them on the wrong axis and re-create the pile-up.
                    if ((nd.zone || nd.id) === 'storage') return;
                    let z = zones[nd.zone || nd.id];
                    let e = zoneExtent[nd.zone || nd.id];
                    if (z && z.bounds && e && z.bounds.x2 > z.bounds.x1 && z.bounds.y2 > z.bounds.y1) {
                        // Inset the destination by the node's own half-extent so
                        // the mapped box sits wholly inside its column.
                        let hw = nd._halfW || nd.radius || 0;
                        let hh = nd._halfH || nd.radius || 0;
                        let dx1 = z.bounds.x1 + hw, dx2 = z.bounds.x2 - hw;
                        let dy1 = z.bounds.y1 + hh, dy2 = z.bounds.y2 - hh;
                        if (!(dx2 > dx1)) { dx1 = dx2 = (z.bounds.x1 + z.bounds.x2) / 2; }
                        if (!(dy2 > dy1)) { dy1 = dy2 = (z.bounds.y1 + z.bounds.y2) / 2; }
                        nd.targetX = mapSpan(pos.x, e.x1, e.x2, dx1, dx2);
                        nd.targetY = mapSpan(pos.y, e.y1, e.y2, dy1, dy2);
                    } else {
                        nd.targetX = (pos.x / ref.w) * usableW;
                        nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
                    }
                    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
                    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
                });
            } else if (VERTICAL_FLOW) {
                // Vertical flow already placed every node deterministically in
                // its band. Falling through to the force solver would scatter
                // that packing — measured: 28 overlaps at 393x1051.
                SOLVER_ACTIVE = false;
            } else {
                SOLVER_ACTIVE = false;
                console.log('Topology: using FR fallback');
                forceDirectedLayout(allLayoutNodes, allLayoutEdges, zones, globalBounds, 120);
            }

            /* ---- Reading line 00→05 (V3 spec, ledger KEEP list) -----------
               Station captions are FIRST-CLASS RECTS in the separation solve
               (FIX-1: the prototype's captions ran through the ring cluster
               because they were ink, not geometry). They are ANCHORED: the
               pairwise pass moves nodes away from them, never them — a
               caption that drifts stops being a reading line. Horizontal
               flow only for now; vertical-flow captions ride the geometry
               slice's band work. Built HERE — after the shelf
               repartition and solver remap have produced the FINAL zone
               bounds — because strips reserved from bounds that a later
               stage rebuilds are reservations the page never had (the
               first build sat before the repartition, and every
               'mysterious' caption collision was that ordering bug). */
            let readingLine = [];
            if (!VERTICAL_FLOW) {
                let stations = [
                    { num: '01', name: 'SOURCES', q: 'WHERE DO THE FACTS COME FROM?', zone: 'source' },
                    { num: '02', name: 'AGGREGATE', q: 'RESOLVERS AGREE?', zone: 'hub' },
                    { num: '03', name: 'ANALYZE + AUDIT', q: 'WHO CHECKS THE CHECKER?', zone: 'engine' },
                    { num: '04', name: 'VERDICTS', q: 'NINE CHECKS \u2014 RINGS TELL THE STATE', zone: 'protocol' },
                    { num: '', name: 'MEMORY', q: 'WHAT DO WE REMEMBER & PROVE?', zone: 'storage' }
                ];
                let capH = 14 * SCL;
                ctx.save();
                ctx.font = '600 ' + Math.round(10.5 * SCL) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
                let rl05W = consoleReserve > 0 ?
                    ctx.measureText('05 \u00b7 YOUR REPORT \u2192').width + 24 : 0;
                function reserveStrip(cap) {
                    let capL = cap.targetX - cap._halfW, capR = cap.targetX + cap._halfW;
                    let capBottom = cap.targetY + cap._halfH;
                    for (let zk in zones) {
                        if (zk === 'storage') continue;
                        let zb = zones[zk].bounds;
                        if (!zb) continue;
                        if (capR > zb.x1 && capL < zb.x2 && capBottom > zb.y1) {
                            zb.y1 = Math.max(zb.y1, capBottom + 8 * SCL);
                        }
                    }
                }
                function mkCap(id, head, q, cx, cy, zoneKey) {
                    let text = head + (q ? ' \u2014 ' + q : '');
                    let tw = ctx.measureText(text).width;
                    let cap = {
                        id: id, shape: 'caption', zone: zoneKey || null,
                        head: head, q: q, text: text,
                        radius: capH / 2,
                        _boxW: tw, _boxH: capH,
                        _halfW: tw / 2 + 4, _halfH: capH / 2 + 3,
                        _anchored: true,
                        targetX: cx, targetY: cy
                    };
                    readingLine.push(cap);
                    allLayoutNodes.push(cap);
                    return cap;
                }
                stations.forEach(function(st) {
                    let z = zones[st.zone];
                    if (!z || !z.bounds) return;
                    let zoneW = z.bounds.x2 - z.bounds.x1;
                    let head = st.num ? st.num + ' \u00b7 ' + st.name : st.name;
                    // The question renders only where the zone can hold it —
                    // a caption wider than its column is the FIX-1 collision
                    // re-authored, and the verifier would rightly refuse it.
                    let q = st.q;
                    // Budget: the zone's width, further clipped by rl05's strip
                    // when this zone's top row would meet it (the 04\u00d705
                    // collision the verifier caught on first run).
                    let budget = zoneW - 12;
                    if (rl05W > 0) {
                        budget = Math.min(budget, (W - consoleReserve - rl05W) - z.bounds.x1 - 12);
                    }
                    if (ctx.measureText(head + ' \u2014 ' + q).width > budget) q = '';
                    let text = head + (q ? ' \u2014 ' + q : '');
                    let tw = ctx.measureText(text).width;
                    // Anchor the caption to the CENTROID of its member nodes,
                    // not the zone's left corner \u2014 a label points at its
                    // contents, not at a rectangle. The corner anchor is what
                    // floated 01 over the arc channel and left 04 beside its
                    // cluster (Carey's 2026-08-16 frames, root-caused by
                    // Science). Membership comes from each node's own zone
                    // field \u2014 never a hand list, so 02 lands on the hub it
                    // actually names.
                    let capCx = z.bounds.x1 + tw / 2 + 6;
                    let mSum = 0, mN = 0;
                    for (let mi = 0; mi < allLayoutNodes.length; mi++) {
                        let mnd = allLayoutNodes[mi];
                        if (mnd.zone === st.zone && mnd.shape !== 'caption') { mSum += mnd.targetX; mN++; }
                    }
                    if (mN > 0) {
                        // Clamp inside the zone so a skewed centroid cannot
                        // re-author the FIX-1 caption-past-column collision.
                        capCx = Math.max(z.bounds.x1 + tw / 2 + 6,
                                         Math.min(mSum / mN, z.bounds.x2 - tw / 2 - 6));
                    }
                    if (st.zone === 'storage') {
                        // Storage is the measured-tight foundation row (the
                        // 236px-in-211px history): stealing a strip from its
                        // interior re-creates the squeeze the band repartition
                        // fixed. The caption sits ABOVE the band, in the
                        // inter-band gap, claiming no interior space.
                        mkCap('rlmemory', head, q,
                            capCx, z.bounds.y1 - capH / 2 - 4, null);
                    } else {
                        // Reserve the caption strip in EVERY zone whose x-range
                        // the caption spans — zones share x at narrow widths,
                        // and a neighbour zone's clamp squeezing its node back
                        // into a caption it never reserved for was the ct\u00d7rl02
                        // failure the verifier caught at 1024px. Space always
                        // comes from zone interiors, never from the caption.
                        // The caption sits ON its cluster: y drops to just
                        // above the topmost member node, so the label owns
                        // its contents instead of a rank line with dead air
                        // under it (Carey's ruling on the 2026-08-16 frames:
                        // "labels in correct places" — the hug variant).
                        // Interior captions are plain anchored rects — the
                        // pairwise solve moves nodes off them; a strip
                        // reservation here would push whole zone tops around.
                        // Zone with no members: rank-line home + strip, the
                        // pre-hug behaviour.
                        let mTop = Infinity;
                        for (let mi2 = 0; mi2 < allLayoutNodes.length; mi2++) {
                            let nd2 = allLayoutNodes[mi2];
                            if (nd2.zone === st.zone && nd2.shape !== 'caption') {
                                let te = nd2.targetY - (nd2._halfH || nd2.radius || 0);
                                if (te < mTop) mTop = te;
                            }
                        }
                        if (mTop < Infinity) {
                            mkCap('rl' + st.num, head, q, capCx, mTop - capH / 2 - 8, st.zone);
                        } else {
                            reserveStrip(mkCap('rl' + st.num, head, q,
                                capCx, z.bounds.y1 + capH / 2 + 4, st.zone));
                        }
                    }
                });
                // 00 VANTAGE anchors to the globe itself — there is no
                // vantage zone; the globe is the station.
                let head0 = '00 \u00b7 VANTAGE';
                // Head-only in g1: the full question collides with the engine
                // cluster at every desktop width (verifier-measured); the
                // question joins the top-rail treatment in the band slice.
                let q0 = '';
                let t0w = ctx.measureText(head0 + (q0 ? ' \u2014 ' + q0 : '')).width;
                let y0 = Math.max(titleSafe + capH, globe.cy - globe.R - 10 * SCL);
                // The globe IS station 00's home, and the globe lives OUTSIDE
                // globalBounds (the graph area starts right of it) — so the
                // caption anchors to the globe's own left edge with a small
                // hard margin, never to globalBounds. The first version
                // floored on globalBounds.x1 and shoved the caption into the
                // hub column; the verifier caught the collision at every
                // desktop width until the floor was traced and removed.
                let x0 = Math.max(12 + t0w / 2, globe.cx - globe.R + t0w / 2);
                if (zones.hub && zones.hub.bounds && x0 + t0w / 2 > zones.hub.bounds.x1 - 10) {
                    // Globe crowds the hub column (very narrow beside-mode):
                    // stagger below the hub caption's reserved strip instead
                    // of authoring two anchored rects into each other.
                    y0 = zones.hub.bounds.y1 + capH + 6 * SCL;
                }
                reserveStrip(mkCap('rl00', head0, q0, x0, y0, null));
                if (consoleReserve > 0) {
                    let head5 = '05 \u00b7 YOUR REPORT \u2192';
                    let t5w = ctx.measureText(head5).width;
                    // The arrow points at the thing it names: the flagship
                    // report card, measured from the DOM the way the popover
                    // measures the console edge (Carey's ruling 2026-08-16 \u2014
                    // "drop the 05 to point directly at the pulsating
                    // engineer's report"). Unmeasurable card (first paint,
                    // hidden console variants) falls back to the top-line
                    // home with its strip.
                    let y5 = 0;
                    let cardEl = document.querySelector('.topo-scan-cta--flagship');
                    let cvs5 = ctx.canvas.getBoundingClientRect();
                    if (cardEl && cvs5.height > 0) {
                        let cr5 = cardEl.getBoundingClientRect();
                        if (cr5.height > 0 && cr5.bottom > cvs5.top && cr5.top < cvs5.bottom) {
                            y5 = (cr5.top + cr5.height / 2 - cvs5.top) * (H / cvs5.height);
                        }
                    }
                    let x5 = W - consoleReserve - t5w / 2 - 10;
                    if (y5 > titleSafe + capH) {
                        // Mid-height caption: a plain anchored rect. The strip
                        // reservation would push every x-overlapping zone's
                        // TOP below this y \u2014 the 04/05 collision inverted \u2014
                        // so separation is the pairwise solve's job here.
                        mkCap('rl05', head5, '', x5, y5, null);
                    } else {
                        reserveStrip(mkCap('rl05', head5, '', x5, titleSafe + 10 * SCL, null));
                    }
                }
                ctx.restore();
            }

            let overlapPad = overlapPadValue;
            for (let op = 0; op < 40; op++) {
                let anyOverlap = false;
                for (let oi = 0; oi < allLayoutNodes.length; oi++) {
                    for (let oj = oi + 1; oj < allLayoutNodes.length; oj++) {
                        let na = allLayoutNodes[oi], nb = allLayoutNodes[oj];
                        let ohw = (na._halfW || na.radius) + (nb._halfW || nb.radius) + overlapPad;
                        let ohh = (na._halfH || na.radius) + (nb._halfH || nb.radius) + overlapPad;
                        let odx = Math.abs(nb.targetX - na.targetX);
                        let ody = Math.abs(nb.targetY - na.targetY);
                        if (odx < ohw && ody < ohh) {
                            // Anchored rects (reading-line captions) never move:
                            // the free partner takes the whole separation. Two
                            // anchored rects overlapping is an authoring error
                            // the post-layout verifier reports rather than a
                            // fight the pass can win.
                            if (na._anchored && nb._anchored) continue;
                            let overX = ohw - odx;
                            let overY = ohh - ody;
                            let pushStr = 0.7;
                            if (overX < overY) {
                                let sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr;
                                if (na._anchored) { nb.targetX += sx * 2; }
                                else if (nb._anchored) { na.targetX -= sx * 2; }
                                else { na.targetX -= sx; nb.targetX += sx; }
                            } else {
                                let sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr;
                                if (na._anchored) { nb.targetY += sy * 2; }
                                else if (nb._anchored) { na.targetY -= sy * 2; }
                                else { na.targetY -= sy; nb.targetY += sy; }
                            }
                            anyOverlap = true;
                        }
                    }
                }
                if (!anyOverlap) break;
                allLayoutNodes.forEach(function(nd) {
                    if (nd._anchored) return;
                    let z = zones[nd.zone || nd.id];
                    if (z && z.bounds) {
                        let zHw = nd._halfW || nd.radius;
                        let zHh = nd._halfH || nd.radius;
                        nd.targetX = Math.max(z.bounds.x1 + zHw, Math.min(z.bounds.x2 - zHw, nd.targetX));
                        nd.targetY = Math.max(z.bounds.y1 + zHh, Math.min(z.bounds.y2 - zHh, nd.targetY));
                    }
                    nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
                    nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
                });
            }

            allLayoutNodes.forEach(function(nd) {
                if (!nd._initialized) {
                    nd.x = nd.targetX;
                    nd.y = nd.targetY;
                    nd._initialized = true;
                }
            });

            /* ---- Post-layout verifier (FIX-4: "no overlap must be measured,
               not asserted"). Runs once per layout on the SETTLED targets:
               strict pairwise intersection over nodes \u222a captions, plus
               node-vs-console intrusions when a reserve exists. The result is
               a number the debug HUD shows and __topoDbg exposes — a claim
               anyone can re-measure, not a property anyone asserts. */
            lastLayoutVerify = (function() {
                let rects = allLayoutNodes.map(function(n) {
                    return { id: n.id, x: n.targetX, y: n.targetY,
                             hw: n._halfW || n.radius, hh: n._halfH || n.radius };
                });
                let pairs = [];
                for (let vi = 0; vi < rects.length; vi++) {
                    for (let vj = vi + 1; vj < rects.length; vj++) {
                        let a = rects[vi], b = rects[vj];
                        if (Math.abs(b.x - a.x) < a.hw + b.hw &&
                            Math.abs(b.y - a.y) < a.hh + b.hh) {
                            pairs.push(a.id + '\u00d7' + b.id);
                        }
                    }
                }
                let intrusions = [];
                if (consoleReserve > 0 && consoleBox) {
                    // Rect-vs-rect: an intrusion needs overlap in BOTH axes
                    // with the console's MEASURED extent. The old x-only
                    // strip test reported nodes sitting in the empty space
                    // BELOW the console (wayback at two widths) — a proxy
                    // asserting occupancy it never measured.
                    rects.forEach(function(r) {
                        if (r.x + r.hw > consoleBox.x1 && r.x - r.hw < consoleBox.x2 &&
                            r.y + r.hh > consoleBox.y1 && r.y - r.hh < consoleBox.y2) {
                            intrusions.push(r.id);
                        }
                    });
                }
                return { overlaps: pairs.length, pairs: pairs.slice(0, 24),
                         consoleIntrusions: intrusions, W: W, H: H };
            })();

            // ?debug=bounds introspection: expose the exact layout the solver
            // produced so rendering bugs can be measured instead of eyeballed.
            if (typeof debugBounds !== 'undefined' && debugBounds) {
                try {
                    window.__topoDbg = {
                        // Bump on every change to registration or placement
                        // logic: the pane's HTTP cache and the boot-time asset
                        // hash make "which build is this page running" a real
                        // question, and identifier-based checks are blind to it
                        // (minification renames locals). inkRev survives.
                        inkRev: 6,
                        W: W, H: H, scl: SCL, solver: SOLVER_ACTIVE,
                        verticalFlow: VERTICAL_FLOW, horizontalNeed: horizontalNeed,
                        edgeLabelTrace: function() { return edgeLabelTrace.slice(); },
                        zones: (function() {
                            let z = {};
                            for (let k in zones) { z[k] = zones[k].bounds; }
                            return z;
                        })(),
                        boxes: allLayoutNodes.map(function(n) {
                            return { id: n.id, zone: n.zone, hw: n._halfW || n.radius, hh: n._halfH || n.radius };
                        }),
                        globe: { cx: globe.cx, cy: globe.cy, R: globe.R },
                        postLayout: lastLayoutVerify,
                        // The ink registry, all five classes. Draw-time ink is
                        // reassigned every pass — a snapshot taken here would
                        // always be empty — so these are READERS that sample the
                        // CURRENT pass. Registration happens at the draw call
                        // sites, so registered ink equals drawn ink by
                        // construction.
                        //
                        // Why this exists: every "0 overlaps" measurement before
                        // this swept __topoDbg.nodes only — 23 node boxes — while
                        // city labels, probe tags, edge pills, timing badges and
                        // the legend were structurally invisible to it. Those
                        // claims were true and nearly meaningless. Sweep ink(),
                        // never a single class list.
                        edgeLabels: function() {
                            return placedEdgeLabels.map(function(p, i) {
                                return {
                                    kind: 'edgeLabel', id: 'edgeLabel#' + i,
                                    x1: p.x - p.w / 2, y1: p.y - p.h / 2,
                                    x2: p.x + p.w / 2, y2: p.y + p.h / 2
                                };
                            });
                        },
                        // Classes 3+4: globe ink (city tags, probe tags) —
                        // top-left anchored at the draw sites.
                        globeInk: function() {
                            return globeInkCurrent.map(function(p) {
                                return { kind: p.kind, id: p.kind + '#' + p.id,
                                         x1: p.x, y1: p.y, x2: p.x + p.w, y2: p.y + p.h };
                            });
                        },
                        // Class 5a: scan-overlay timing badges under nodes.
                        scanInk: function() {
                            return scanInkCurrent.map(function(p) {
                                return { kind: p.kind, id: p.kind + '#' + p.id,
                                         x1: p.x, y1: p.y, x2: p.x + p.w, y2: p.y + p.h };
                            });
                        },
                        // Class 5b: the DOM legend's reserved band. Canvas ink
                        // with y2 beyond this rect's y1 is an invasion.
                        legendReserve: function() {
                            if (!(_legendSafeY > 0)) return [];
                            return [{ kind: 'legendReserve', id: 'legendReserve',
                                      x1: 0, y1: _legendSafeY, x2: W, y2: H }];
                        },
                        // THE sweep surface: every ink class in one list, in
                        // drawn-position coordinates (nodes included at their
                        // current animated position — the ink actually on
                        // screen). An overlap sweep that consumes anything
                        // narrower is measuring a subset and must say so.
                        ink: function() {
                            let out = [];
                            allLayoutNodes.forEach(function(n) {
                                let hw = n._halfW || n.radius, hh = n._halfH || n.radius;
                                out.push({ kind: 'node', id: n.id,
                                           x1: n.x - hw, y1: n.y - hh, x2: n.x + hw, y2: n.y + hh });
                            });
                            return out
                                .concat(window.__topoDbg.edgeLabels())
                                .concat(window.__topoDbg.globeInk())
                                .concat(window.__topoDbg.scanInk())
                                .concat(window.__topoDbg.legendReserve());
                        },
                        nodes: allLayoutNodes.map(function(n) {
                            return { id: n.id, zone: n.zone, x: Math.round(n.x), y: Math.round(n.y),
                                     tx: Math.round(n.targetX), ty: Math.round(n.targetY) };
                        })
                    };
                } catch (e) { /* diagnostics only */ }
            }
        }

        let hoverNode = null;
        let lastLayoutVerify = null;
        let mouseX = -1, mouseY = -1;

        function hitTest(mx, my) {
            let all = SOURCES.concat(CONFIDENCE, STORAGE, (HUD_ACTIVE || !SHOW_OUTPUTS) ? [] : OUTPUTS, PROTOCOLS, [ENGINE, HUB]);
            for (let i = 0; i < all.length; i++) {
                let n = all[i];
                let dx = mx - n.x;
                let dy = my - n.y;
                let hr = n.radius + 12;
                if (dx * dx + dy * dy < hr * hr) return n;
            }
            return null;
        }

        function hitTestPop(mx, my) {
            for (let i = popHitAreas.length - 1; i >= 0; i--) {
                let ha = popHitAreas[i];
                if (mx >= ha.x && mx <= ha.x + ha.w && my >= ha.y && my <= ha.y + ha.h) return ha.idx;
                let ddx = mx - ha.dotX;
                let ddy = my - ha.dotY;
                if (ddx * ddx + ddy * ddy < 144) return ha.idx;
            }
            return null;
        }

        canvas.addEventListener('mousemove', function(ev) {
            let rect = canvas.getBoundingClientRect();
            mouseX = ev.clientX - rect.left;
            mouseY = ev.clientY - rect.top;
            hoverNode = hitTest(mouseX, mouseY);
            hoveredPop = hitTestPop(mouseX, mouseY);
            canvas.classList.toggle('topo-cursor-pointer', !!(hoverNode || hoveredPop !== null));
        });

        canvas.addEventListener('mouseleave', function() {
            mouseX = -1; mouseY = -1; hoverNode = null; hoveredPop = null;
            canvas.classList.remove('topo-cursor-pointer');
        });

        function getConnectedIds(nodeId) {
            let ids = {};
            FLOW_EDGES.concat(PROTO_EDGES).forEach(function(e) {
                if (e.from === nodeId) ids[e.to] = true;
                if (e.to === nodeId) ids[e.from] = true;
            });
            return ids;
        }

        function getNodeBoundary(node, tx, ty) {
            let dx = tx - node.x;
            let dy = ty - node.y;
            let len = Math.sqrt(dx * dx + dy * dy) || 1;
            let nx = dx / len;
            let ny = dy / len;
            let pad = 5;

            if (!node._boxW) measureNodeBox(node);
            let hw = node._halfW + pad;
            let hh = node._halfH + pad;

            if (node.shape === 'rect' || node.shape === 'hub') {
                let tx2 = Math.abs(nx) > 0.001 ? hw / Math.abs(nx) : 99999;
                let ty2 = Math.abs(ny) > 0.001 ? hh / Math.abs(ny) : 99999;
                let t = Math.min(tx2, ty2);
                return { x: node.x + nx * t, y: node.y + ny * t };
            }
            if (node.shape === 'diamond') {
                let s = node.radius * 0.85 + pad;
                let t2 = s / (Math.abs(nx) + Math.abs(ny) || 1);
                return { x: node.x + nx * t2, y: node.y + ny * t2 };
            }
            if (node.shape === 'cylinder') {
                let tx3 = Math.abs(nx) > 0.001 ? hw / Math.abs(nx) : 99999;
                let ty3 = Math.abs(ny) > 0.001 ? hh / Math.abs(ny) : 99999;
                return { x: node.x + nx * Math.min(tx3, ty3), y: node.y + ny * Math.min(tx3, ty3) };
            }
            if (node.shape === 'hexagon') {
                let angle = Math.atan2(ny, nx);
                let sector = Math.round(angle / (Math.PI / 3));
                let sAngle = sector * Math.PI / 3;
                let cosD = Math.cos(angle - sAngle);
                let dist = cosD > 0.001 ? (node.radius + pad) / cosD : node.radius + pad;
                dist = Math.min(dist, node.radius + pad + 4);
                return { x: node.x + nx * dist, y: node.y + ny * dist };
            }
            return { x: node.x + nx * (node.radius + pad), y: node.y + ny * (node.radius + pad) };
        }

        let PROTO_IDS = {};
        PROTOCOLS.forEach(function(p) { PROTO_IDS[p.id] = true; });

        function findEdgeCurveOffset(from, to, edgeType) {
            if (edgeType === 'flow') return null;
            if (!PROTO_IDS[from.id] || !PROTO_IDS[to.id]) return null;
            let mx = (from.x + to.x) / 2;
            let my = (from.y + to.y) / 2;
            let edx = to.x - from.x;
            let edy = to.y - from.y;
            let elen = Math.sqrt(edx * edx + edy * edy) || 1;
            let perpX = -edy / elen;
            let perpY = edx / elen;
            let bestOffset = 0;
            let closestDist = Infinity;
            for (let pi = 0; pi < PROTOCOLS.length; pi++) {
                let pn = PROTOCOLS[pi];
                if (pn.id === from.id || pn.id === to.id) continue;
                // Solved positions: the offset choice is a decision, and
                // wobble here flipped curve sides frame-to-frame.
                let pnx = (pn.targetX !== undefined ? pn.targetX : pn.x);
                let pny = (pn.targetY !== undefined ? pn.targetY : pn.y);
                let dx2 = pnx - mx;
                let dy2 = pny - my;
                let distToMid = Math.sqrt(dx2 * dx2 + dy2 * dy2);
                if (distToMid < pn.radius + 50 && distToMid < closestDist) {
                    closestDist = distToMid;
                    let side = dx2 * perpX + dy2 * perpY;
                    bestOffset = (side > 0 ? -1 : 1) * Math.max(40, pn.radius + 20);
                }
            }
            if (bestOffset === 0) return null;
            return { cx: mx + perpX * bestOffset, cy: my + perpY * bestOffset };
        }

        function drawFlowEdge(e) {
            let from = allNodes[e.from];
            let to = allNodes[e.to];
            if (!from || !to) return;

            // Output nodes are hidden unless SHOW_OUTPUTS, and always yield
            // while the scan console/verdict panel owns the right side.
            if (((from.zone === 'output') || (to.zone === 'output')) && (HUD_ACTIVE || !SHOW_OUTPUTS)) return;

            let isHL = hoverNode && (hoverNode.id === e.from || hoverNode.id === e.to);
            let alpha;
            if (e.type === 'flow') {
                // The pipeline should read at rest, not only on hover — ICIE's
                // connections carry the whole frame, so they rest brightest.
                let touchesEngine = e.from === 'engine' || e.to === 'engine';
                alpha = isHL ? 0.35 : (touchesEngine ? 0.18 : 0.13);
            }
            else alpha = isHL ? 0.6 : (e.type === 'hard' ? 0.4 : 0.25);

            let curve = findEdgeCurveOffset(from, to, e.type);

            let startPt, endPt;
            if (curve) {
                startPt = getNodeBoundary(from, curve.cx, curve.cy);
                endPt = getNodeBoundary(to, curve.cx, curve.cy);
            } else {
                startPt = getNodeBoundary(from, to.x, to.y);
                endPt = getNodeBoundary(to, from.x, from.y);
            }

            ctx.beginPath();
            ctx.moveTo(startPt.x, startPt.y);
            if (curve) {
                ctx.quadraticCurveTo(curve.cx, curve.cy, endPt.x, endPt.y);
            } else {
                ctx.lineTo(endPt.x, endPt.y);
            }
            ctx.strokeStyle = 'rgba(255,255,255,' + alpha + ')';
            if (e.type === 'soft') { ctx.setLineDash([4, 6]); ctx.lineWidth = 1; }
            else if (e.type === 'flow') { ctx.setLineDash([3, 5]); ctx.lineWidth = 0.8; }
            else { ctx.setLineDash([]); ctx.lineWidth = 1.5; }
            ctx.stroke();
            ctx.setLineDash([]);

            if (e.type !== 'flow') {
                let now = Date.now();
                let speed = 3000 + (e.from ? e.from.charCodeAt ? 0 : e.from * 400 : 0);
                let probeT = ((now % speed) / speed);
                let probePts = [];
                if (curve) {
                    for (let pi = 0; pi < 2; pi++) {
                        let pt = (probeT + pi * 0.5) % 1.0;
                        let px = (1-pt)*(1-pt)*startPt.x + 2*(1-pt)*pt*curve.cx + pt*pt*endPt.x;
                        let py = (1-pt)*(1-pt)*startPt.y + 2*(1-pt)*pt*curve.cy + pt*pt*endPt.y;
                        probePts.push({x:px, y:py, a: 0.7 - pi*0.3});
                    }
                } else {
                    for (let pi2 = 0; pi2 < 2; pi2++) {
                        let pt2 = (probeT + pi2 * 0.5) % 1.0;
                        let px2 = startPt.x + (endPt.x - startPt.x) * pt2;
                        let py2 = startPt.y + (endPt.y - startPt.y) * pt2;
                        probePts.push({x:px2, y:py2, a: 0.7 - pi2*0.3});
                    }
                }
                for (let ppI = 0; ppI < probePts.length; ppI++) {
                    let pp = probePts[ppI];
                    ctx.beginPath();
                    ctx.arc(pp.x, pp.y, 2.5 * SCL, 0, Math.PI * 2);
                    ctx.fillStyle = 'rgba(120,180,255,' + (pp.a * alpha * 3) + ')';
                    ctx.fill();
                }
            }

            if (e.label && (isHL || e.type !== 'flow')) {
                let t = e.labelT || 0.5;
                // The label SEED is a placement decision too: seeding from the
                // animated curve left "requires" bistable at phone density —
                // the wobble crossed an avoidance threshold and the 3-pass
                // escape flung the pill to a distant slot (simulator burst,
                // 2026-08-16: top-left one frame, beside CAA the next). Seed
                // from the SOLVED endpoints through the same curve function,
                // so the whole placement chain reads one stable geometry.
                let sFrom = { id: from.id,
                              x: (from.targetX !== undefined ? from.targetX : from.x),
                              y: (from.targetY !== undefined ? from.targetY : from.y),
                              radius: from.radius, _halfW: from._halfW, _halfH: from._halfH,
                              _boxW: from._boxW, _boxH: from._boxH, shape: from.shape, zone: from.zone };
                let sTo = { id: to.id,
                            x: (to.targetX !== undefined ? to.targetX : to.x),
                            y: (to.targetY !== undefined ? to.targetY : to.y),
                            radius: to.radius, _halfW: to._halfW, _halfH: to._halfH,
                            _boxW: to._boxW, _boxH: to._boxH, shape: to.shape, zone: to.zone };
                let sCurve = findEdgeCurveOffset(sFrom, sTo, e.type);
                let lx, ly;
                if (sCurve) {
                    lx = (1 - t) * (1 - t) * sFrom.x + 2 * (1 - t) * t * sCurve.cx + t * t * sTo.x;
                    ly = (1 - t) * (1 - t) * sFrom.y + 2 * (1 - t) * t * sCurve.cy + t * t * sTo.y;
                } else {
                    lx = sFrom.x + (sTo.x - sFrom.x) * t;
                    ly = sFrom.y + (sTo.y - sFrom.y) * t;
                }
                ly -= 8 * SCL;

                for (let nri = 0; nri < allLayoutNodes.length; nri++) {
                    let nn = allLayoutNodes[nri];
                    let nhw = (nn._halfW || nn._boxW / 2 || nn.radius) + 12;
                    let nhh = (nn._halfH || nn._boxH / 2 || nn.radius) + 12;
                    // Solved positions here too — same rule as the obstacle
                    // set above: the avoidance PUSH is a decision, and wobble
                    // in its inputs is what flipped pills between rows.
                    let nsx = (nn.targetX !== undefined ? nn.targetX : nn.x);
                    let nsy = (nn.targetY !== undefined ? nn.targetY : nn.y);
                    if (nn.shape === 'circle') {
                        let ldx = lx - nsx;
                        let ldy = ly - nsy;
                        let ldist = Math.sqrt(ldx * ldx + ldy * ldy);
                        if (ldist < nn.radius + 24 && ldist > 0.1) {
                            let lnorm = (nn.radius + 28) / ldist;
                            lx = nsx + ldx * lnorm;
                            ly = nsy + ldy * lnorm;
                        }
                    } else {
                        let ndx = lx - nsx;
                        let ndy = ly - nsy;
                        if (Math.abs(ndx) < nhw && Math.abs(ndy) < nhh) {
                            if (Math.abs(ndx) / nhw > Math.abs(ndy) / nhh) {
                                lx = nsx + (ndx >= 0 ? 1 : -1) * (nhw + 6);
                            } else {
                                ly = nsy + (ndy >= 0 ? 1 : -1) * (nhh + 6);
                            }
                        }
                    }
                }

                let edgeFontSize = Math.max(8, FONT_SUB - 1);
                ctx.font = edgeFontSize + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                let tw = ctx.measureText(e.label).width;
                let pw = tw + 10 * SCL;
                let ph = edgeFontSize + 8 * SCL;

                // The pill's natural anchor after endpoint avoidance — the
                // perpendicular-escape fallback measures candidates from here,
                // in every mode, so debug and production place identically.
                let anchorLX = lx, anchorLY = ly;
                let _trace = null;
                if (typeof debugBounds !== 'undefined' && debugBounds) {
                    _trace = { edge: (from.id || '?') + '→' + (to.id || '?') + ':' + e.label,
                               afterAvoid: [lx, ly], obstacleCount: edgeLabelObstacles.length };
                    edgeLabelTrace.push(_trace);
                }

                for (let llPass = 0; llPass < 3; llPass++) {
                    let llMoved = false;
                    // Nodes and already-placed pills are one obstacle set —
                    // resolving against pills alone let a pill settle onto a
                    // node with both placements reporting success.
                    let obstacles = edgeLabelObstacles.concat(placedEdgeLabels);
                    for (let pli = 0; pli < obstacles.length; pli++) {
                        let pl = obstacles[pli];
                        let olx = Math.min(lx + pw / 2, pl.x + pl.w / 2) - Math.max(lx - pw / 2, pl.x - pl.w / 2);
                        let oly = Math.min(ly + ph / 2, pl.y + pl.h / 2) - Math.max(ly - ph / 2, pl.y - pl.h / 2);
                        if (olx > 0 && oly > 0) {
                            if (olx < oly) {
                                lx += (lx >= pl.x ? 1 : -1) * (olx + 6);
                            } else {
                                ly += (ly >= pl.y ? 1 : -1) * (oly + 6);
                            }
                            llMoved = true;
                        }
                    }
                    // Clamp inside the pass, not after it: a post-loop clamp
                    // could shove a resolved pill straight back onto an
                    // obstacle with nothing left to notice.
                    ly = Math.max(20, Math.min(H - 20, ly));
                    lx = Math.max(30, Math.min(W - 30, lx));
                    if (!llMoved) break;
                }

                // Convergence check. The pass structure translates along one
                // axis per collision, so a pill whose edge corridor is
                // narrower than the pill oscillates between its own endpoint
                // boxes and exits the pass budget still colliding (measured:
                // the dmarc→spf alignment pill, trapped at 8.8px of travel).
                // The escape that corridor geometry cannot fight is
                // PERPENDICULAR to the edge: slide sideways from the pill's
                // natural anchor to the first free spot. If no candidate in
                // budget is free, keep the least-overlapping one — drawn ink
                // and registered ink stay identical either way, so the sweep
                // still sees whatever remains.
                let stillHits = function(cx, cy) {
                    let obs = edgeLabelObstacles.concat(placedEdgeLabels);
                    let total = 0;
                    for (let oi = 0; oi < obs.length; oi++) {
                        let ob = obs[oi];
                        let ox = Math.min(cx + pw / 2, ob.x + ob.w / 2) - Math.max(cx - pw / 2, ob.x - ob.w / 2);
                        let oy = Math.min(cy + ph / 2, ob.y + ob.h / 2) - Math.max(cy - ph / 2, ob.y - ob.h / 2);
                        if (ox > 0 && oy > 0) total += ox * oy;
                    }
                    return total;
                };
                if (stillHits(lx, ly) > 0) {
                    let ex = to.x - from.x, ey = to.y - from.y;
                    let elen = Math.sqrt(ex * ex + ey * ey) || 1;
                    let perpX = -ey / elen, perpY = ex / elen;
                    let anchorX = anchorLX;
                    let anchorY = anchorLY;
                    let bestX = lx, bestY = ly, bestArea = stillHits(lx, ly);
                    for (let esc = 1; esc <= 8 && bestArea > 0; esc++) {
                        for (let side = 1; side >= -1; side -= 2) {
                            let cx = Math.max(30, Math.min(W - 30, anchorX + perpX * side * esc * 12));
                            let cy = Math.max(20, Math.min(H - 20, anchorY + perpY * side * esc * 12));
                            let area = stillHits(cx, cy);
                            if (area < bestArea) { bestArea = area; bestX = cx; bestY = cy; }
                        }
                    }
                    lx = bestX; ly = bestY;
                    if (_trace) { _trace.escapedArea = bestArea; }
                }
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';

                let pr = ph / 2;
                ctx.save();
                ctx.beginPath();
                ctx.moveTo(lx - pw / 2 + pr, ly - ph / 2);
                ctx.lineTo(lx + pw / 2 - pr, ly - ph / 2);
                ctx.arc(lx + pw / 2 - pr, ly, pr, -Math.PI / 2, Math.PI / 2);
                ctx.lineTo(lx - pw / 2 + pr, ly + ph / 2);
                ctx.arc(lx - pw / 2 + pr, ly, pr, Math.PI / 2, -Math.PI / 2);
                ctx.closePath();

                ctx.shadowColor = 'rgba(0,0,0,0.5)';
                ctx.shadowBlur = 6;
                ctx.shadowOffsetY = 2;
                let pillGrd = ctx.createLinearGradient(lx - pw/2, ly - ph/2, lx - pw/2, ly + ph/2);
                pillGrd.addColorStop(0, isHL ? 'rgba(20, 26, 40, 0.92)' : 'rgba(14, 18, 30, 0.78)');
                pillGrd.addColorStop(1, isHL ? 'rgba(10, 14, 24, 0.92)' : 'rgba(8, 10, 20, 0.78)');
                ctx.fillStyle = pillGrd;
                ctx.fill();
                ctx.shadowColor = 'transparent';
                ctx.shadowBlur = 0;
                ctx.shadowOffsetY = 0;

                ctx.strokeStyle = 'rgba(120,160,220,' + (isHL ? 0.35 : 0.15) + ')';
                ctx.lineWidth = 0.8;
                ctx.stroke();

                let hlGrd = ctx.createLinearGradient(lx - pw/2, ly - ph/2, lx + pw/2, ly - ph/2);
                hlGrd.addColorStop(0, 'rgba(255,255,255,0)');
                hlGrd.addColorStop(0.5, 'rgba(255,255,255,' + (isHL ? 0.06 : 0.03) + ')');
                hlGrd.addColorStop(1, 'rgba(255,255,255,0)');
                ctx.beginPath();
                ctx.moveTo(lx - pw / 2 + pr, ly - ph / 2);
                ctx.lineTo(lx + pw / 2 - pr, ly - ph / 2);
                ctx.arc(lx + pw / 2 - pr, ly, pr, -Math.PI / 2, 0);
                ctx.lineTo(lx + pw / 2, ly);
                ctx.lineTo(lx - pw / 2, ly);
                ctx.arc(lx - pw / 2 + pr, ly, pr, Math.PI, -Math.PI / 2);
                ctx.closePath();
                ctx.fillStyle = hlGrd;
                ctx.fill();
                ctx.restore();

                ctx.fillStyle = 'rgba(255,255,255,' + (isHL ? 0.92 : 0.6) + ')';
                ctx.fillText(e.label, lx, ly);
                if (_trace) { _trace.final = [lx, ly, pw, ph]; }
                placedEdgeLabels.push({ x: lx, y: ly, w: pw, h: ph });
            }
        }

        function drawNodeTag(n, isHover, dimmed) {
            let fs = FONT_LABEL;
            if (!n._boxW) measureNodeBox(n);
            let w = n._boxW;
            let h = n._boxH;
            n._drawW = w;
            n._drawH = h;
            ctx.font = (isHover ? 'bold ' : '') + fs + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            let r = 5;

            roundRect(n.x - w / 2, n.y - h / 2, w, h, r);
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.04 : (isHover ? 0.18 : 0.08));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.12 : (isHover ? 0.7 : 0.3));
            ctx.lineWidth = isHover ? 1.5 : 0.8;
            ctx.stroke();

            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.15)' : (isHover ? '#fff' : 'rgba(255,255,255,0.85)');
            ctx.fillText(n.label, n.x, n.y - (n.sub && !dimmed ? 7 * SCL : 0));

            if (!dimmed && n.sub) {
                let lines = n.sub.split('\n');
                ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.fillStyle = isHover ? 'rgba(255,255,255,0.55)' : 'rgba(255,255,255,0.3)';
                for (let i = 0; i < lines.length; i++) {
                    ctx.fillText(lines[i], n.x, n.y + 6 * SCL + i * (FONT_SUB + 2));
                }
            }
        }

        function drawHubNode(n) {
            let isHover = hoverNode && hoverNode.id === n.id;
            let dimmed = hoverNode && !isHover && !getConnectedIds(hoverNode.id)[n.id];

            if (!n._boxW) measureNodeBox(n);
            let w = n._boxW;
            let h = n._boxH;
            n._drawW = w;
            n._drawH = h;

            let glow = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.radius * 2);
            glow.addColorStop(0, hexToRgba(n.color, dimmed ? 0.03 : (isHover ? 0.15 : 0.06)));
            glow.addColorStop(1, hexToRgba(n.color, 0));
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius * 2, 0, Math.PI * 2);
            ctx.fillStyle = glow;
            ctx.fill();

            roundRect(n.x - w / 2, n.y - h / 2, w, h, 6);
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.05 : (isHover ? 0.2 : 0.1));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.15 : (isHover ? 0.8 : 0.4));
            ctx.lineWidth = isHover ? 2 : 1.2;
            ctx.stroke();

            ctx.font = (isHover ? 'bold ' : '') + FONT_LABEL + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.2)' : (isHover ? '#fff' : 'rgba(255,255,255,0.9)');
            ctx.fillText(n.label, n.x, n.y - 7 * SCL);

            ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.4)';
            ctx.fillText(n.sub, n.x, n.y + 8 * SCL);
        }

        function drawEngineNode(n) {
            let isHover = hoverNode && hoverNode.id === n.id;
            let dimmed = hoverNode && !isHover;

            let pulseR = n.radius + Math.sin(time * 1.5) * 3;

            let glow = ctx.createRadialGradient(n.x, n.y, pulseR * 0.2, n.x, n.y, pulseR * 2.5);
            glow.addColorStop(0, hexToRgba(n.color, dimmed ? 0.03 : (isHover ? 0.15 : 0.08)));
            glow.addColorStop(1, hexToRgba(n.color, 0));
            ctx.beginPath();
            ctx.arc(n.x, n.y, pulseR * 2.5, 0, Math.PI * 2);
            ctx.fillStyle = glow;
            ctx.fill();

            ctx.beginPath();
            ctx.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.05 : (isHover ? 0.2 : 0.1));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.15 : (isHover ? 0.8 : 0.4));
            ctx.lineWidth = isHover ? 2 : 1.2;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(n.x, n.y, pulseR * 0.55, 0, Math.PI * 2);
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.06 : 0.15);
            ctx.lineWidth = 0.5;
            ctx.stroke();

            let engFont = Math.round(17 * SCL);
            ctx.font = 'bold ' + engFont + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.2)' : (isHover ? '#fff' : 'rgba(255,255,255,0.9)');
            ctx.fillText(n.label, n.x, n.y - 8 * SCL);

            ctx.font = (FONT_SUB + 1) + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.5)';
            ctx.fillText(n.sub, n.x, n.y + 12 * SCL);
        }

        function drawConfidenceNode(n) {
            let isHover = hoverNode && hoverNode.id === n.id;
            let conn = hoverNode ? getConnectedIds(hoverNode.id) : {};
            let dimmed = hoverNode && !isHover && !conn[n.id];

            if (n.shape === 'rect') {
                drawNodeTag(n, isHover, dimmed);
                return;
            }

            let r = n.radius;
            ctx.save();
            ctx.translate(n.x, n.y);
            ctx.rotate(Math.PI / 4);
            let s = r * 0.75;
            ctx.beginPath();
            ctx.rect(-s, -s, s * 2, s * 2);
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.04 : (isHover ? 0.18 : 0.08));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.12 : (isHover ? 0.7 : 0.35));
            ctx.lineWidth = isHover ? 1.5 : 0.8;
            ctx.stroke();
            ctx.restore();

            ctx.font = (isHover ? 'bold ' : '') + FONT_LABEL + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.15)' : (isHover ? '#fff' : 'rgba(255,255,255,0.85)');
            let subLines = n.sub ? n.sub.split('\n') : [];
            ctx.fillText(n.label, n.x, n.y - (subLines.length > 1 ? 8 : 5) * SCL);

            ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.1)' : (isHover ? 'rgba(255,255,255,0.55)' : 'rgba(255,255,255,0.35)');
            for (let i = 0; i < subLines.length; i++) {
                ctx.fillText(subLines[i], n.x, n.y + 6 * SCL + i * (FONT_SUB + 2));
            }
        }

        function drawProtocolNode(p) {
            let isHover = hoverNode && hoverNode.id === p.id;
            let conn = hoverNode ? getConnectedIds(hoverNode.id) : {};
            let dimmed = hoverNode && !isHover && !conn[p.id];

            let r = p.radius;
            // The body keeps its FAMILY colour — email / transport / policy /
            // brand grouping is scientific content, not decoration. The verdict
            // lives on the ring, with a brief flash through the body when it
            // lands. An absent protocol is drained rather than recoloured, so
            // it still reads as a member of its family.
            let vCol = nodeVerdictColor(p.id);
            let status = scanState.verdicts ? scanState.verdicts[p.id] : null;
            let isIndet = status === 'indeterminate' || status === 'info';
            let flash = vCol ? verdictFlash() : 0;
            let col = flash > 0 ? mixHex(p.color, vCol, flash * 0.85) : p.color;

            let glowR = r * 1.5;
            let glow = ctx.createRadialGradient(p.x, p.y, r * 0.3, p.x, p.y, glowR);
            glow.addColorStop(0, hexToRgba(col, dimmed ? 0.03 : (isHover ? 0.2 : 0.1)));
            glow.addColorStop(1, hexToRgba(col, 0));
            ctx.beginPath();
            ctx.arc(p.x, p.y, glowR, 0, Math.PI * 2);
            ctx.fillStyle = glow;
            ctx.fill();

            ctx.beginPath();
            ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
            // Absent protocol: drained family colour + dashed edge. Present:
            // normal family fill, brightened while the verdict flash decays.
            ctx.fillStyle = hexToRgba(col, dimmed ? 0.05 : (isIndet ? 0.035 : (isHover ? 0.22 : 0.1 + flash * 0.18)));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(col, dimmed ? 0.12 : (isHover ? 0.85 : (isIndet ? 0.22 : 0.45 + flash * 0.4)));
            ctx.lineWidth = isHover ? 2 : 1;
            if (isIndet) ctx.setLineDash([5, 4]);
            ctx.stroke();
            ctx.setLineDash([]);

            let fontSize = Math.round((p.label.length > 6 ? 12 : (p.label.length > 4 ? 13 : 15)) * SCL);
            ctx.font = (isHover ? 'bold ' : '') + fontSize + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.15)' : (isHover ? '#fff' : 'rgba(255,255,255,0.9)');
            ctx.fillText(p.label, p.x, p.y - 6 * SCL);

            ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.08)' : (isHover ? 'rgba(255,255,255,0.6)' : 'rgba(255,255,255,0.3)');
            ctx.fillText('RFC ' + (p.rfc === 'draft' ? 'Draft' : p.rfc), p.x, p.y + 10 * SCL);
        }

        function drawStorageNode(n) {
            let isHover = hoverNode && hoverNode.id === n.id;
            let conn = hoverNode ? getConnectedIds(hoverNode.id) : {};
            let dimmed = hoverNode && !isHover && !conn[n.id];

            if (!n._boxW) measureNodeBox(n);
            let w = n._boxW;
            let h = n._boxH;
            n._drawW = w;
            n._drawH = h;
            // Anchor the drum from the TOP of the measured box rather than
            // centring it on n.y. The box now includes the sub-text drawn
            // below the drum (see cylinderParts), so centring the drum would
            // push that text back out the bottom — which is the bug this
            // pair-of-changes fixes. Deriving both from cylinderParts keeps
            // the drawn ink inside the measured box by construction.
            let parts = cylinderParts(n.radius, SCL, FONT_SUB, n.sub ? n.sub.split('\n').length : 0);
            let ew = w / 2;
            let eh = parts.capH;
            let drumTop = n.y - h / 2 + parts.capH;
            let drumBot = drumTop + parts.drumH;
            let drumMid = (drumTop + drumBot) / 2;

            ctx.beginPath();
            ctx.ellipse(n.x, drumTop, ew, eh, 0, Math.PI, Math.PI * 2);
            ctx.lineTo(n.x + ew, drumBot);
            ctx.ellipse(n.x, drumBot, ew, eh, 0, 0, Math.PI);
            ctx.lineTo(n.x - ew, drumTop);
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.04 : (isHover ? 0.18 : 0.08));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.12 : (isHover ? 0.7 : 0.3));
            ctx.lineWidth = isHover ? 1.5 : 0.8;
            ctx.stroke();

            ctx.beginPath();
            ctx.ellipse(n.x, drumTop, ew, eh, 0, 0, Math.PI * 2);
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.08 : (isHover ? 0.5 : 0.2));
            ctx.lineWidth = 0.6;
            ctx.stroke();

            let fs = Math.round((n.label.length > 10 ? 11 : 12) * SCL);
            ctx.font = (isHover ? 'bold ' : '') + fs + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.15)' : (isHover ? '#fff' : 'rgba(255,255,255,0.75)');
            ctx.fillText(n.label, n.x, drumMid);

            if (!dimmed && n.sub) {
                let lines = n.sub.split('\n');
                ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.fillStyle = isHover ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,0.2)';
                for (let i = 0; i < lines.length; i++) {
                    ctx.fillText(lines[i], n.x, drumBot + 12 * SCL + i * (FONT_SUB + 2));
                }
            }
        }

        function drawOutputNode(n) {
            let isHover = hoverNode && hoverNode.id === n.id;
            let conn = hoverNode ? getConnectedIds(hoverNode.id) : {};
            let dimmed = hoverNode && !isHover && !conn[n.id];

            let r = n.radius;
            ctx.beginPath();
            for (let i = 0; i < 6; i++) {
                let angle = Math.PI / 6 + i * Math.PI / 3;
                let hx = n.x + r * Math.cos(angle);
                let hy = n.y + r * Math.sin(angle);
                if (i === 0) ctx.moveTo(hx, hy);
                else ctx.lineTo(hx, hy);
            }
            ctx.closePath();
            ctx.fillStyle = hexToRgba(n.color, dimmed ? 0.04 : (isHover ? 0.18 : 0.08));
            ctx.fill();
            ctx.strokeStyle = hexToRgba(n.color, dimmed ? 0.12 : (isHover ? 0.7 : 0.3));
            ctx.lineWidth = isHover ? 1.5 : 0.8;
            ctx.stroke();

            let fs2 = Math.round((n.label.length > 10 ? 10 : (n.label.length > 7 ? 11 : 13)) * SCL);
            ctx.font = (isHover ? 'bold ' : '') + fs2 + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.15)' : (isHover ? '#fff' : 'rgba(255,255,255,0.75)');
            ctx.fillText(n.label, n.x, n.y - (n.sub && !dimmed ? 5 * SCL : 0));

            if (!dimmed && n.sub) {
                let lines = n.sub.split('\n');
                ctx.font = FONT_SUB + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                ctx.fillStyle = isHover ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,0.2)';
                for (let i = 0; i < lines.length; i++) {
                    ctx.fillText(lines[i], n.x, n.y + 8 * SCL + i * (FONT_SUB + 2));
                }
            }
        }

        let AMBIENT_COUNT = 50;
        let ambientParticles = [];
        function initAmbient() {
            ambientParticles = [];
            for (let i = 0; i < AMBIENT_COUNT; i++) {
                ambientParticles.push({
                    x: Math.random() * (W || 1200),
                    y: Math.random() * (H || 700),
                    vx: (Math.random() - 0.5) * 0.15,
                    vy: (Math.random() - 0.5) * 0.1 + 0.02,
                    size: Math.random() * 1 + 0.3,
                    alpha: Math.random() * 0.1 + 0.02
                });
            }
        }

        let flowParticles = [];
        function initFlowParticles() {
            flowParticles = [];
            FLOW_EDGES.forEach(function(e) {
                let count = 2;
                for (let i = 0; i < count; i++) {
                    flowParticles.push({
                        edge: e,
                        t: Math.random(),
                        speed: 0.002 + Math.random() * 0.003,
                        size: 1.8,
                        alpha: 0.4
                    });
                }
            });
            PROTO_EDGES.forEach(function(e) {
                for (let i = 0; i < 2; i++) {
                    flowParticles.push({
                        edge: e,
                        t: Math.random(),
                        speed: 0.002 + Math.random() * 0.002,
                        size: 1.5,
                        alpha: 0.35
                    });
                }
            });
        }

        let time = 0;
        let lastFrameMs = 0;

        function resize() {
            let rect = wrap.getBoundingClientRect();
            W = rect.width;
            H = rect.height;
            canvas.width = W * dpr;
            canvas.height = H * dpr;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            layoutAll();

            // Second pass, portrait only: seven stages stacked in reading order
            // are usually taller than a phone viewport. Grow the canvas to the
            // height the flow needs and lay out again, so the page scrolls
            // instead of the stages colliding. One extra pass, never a loop —
            // the re-layout runs against the grown height and settles.
            if (VERTICAL_FLOW && VERTICAL_NEEDED_H > H + 1) {
                let target = Math.min(VERTICAL_NEEDED_H, 6000);
                wrap.style.height = target + 'px';
                let grown = wrap.getBoundingClientRect();
                W = grown.width;
                H = grown.height;
                canvas.width = W * dpr;
                canvas.height = H * dpr;
                ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
                layoutAll();
            } else if (!VERTICAL_FLOW && wrap.style.height) {
                // Rotating back to landscape must release the portrait height,
                // or the graph keeps a phone-tall canvas on a short viewport.
                wrap.style.height = '';
            }
        }

        function update() {
            // Real elapsed time, not per-frame constants — a 120 Hz display
            // must not spin the Earth twice as fast as a 60 Hz one.
            let nowMs = Date.now();
            let dtSec = lastFrameMs > 0 ? Math.min(0.1, (nowMs - lastFrameMs) / 1000) : 0.016;
            lastFrameMs = nowMs;
            time += dtSec;

            globe.rotLon = (globe.rotLon + 4.8 * dtSec) % 360; // 4.8°/s = 75 s/revolution

            let allArr = SOURCES.concat(CONFIDENCE, STORAGE, OUTPUTS, PROTOCOLS, [ENGINE, HUB]);
            for (let i = 0; i < allArr.length; i++) {
                let n = allArr[i];
                let bx = Math.sin(time * 0.3 + n.targetX * 0.01) * 1.5;
                let by = Math.cos(time * 0.25 + n.targetY * 0.01) * 1;
                n.x += (n.targetX + bx - n.x) * 0.04;
                n.y += (n.targetY + by - n.y) * 0.04;
            }

            for (let ai = 0; ai < ambientParticles.length; ai++) {
                let ap = ambientParticles[ai];
                ap.x += ap.vx;
                ap.y += ap.vy;
                if (ap.x < 0) ap.x = W;
                if (ap.x > W) ap.x = 0;
                if (ap.y < 0) ap.y = H;
                if (ap.y > H) ap.y = 0;
            }

            for (let fi = 0; fi < flowParticles.length; fi++) {
                flowParticles[fi].t += flowParticles[fi].speed;
                if (flowParticles[fi].t > 1) flowParticles[fi].t -= 1;
            }

            for (let si = 0; si < signalParticles.length; si++) {
                signalParticles[si].t += signalParticles[si].speed;
                if (signalParticles[si].t > 1) signalParticles[si].t -= 1;
            }
        }

        function drawAmbient() {
            for (let i = 0; i < ambientParticles.length; i++) {
                let ap = ambientParticles[i];
                ctx.beginPath();
                ctx.arc(ap.x, ap.y, ap.size, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(255,255,255,' + ap.alpha + ')';
                ctx.fill();
            }
        }

        function drawFlowParticles() {
            for (let i = 0; i < flowParticles.length; i++) {
                let fp = flowParticles[i];
                let from = allNodes[fp.edge.from];
                let to = allNodes[fp.edge.to];
                if (!from || !to) continue;
                if (((from.zone === 'output') || (to.zone === 'output')) && (HUD_ACTIVE || !SHOW_OUTPUTS)) continue;
                let curve = findEdgeCurveOffset(from, to, fp.edge.type);
                let startPt, endPt;
                if (curve) {
                    startPt = getNodeBoundary(from, curve.cx, curve.cy);
                    endPt = getNodeBoundary(to, curve.cx, curve.cy);
                } else {
                    startPt = getNodeBoundary(from, to.x, to.y);
                    endPt = getNodeBoundary(to, from.x, from.y);
                }
                let x, y;
                if (curve) {
                    let ft = fp.t;
                    x = (1 - ft) * (1 - ft) * startPt.x + 2 * (1 - ft) * ft * curve.cx + ft * ft * endPt.x;
                    y = (1 - ft) * (1 - ft) * startPt.y + 2 * (1 - ft) * ft * curve.cy + ft * ft * endPt.y;
                } else {
                    x = startPt.x + (endPt.x - startPt.x) * fp.t;
                    y = startPt.y + (endPt.y - startPt.y) * fp.t;
                }
                let isHL = hoverNode && (hoverNode.id === fp.edge.from || hoverNode.id === fp.edge.to);
                let touchesEngine = fp.edge.from === 'engine' || fp.edge.to === 'engine';
                let alpha = isHL ? fp.alpha * 1.8 : fp.alpha * (touchesEngine ? 1.0 : 0.75);
                let color = from.color || COLORS.engine;
                ctx.beginPath();
                ctx.arc(x, y, fp.size * (isHL ? 1.3 : 1), 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(color, alpha);
                ctx.fill();
            }
        }

        function drawFixturePulse() {
            // Scanning a fixture-corpus domain lights up the Golden Fixtures
            // node — the disclosure lives in the graph, not just the console.
            let fx = allNodes.fixtures;
            if (!fx || !fx._initialized) return;
            let a = 0.4 + 0.35 * Math.sin(time * 3);
            let hw = (fx._halfW || fx.radius) + 10;
            let hh = (fx._halfH || fx.radius) + 10;
            ctx.strokeStyle = 'rgba(255,204,128,' + a.toFixed(3) + ')';
            ctx.lineWidth = 2;
            ctx.setLineDash([6, 4]);
            ctx.strokeRect(fx.x - hw, fx.y - hh, hw * 2, hh * 2);
            ctx.setLineDash([]);
        }

        let placedEdgeLabels = [];
        // Node AABBs as obstacles for edge-pill resolution, rebuilt once per
        // frame. placedEdgeLabels and the node boxes were two lists that never
        // consulted each other, so a pill could land on a node with both
        // placements reporting success — the first full ink() sweep caught
        // exactly that (spf×edgeLabel, dane×edgeLabel). Center-based {x,y,w,h}
        // to match the pill entries; the pad matches the +6 push offsets.
        let edgeLabelObstacles = [];
        let edgeLabelTrace = [];
        // Ink registry classes 3-5 (the __topoDbg comment names all five):
        // globe ink (city tags + probe tags) and scan-overlay ink (timing
        // badges), re-registered at their DRAW sites each frame so registered
        // ink equals drawn ink by construction — never the layout's intent.
        // _legendSafeY is the top of the DOM legend's reserved band; canvas
        // ink below that line is an invasion the sweep must see.
        let globeInkCurrent = [];
        let scanInkCurrent = [];
        let _legendSafeY = 0;

        /* The reading line: gold station heads, muted questions — drawn
           from the same anchored rects the solve honored, so ink equals
           geometry by construction. */
        function drawReadingLine() {
            if (VERTICAL_FLOW) return;
            let caps = allLayoutNodes.filter(function(n) { return n.shape === 'caption'; });
            if (!caps.length) return;
            ctx.save();
            ctx.font = '600 ' + Math.round(10.5 * SCL) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            caps.forEach(function(c) {
                let x = c.targetX - c._boxW / 2;
                let headW = ctx.measureText(c.head).width;
                ctx.fillStyle = 'rgba(212,168,83,0.92)';
                ctx.fillText(c.head, x, c.targetY);
                if (c.q) {
                    ctx.fillStyle = 'rgba(125,136,150,0.85)';
                    ctx.fillText(' \u2014 ' + c.q, x + headW, c.targetY);
                }
            });
            if (debugBounds && lastLayoutVerify) {
                let v = lastLayoutVerify;
                ctx.font = '600 ' + Math.round(11 * SCL) + 'px ui-monospace, SFMono-Regular, Menlo, monospace';
                ctx.fillStyle = v.overlaps === 0 ? 'rgba(63,185,80,0.95)' : 'rgba(239,83,80,0.95)';
                ctx.fillText('verify: ' + v.overlaps + ' overlaps' +
                    (v.consoleIntrusions.length ? ' \u00b7 console intrusions: ' + v.consoleIntrusions.join(',') : ''),
                    12, H - 12);
            }
            ctx.restore();
        }

        function draw() {
            ctx.clearRect(0, 0, W, H);

            drawAmbient();
            drawGlobe(time);
            drawReadingLine();

            placedEdgeLabels = [];
            scanInkCurrent = [];
            edgeLabelTrace = [];
            edgeLabelObstacles = [];
            allLayoutNodes.forEach(function(n) {
                let hw = n._halfW || n.radius, hh = n._halfH || n.radius;
                // Obstacles use the SOLVED position, not the animated one:
                // label placement is a per-frame decision, and feeding it the
                // ±1.5px ambient wobble put dense phone layouts on a decision
                // boundary — the pills teleported between candidate slots
                // every few frames (caught on the iPhone simulator, 2026-08-16,
                // two frames 600ms apart with "requires" in different rows).
                // Paint wobbles; decisions don't.
                let sx = (n.targetX !== undefined ? n.targetX : n.x);
                let sy = (n.targetY !== undefined ? n.targetY : n.y);
                edgeLabelObstacles.push({ x: sx, y: sy, w: hw * 2 + 12, h: hh * 2 + 12 });
            });
            FLOW_EDGES.forEach(function(e) { drawFlowEdge(e); });
            PROTO_EDGES.forEach(function(e) { drawFlowEdge(e); });
            drawFlowParticles();

            SOURCES.forEach(function(s) {
                let isHover = hoverNode && hoverNode.id === s.id;
                let conn = hoverNode ? getConnectedIds(hoverNode.id) : {};
                let dimmed = hoverNode && !isHover && !conn[s.id];
                drawNodeTag(s, isHover, dimmed);
            });

            drawHubNode(HUB);
            drawEngineNode(ENGINE);
            CONFIDENCE.forEach(function(c) { drawConfidenceNode(c); });
            STORAGE.forEach(function(s) { drawStorageNode(s); });
            PROTOCOLS.forEach(function(p) { drawProtocolNode(p); });
            if (SHOW_OUTPUTS && !HUD_ACTIVE) OUTPUTS.forEach(function(o) { drawOutputNode(o); });

            drawScanRings();
            if (FIXTURE_SCAN) drawFixturePulse();
            drawVerdictPopover();

            if (debugBounds) {
                allLayoutNodes.forEach(function(nd) {
                    if (!nd._boxW) measureNodeBox(nd);
                    let hw = nd._halfW || nd.radius;
                    let hh = nd._halfH || nd.radius;
                    ctx.strokeStyle = 'rgba(0,255,0,0.5)';
                    ctx.lineWidth = 1;
                    ctx.setLineDash([3, 3]);
                    ctx.strokeRect(nd.x - hw, nd.y - hh, hw * 2, hh * 2);
                    ctx.setLineDash([]);
                });
            }

            drawPopTooltip();
        }

        /* ---- Live scan console ------------------------------------------
           Drives the topology canvas from a real scan: POST /analyze with
           Accept: application/json (202 + progress token), then polls
           /api/scan/progress/:token every 500ms. Phase groups from the
           server's phase telemetry map onto canvas nodes; verdict chips are
           read from the saved analysis via /api/analysis/:id on completion.
           No navigation ever occurs (Safari-safe); links are plain anchors. */

        let REPLAY = window.__TOPO_REPLAY || null;
        let FIXTURE_CORPUS = window.__FIXTURE_CORPUS || null;
        let FIXTURE_SCAN = null;   // active fixture-domain disclosure, per scan
        let SCAN_NOTICE = '';      // chip text: fixture disclosure and/or subdomain note
        let HUD_ACTIVE = false;    // scan console owns the right side; output nodes yield
        // Output nodes (Reports/JSON API/Schema.org/SVG Badges) are program
        // plumbing, not DNS — hidden by default per Carey 2026-07-26, pending
        // a mission-critical verdict from the science review. Flip to true to
        // restore them to the idle graph.
        let SHOW_OUTPUTS = false;

        function fixtureLookup(domain) {
            if (!FIXTURE_CORPUS) return null;
            let d = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
            // Suffix walk = registrable-domain matching against the small
            // corpus allowlist (www.apple.com → apple.com); mirrors the
            // server's fixturecorpus.Lookup.
            while (d) {
                if (FIXTURE_CORPUS[d]) return FIXTURE_CORPUS[d];
                let i = d.indexOf('.');
                if (i < 0) return null;
                d = d.slice(i + 1);
                if (d.indexOf('.') < 0) return null;
            }
            return null;
        }

        let scanEls = {
            form: document.getElementById('topoScanForm'),
            domain: document.getElementById('topoScanDomain'),
            run: document.getElementById('topoScanRun'),
            advBtn: document.getElementById('topoScanAdvBtn'),
            adv: document.getElementById('topoScanAdv'),
            hud: document.getElementById('topoScanHud'),
            stamp: document.getElementById('topoScanStamp'),
            fixtureHud: document.getElementById('topoScanFixtureHud'),
            fixtureVerdict: document.getElementById('topoScanFixtureVerdict'),
            status: document.getElementById('topoScanStatus'),
            target: document.getElementById('topoScanTarget'),
            elapsed: document.getElementById('topoScanElapsed'),
            cancel: document.getElementById('topoScanCancel'),
            phases: document.getElementById('topoScanPhases'),
            phaseBar: document.getElementById('topoMeterPhaseBar'),
            taskBar: document.getElementById('topoMeterTaskBar'),
            latency: document.getElementById('topoScanLatency'),
            error: document.getElementById('topoScanError'),
            verdict: document.getElementById('topoScanVerdict'),
            chips: document.getElementById('topoScanChips'),
            links: document.getElementById('topoScanLinks'),
            note: document.getElementById('topoScanNote'),
            ticker: document.getElementById('topoScanTicker'),
            owls: document.getElementById('topoScanOwls'),
            owlNote: document.getElementById('topoScanOwlNote'),
            exposure: document.getElementById('topoExposure'),
            devnull: document.getElementById('topoDevnull')
        };

        let GROUP_NODES = {
            dns_records: ['hub'],
            email_auth: ['spf', 'dkim', 'dmarc'],
            dnssec_dane: ['dnssec', 'dane'],
            ct_subdomains: ['ct'],
            smtp_transport: ['probes'],
            policy_records: ['mtasts', 'tlsrpt', 'bimi', 'caa'],
            registrar_infra: ['root', 'rdap'],
            analysis_engine: ['engine']
        };

        let VERDICT_PROTOCOLS = [
            { node: 'spf',    label: 'SPF',     key: 'spf_analysis' },
            { node: 'dkim',   label: 'DKIM',    key: 'dkim_analysis' },
            { node: 'dmarc',  label: 'DMARC',   key: 'dmarc_analysis' },
            { node: 'dnssec', label: 'DNSSEC',  key: 'dnssec_analysis' },
            { node: 'dane',   label: 'DANE',    key: 'dane_analysis' },
            { node: 'mtasts', label: 'MTA-STS', key: 'mta_sts_analysis' },
            { node: 'tlsrpt', label: 'TLS-RPT', key: 'tlsrpt_analysis' },
            { node: 'bimi',   label: 'BIMI',    key: 'bimi_analysis' },
            { node: 'caa',    label: 'CAA',     key: 'caa_analysis' }
        ];

        /* Analyzer status strings → the four states this canvas can draw.
           The server deliberately passes analyzer statuses through verbatim
           (see analysis_replay.go: "never collapsed into pass or fail —
           tri-state honesty"). The client used to know only four of them and
           fall through to RED for everything else, which meant affirmative
           results — 'pass', 'present', 'ok', 'found' — drew a failure ring,
           and 'skipped'/'not_applicable' drew failure for something that was
           never measured. That is precisely the absence-as-result error the
           server comment exists to prevent, reintroduced one layer later. */
        let VERDICT_STATUS_ALIAS = {
            // Affirmative
            success: 'success', pass: 'success', passed: 'success', ok: 'success',
            present: 'success', found: 'success', secure: 'success', valid: 'success',
            configured: 'success', enforced: 'success', completed: 'success',
            synchronized: 'success', validated: 'success',
            // Qualified / partial
            warning: 'warning', partial: 'warning', propagating: 'warning',
            inferred: 'warning', deferred: 'warning', default: 'warning',
            testing: 'warning', weak: 'warning',
            // Adverse
            fail: 'failed', failed: 'failed', error: 'failed', bogus: 'failed',
            insecure: 'failed', exposed: 'failed', invalid: 'failed',
            // Observed-but-unscored, or explicitly not measured
            indeterminate: 'indeterminate', info: 'indeterminate',
            observed: 'indeterminate', not_applicable: 'indeterminate',
            skipped: 'indeterminate', unknown: 'indeterminate', custom: 'indeterminate',
            clear: 'indeterminate',
            // DANE verification vocabulary (probe /probe/dane-verify via the
            // analyzer's dane_verification field, PRs #406-#408): a measured
            // match is affirmative, a measured digest mismatch is adverse,
            // and every couldn't-measure flavor stays out of both. no_tlsa
            // is measured absence and lives in the absence set below.
            // (Do not name that set here: the drift test bounds each map by
            // the FIRST occurrence of its identifier, so naming it inside
            // this object breaks the parse — measured 2026-08-16.)
            // ⚠ 'error' above maps to 'failed' for legacy producers, but the
            // DANE lane's 'error' means could-not-measure — when the DANE
            // ring consumes dane_verification, it must canonicalize through
            // a DANE-specific table, never this generic map, or a transport
            // failure renders as an adverse verdict.
            verified: 'success',
            mismatch: 'failed',
            not_verifiable: 'indeterminate',
            cert_invalid: 'warning',
            unreachable: 'indeterminate',
            unmeasured: 'indeterminate',
            no_tlsa: 'indeterminate'
        };

        /* Absence is protocol-dependent, and that is a scientific judgement
           rather than a rendering detail — a domain with no DMARC has a real
           gap; a domain with no DANE is unremarkable. So absence maps per
           protocol instead of by one global rule. Tunable on purpose. */
        let ABSENCE_STATUSES = { missing: 1, absent: 1, not_found: 1, not_configured: 1, no_key: 1, none: 1, no_tlsa: 1 };
        let ABSENCE_IS_GAP = { spf: 1, dmarc: 1, dkim: 1, dnssec: 1, caa: 1 };

        // Which nodes reached their state by being ABSENT rather than by a
        // unsigned zone and a BROKEN DNSSEC chain both surface as amber, and
        // only the first can be a deliberate architectural choice.
        let _absentThisScan = {};

        // DNSSEC absence is not unconditionally a gap. Rendering it amber is
        // the exact error this file's own comment warns about — "a domain with
        // no DMARC has a real gap; a domain with no DANE is unremarkable" —
        // applied to a protocol the list never reconsidered.
        //
        // Measured 2026-07-31: gmail.com and google.com publish ZERO DNSKEY
        // records AND a valid MTA-STS policy (v=STSv1) plus TLS-RPT. MTA-STS
        // is the PKI-anchored substitute for what DANE obtains via DNSSEC, so
        // unsigned-with-MTA-STS is a documented architectural choice, not a
        // deficiency. A population survey (n=339) put MTA-STS at 36% for
        // mailbox providers versus 10.7% for tenant domains — providers chose
        // the PKI-anchored path at roughly 3x the rate, which is the measured
        // basis for this conditional.
        //
        // Unsigned with NO transport substitute stays amber. apple.com is that
        // case, and it is also why presence must come from the analyzer's own
        // mtasts verdict rather than a raw lookup: _mta-sts.apple.com answers
        // with a wildcard SPF TXT, so "some TXT exists there" would have
        // excused a genuine gap.
        //
        // DANE is deliberately not consulted: DANE REQUIRES DNSSEC, so
        // DANE-absent is entailed by DNSSEC-absent and counting it would
        // report one fact twice.
        }

        function canonicalVerdict(nodeId, status) {
            if (typeof status !== 'string' || !status) return 'indeterminate';
            let s = status.toLowerCase();
            if (ABSENCE_STATUSES[s]) {
                _absentThisScan[nodeId] = true;
                return ABSENCE_IS_GAP[nodeId] ? 'warning' : 'indeterminate';
            }
            // An unrecognised string means this client does not know what the
            // analyzer meant. Saying so is the honest render; guessing 'failed'
            // is not.
            return VERDICT_STATUS_ALIAS[s] || 'indeterminate';
        }

        let VERDICT_RING_COLORS = {
            failed: 'rgba(239,83,80,0.85)',
            success: 'rgba(129,199,132,0.85)',
            warning: 'rgba(255,183,77,0.85)',
            indeterminate: 'rgba(159,176,192,0.7)',
            info: 'rgba(159,176,192,0.7)'
        };

        let VERDICT_RING_OUTER = {
            failed: 'rgba(239,83,80,0.35)',
            success: 'rgba(129,199,132,0.35)',
            warning: 'rgba(255,183,77,0.35)',
            indeterminate: 'rgba(159,176,192,0.3)',
            info: 'rgba(159,176,192,0.3)'
        };

        /* ---- DNSSEC ring construction (build ledger, locked 2026-08-15) --
           Colour comes from the producer's own display_severity — the
           honest derivation the report already consumes — NEVER from the
           status field, which flattens a CD-confirmed bogus chain into
           the same "warning" as an unconfirmed one (dnssec.go:257).
           Line style is the epistemic channel: dashed means we couldn't
           tell. Dashed iff severity is 'secondary' (the producer's
           could-not-measure tier) OR the chain is 'unconfirmed' without
           a measured 'split' consensus — validators that answered and
           disagreed are a MEASURED result (solid); an absent AD flag is
           not (dashed). ad_consensus is consulted ONLY inside the
           unconfirmed branch: the inherited path writes no ad_consensus
           key at all, so a missing third field never falls through.
           A severity word this client does not recognise renders dashed
           GREY — the indeterminate colour, matching canonicalVerdict's
           own default. Amber is a verdict colour; painting it on a state
           the client couldn't interpret would claim a gap from an
           uninterpretable input (Science's fail-direction correction,
           2026-08-16). Unknown states claim nothing in BOTH channels.
           Rows scanned before the display fields existed produce no
           spec at all and keep the status-based rendering (the raw API
           payload is never view-backfilled), so the construction is
           self-scoping. */
        let RING_SEV_COLOR = { success: 'success', warning: 'warning', danger: 'failed', secondary: 'warning' };

        function dnssecRingSpec(section) {
            if (!section || typeof section !== 'object') return null;
            let sev = section.display_severity;
            if (typeof sev !== 'string' || !sev) return null;
            let known = Object.prototype.hasOwnProperty.call(RING_SEV_COLOR, sev);
            let dashed = !known || sev === 'secondary' ||
                (section.chain_of_trust === 'unconfirmed' && section.ad_consensus !== 'split');
            return {
                colorKey: known ? RING_SEV_COLOR[sev] : 'indeterminate',
                dashed: dashed,
                danger: sev === 'danger',
                label: typeof section.display_label === 'string' ? section.display_label : ''
            };
        }

        /* Canonical verdict implied by a ring spec — chips, counts and
           node logic follow the ring instead of contradicting it. A
           dashed state is could-not-tell regardless of its colour. */
        function ringSpecCanon(spec) {
            return spec.dashed ? 'indeterminate' : spec.colorKey;
        }

        /* Standards references mirror the analyzer's verified-standards
           table (integrity_hash.go) — RFC-cited, never invented. */
        let VERDICT_RFCS = {
            spf: 'RFC 7208',
            dkim: 'RFC 6376',
            dmarc: 'RFC 7489',
            dnssec: 'RFC 4033 \u00b7 4034 \u00b7 4035',
            dane: 'RFC 6698 \u00b7 RFC 7671',
            mtasts: 'RFC 8461',
            tlsrpt: 'RFC 8460',
            bimi: 'draft-brand-indicators-for-message-identification',
            caa: 'RFC 8659'
        };

        let scanState = {
            active: false,
            ringsOn: false,
            token: null,
            pollId: 0,
            failures: 0,
            startedAt: 0,
            gen: 0,
            lastPollMs: 0,
            groups: {},
            verdicts: null,
            verdictDetails: null,
            verdictRings: null
        };

        function fmtScanDur(ms) {
            if (ms >= 1000) return (ms / 1000).toFixed(1) + 's';
            return Math.round(ms) + 'ms';
        }

        /* ---- Epistemic ticker -------------------------------------------
           Rolls real pipeline events only: live scans diff successive
           progress polls (phase started / task counts / phase complete);
           replays emit the recorded telemetry events as the timeline
           passes each event's end offset. Nothing is synthesized. */

        /* Mirrors analyzer.PhaseGroupLabels (phase_telemetry.go). */
        let PHASE_LABELS = {
            dns_records: 'DNS Records',
            email_auth: 'Email Authentication',
            dnssec_dane: 'DNSSEC & DANE',
            ct_subdomains: 'Certificate Transparency',
            smtp_transport: 'SMTP Transport',
            policy_records: 'Policy Records',
            registrar_infra: 'Registrar & Infrastructure',
            analysis_engine: 'Analysis Engine',
            web3_analysis: 'Web3 Analysis'
        };

        let TICKER_MAX_LINES = 40;
        let tickerState = { prev: {}, lines: 0, emitted: null };

        function phaseDisplay(g) { return PHASE_LABELS[g] || g; }

        function fmtTickStamp(ms) { return (ms / 1000).toFixed(1) + 's'; }

        function tickerReset() {
            tickerState.prev = {};
            tickerState.lines = 0;
            tickerState.emitted = null;
            if (scanEls.ticker) {
                scanEls.ticker.textContent = '';
                setHidden(scanEls.ticker, true);
            }
        }

        function tickerLine(stamp, text, cls) {
            let div = document.createElement('div');
            div.className = 'topo-tick-line' + (cls ? ' ' + cls : '');
            if (stamp) {
                let t = document.createElement('span');
                t.className = 'topo-tick-time';
                t.textContent = stamp;
                div.appendChild(t);
            }
            div.appendChild(document.createTextNode(text));
            return div;
        }

        function tickerPush(frag, count) {
            if (!scanEls.ticker || !count) return;
            scanEls.ticker.appendChild(frag);
            tickerState.lines += count;
            while (tickerState.lines > TICKER_MAX_LINES && scanEls.ticker.firstChild) {
                scanEls.ticker.removeChild(scanEls.ticker.firstChild);
                tickerState.lines--;
            }
            setHidden(scanEls.ticker, false);
            scanEls.ticker.scrollTop = scanEls.ticker.scrollHeight;
        }

        function tickerDiffLive(data) {
            if (!scanEls.ticker) return;
            let phases = data.phases || {};
            let now = typeof data.elapsed_ms === 'number' ? fmtTickStamp(data.elapsed_ms) : '';
            let frag = document.createDocumentFragment();
            let count = 0;
            for (let g in phases) {
                let ph = phases[g];
                let prev = tickerState.prev[g] || { status: 'pending', tasks_done: 0 };
                let done = ph.status === 'done' || ph.status === 'complete';
                let running = ph.status === 'running' || ph.status === 'started';
                let prevDone = prev.status === 'done' || prev.status === 'complete';
                let prevRunning = prev.status === 'running' || prev.status === 'started';
                if (running && !prevRunning && !prevDone) {
                    frag.appendChild(tickerLine(now, phaseDisplay(g) + ' \u2014 phase started', 'topo-tick-start'));
                    count++;
                }
                let td = ph.tasks_done || 0;
                if (!done && td > (prev.tasks_done || 0) && (ph.tasks_total || 0) > 0) {
                    frag.appendChild(tickerLine(now, phaseDisplay(g) + ' \u2014 ' + td + '/' + ph.tasks_total + ' tasks', 'topo-tick-task'));
                    count++;
                }
                if (done && !prevDone) {
                    let durTxt = typeof ph.duration_ms === 'number' ? ' in ' + fmtScanDur(ph.duration_ms) : '';
                    frag.appendChild(tickerLine(now, phaseDisplay(g) + ' \u2014 complete' + durTxt, 'topo-tick-done'));
                    count++;
                }
                tickerState.prev[g] = { status: ph.status, tasks_done: td };
            }
            tickerPush(frag, count);
        }

        function tickerFail(msg) {
            if (!scanEls.ticker) return;
            let frag = document.createDocumentFragment();
            frag.appendChild(tickerLine('', 'scan failed' + (msg ? ' \u2014 ' + msg : ''), 'topo-tick-fail'));
            tickerPush(frag, 1);
        }

        function tickerReplayFrame(events, T) {
            if (!scanEls.ticker) return;
            if (!tickerState.emitted || tickerState.emitted.length !== events.length) {
                tickerState.emitted = new Array(events.length);
            }
            let frag = document.createDocumentFragment();
            let count = 0;
            for (let i = 0; i < events.length; i++) {
                if (tickerState.emitted[i]) continue;
                let ev = events[i];
                let end = ev.t + (ev.dur || 0);
                if (end > T) continue;
                tickerState.emitted[i] = true;
                let name = (ev.task || 'task') + ' (' + phaseDisplay(ev.group) + ')';
                if (ev.err) {
                    frag.appendChild(tickerLine(fmtTickStamp(end), name + ' \u2014 ' + ev.err, 'topo-tick-fail'));
                } else {
                    let txt = name + ' \u2014 ' + fmtScanDur(ev.dur || 0);
                    if (typeof ev.rc === 'number' && ev.rc > 0) {
                        txt += ' \u00b7 ' + ev.rc + (ev.rc === 1 ? ' record' : ' records');
                    }
                    frag.appendChild(tickerLine(fmtTickStamp(end), txt, 'topo-tick-task'));
                }
                count++;
            }
            tickerPush(frag, count);
        }

        /* ---- Owl semaphore ----------------------------------------------
           Renders the additive owl_semaphore key from /api/analysis/:id.
           States are computed server-side from stored analysis data; the
           client only displays them. Absent key = no owls (older scans). */

        let OWL_DEFS = [
            { key: 'normative', label: 'Normative', asset: 'NORM' },
            { key: 'non_normative', label: 'Non-Normative', asset: 'NONNORM' },
            { key: 'critical', label: 'Critical', asset: 'CRIT' },
            { key: 'metacognitive', label: 'Metacognitive', asset: 'META' }
        ];

        function owlAssetURL(asset, w) {
            return '/static/exports/owl-semaphore/derived/' + asset + '-composite-transparent-w' + w + '.webp';
        }

        function owlsReset() {
            if (scanEls.owls) {
                scanEls.owls.textContent = '';
                setHidden(scanEls.owls, true);
            }
            if (scanEls.owlNote) {
                scanEls.owlNote.textContent = '';
                setHidden(scanEls.owlNote, true);
            }
        }

        function owlToggleNote(label, reason) {
            if (!scanEls.owlNote) return;
            let open = !scanEls.owlNote.hidden && scanEls.owlNote.getAttribute('data-owl') === label;
            if (open) {
                setHidden(scanEls.owlNote, true);
                return;
            }
            scanEls.owlNote.setAttribute('data-owl', label);
            scanEls.owlNote.textContent = label + ': ' + reason;
            setHidden(scanEls.owlNote, false);
        }

        function scanBuildOwls(sem) {
            if (!scanEls.owls || !sem) return;
            owlsReset();
            let shown = 0;
            for (let i = 0; i < OWL_DEFS.length; i++) {
                let def = OWL_DEFS[i];
                let st = sem[def.key];
                if (!st || typeof st.lit !== 'boolean') continue;
                let btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'topo-owl' + (st.lit ? ' is-lit' : '');
                btn.title = (st.reason && typeof st.reason === 'string') ? st.reason : def.label;
                let img = document.createElement('img');
                img.src = owlAssetURL(def.asset, 40);
                img.srcset = owlAssetURL(def.asset, 40) + ' 1x, ' + owlAssetURL(def.asset, 96) + ' 2x';
                img.width = 40;
                img.height = 40;
                img.alt = def.label + ' owl \u2014 ' + (st.lit ? 'lit' : 'dark');
                img.loading = 'lazy';
                img.decoding = 'async';
                btn.appendChild(img);
                let cap = document.createElement('span');
                cap.className = 'topo-owl-label';
                cap.textContent = def.label;
                btn.appendChild(cap);
                (function(label, reason) {
                    btn.addEventListener('click', function() { owlToggleNote(label, reason); });
                })(def.label, (st.reason && typeof st.reason === 'string') ? st.reason : '');
                scanEls.owls.appendChild(btn);
                shown++;
            }
            setHidden(scanEls.owls, shown === 0);
        }

        function drawScanNodeLabel(n, text, color) {
            let fontPx = Math.round(9 * SCL);
            ctx.font = '600 ' + fontPx + 'px ' + 'ui-monospace, SFMono-Regular, Menlo, monospace';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = color;
            let badgeY = n.y + effRadius(n) + 9;
            ctx.fillText(text, n.x, badgeY);
            // Ink class 5a: the timing/task badge under a node. Measured at the
            // draw site (a handful per frame, bounded by phase groups — no
            // memoisation needed at this volume).
            let bw = ctx.measureText(text).width;
            scanInkCurrent.push({ kind: 'timingBadge', id: n.id, x: n.x - bw / 2, y: badgeY, w: bw, h: fontPx });
        }

        function scanPhaseLabel(ph) {
            if (ph.status === 'running' || ph.status === 'started') {
                if (typeof ph.tasks_total === 'number' && ph.tasks_total > 0) {
                    return { text: (ph.tasks_done || 0) + '/' + ph.tasks_total, color: 'rgba(255,193,7,0.85)' };
                }
                return { text: '\u2026', color: 'rgba(255,193,7,0.85)' };
            }
            if ((ph.status === 'done' || ph.status === 'complete') && typeof ph.duration_ms === 'number') {
                return { text: fmtScanDur(ph.duration_ms), color: 'rgba(129,199,132,0.75)' };
            }
            return null;
        }

        // Scan/verdict rings: circular nodes get circles, but wide box nodes
        // (source tags, IETF, storage cylinders) get rings that hug the box.
        // effRadius on a wide tag yields a circle sized to the tag's WIDTH,
        // which bleeds onto the neighbors in the packed source column — the
        // "crisp elliptical strokes overlapping the source nodes" artifact.
        // 'hub' is box-drawn (roundRect) like rect/cylinder — it was missing
        // here, so DNS Resolvers got a wide circle circumscribing its box on
        // top of the outline it already has. One indicator is enough.
        function isBoxNode(n) { return n.shape === 'rect' || n.shape === 'cylinder' || n.shape === 'hub'; }

        // Once a scan has produced a verdict, the node itself must carry it.
        // Protocol nodes are tinted by CATEGORY (DANE is transport → green),
        // so an indeterminate DANE still read as green while its chip and ring
        // said otherwise. The verdict outranks the category.
        let VERDICT_NODE_COLORS = {
            success: '#81c784',
            warning: '#ffb74d',
            indeterminate: '#9fb0c0',
            info: '#9fb0c0',
            failed: '#ef5350',
            error: '#ef5350'
        };
        function nodeVerdictColor(id) {
            if (!scanState.verdicts) return null;
            let v = scanState.verdicts[id];
            if (!v) return null;
            // scanState.verdicts holds canonical states, but fall back to
            // indeterminate rather than failed: an unknown state is unknown,
            // not bad.
            return VERDICT_NODE_COLORS[v] || VERDICT_NODE_COLORS.indeterminate;
        }

        // Verdicts arrive all at once; flash the result colour through the
        // node bodies, then decay back to the family palette. Attention first,
        // taxonomy after — the family colours are themselves scientific
        // communication and must not be permanently overwritten by a verdict.
        const VERDICT_FLASH_MS = 1400;
        function verdictFlash() {
            if (!scanState.verdictAt) return 0;
            let t = (Date.now() - scanState.verdictAt) / VERDICT_FLASH_MS;
            if (t < 0 || t > 1) return 0;
            return 1 - t;
        }

        function mixHex(a, b, t) {
            let pa = Number.parseInt(a.slice(1), 16), pb = Number.parseInt(b.slice(1), 16);
            let ar = (pa >> 16) & 255, ag = (pa >> 8) & 255, ab = pa & 255;
            let br = (pb >> 16) & 255, bg = (pb >> 8) & 255, bb = pb & 255;
            let r = Math.round(ar + (br - ar) * t);
            let g = Math.round(ag + (bg - ag) * t);
            let bl = Math.round(ab + (bb - ab) * t);
            return '#' + ((1 << 24) | (r << 16) | (g << 8) | bl).toString(16).slice(1);
        }

        function ringBoxPath(n, pad) {
            let hw = ((n._drawW || n.radius * 2.2) / 2) + pad;
            let hh = ((n._drawH || n.radius * 1.4) / 2) + pad;
            roundRect(n.x - hw, n.y - hh, hw * 2, hh * 2, 9);
        }

        function drawRingCircle(n, color, width) {
            ctx.strokeStyle = color;
            ctx.lineWidth = width;
            if (isBoxNode(n)) {
                ringBoxPath(n, 5);
                ctx.stroke();
                return;
            }
            ctx.beginPath();
            ctx.arc(n.x, n.y, effRadius(n) + 5, 0, Math.PI * 2);
            ctx.stroke();
        }

        function drawRunningRing(n) {
            if (isBoxNode(n)) {
                let a = 0.35 + 0.5 * (0.5 + 0.5 * Math.sin(time * 3.6));
                ctx.strokeStyle = 'rgba(255,193,7,' + a.toFixed(3) + ')';
                ctx.lineWidth = 2;
                ringBoxPath(n, 5);
                ctx.stroke();
                return;
            }
            let r = effRadius(n) + 5;
            let a0 = (time * 1.8) % (Math.PI * 2);
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(255,193,7,0.16)';
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, a0, a0 + Math.PI * 1.3);
            ctx.strokeStyle = 'rgba(255,193,7,0.9)';
            ctx.lineWidth = 2;
            ctx.stroke();
        }

        function scanRingColor(status) {
            if (status === 'done' || status === 'complete') return 'rgba(129,199,132,0.7)';
            if (status === 'failed' || status === 'error') return 'rgba(239,83,80,0.85)';
            return null;
        }

        function drawVerdictRings(n, status) {
            // A ring spec (producer-field construction) outranks the
            // canonical status; nodes without one keep the legacy render.
            let spec = scanState.verdictRings && scanState.verdictRings[n.id];
            let key = spec ? spec.colorKey : status;
            let vc = VERDICT_RING_COLORS[key] || VERDICT_RING_COLORS.indeterminate;
            let oc = VERDICT_RING_OUTER[key] || VERDICT_RING_OUTER.indeterminate;
            let dashed = spec ? spec.dashed : (status === 'indeterminate' || status === 'info');
            // The ring is now the sole carrier of the verdict, so it has to be
            // strong enough to read on its own against a family-coloured body.
            if (dashed) ctx.setLineDash([4, 3]);
            drawRingCircle(n, vc, 3.2);
            ctx.strokeStyle = oc;
            ctx.lineWidth = 1.6;
            if (isBoxNode(n)) {
                ringBoxPath(n, 9);
            } else {
                ctx.beginPath();
                ctx.arc(n.x, n.y, effRadius(n) + 9, 0, Math.PI * 2);
            }
            ctx.stroke();
            if (dashed) ctx.setLineDash([]);
            if (spec && spec.danger) drawDangerBadge(n);
        }

        /* The grammar's third, non-colour cue: solid-green and solid-red
           rings differ only in hue, so a measured failure additionally
           carries a badge — an exclamation drawn from primitives (bar +
           dot) so no font is involved. Shape, not colour, is the channel. */
        function drawDangerBadge(n) {
            let bx, by;
            if (isBoxNode(n)) {
                let hw = ((n._drawW || n.radius * 2.2) / 2) + 9;
                let hh = ((n._drawH || n.radius * 1.4) / 2) + 9;
                bx = n.x + hw;
                by = n.y - hh;
            } else {
                let r = effRadius(n) + 9;
                bx = n.x + r * 0.7071;
                by = n.y - r * 0.7071;
            }
            ctx.beginPath();
            ctx.arc(bx, by, 7.5, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239,83,80,0.95)';
            ctx.fill();
            ctx.strokeStyle = 'rgba(13,17,23,0.9)';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.fillStyle = '#fff';
            ctx.fillRect(bx - 0.9, by - 4.2, 1.8, 5.2);
            ctx.beginPath();
            ctx.arc(bx, by + 3.1, 1.1, 0, Math.PI * 2);
            ctx.fill();
        }

        function wrapPopoverText(text, maxW) {
            let words = String(text).split(/\s+/);
            let lines = [];
            let cur = '';
            for (let i = 0; i < words.length; i++) {
                let next = cur ? cur + ' ' + words[i] : words[i];
                if (cur && ctx.measureText(next).width > maxW) {
                    lines.push(cur);
                    cur = words[i];
                } else {
                    cur = next;
                }
                if (lines.length >= 5) {
                    lines[4] = lines[4] + ' \u2026';
                    return lines;
                }
            }
            if (cur) lines.push(cur);
            return lines;
        }

        function drawVerdictPopover() {
            if (!scanState.verdicts || !hoverNode) return;
            let status = scanState.verdicts[hoverNode.id];
            if (!status) return;
            let label = null;
            for (let i = 0; i < VERDICT_PROTOCOLS.length; i++) {
                if (VERDICT_PROTOCOLS[i].node === hoverNode.id) { label = VERDICT_PROTOCOLS[i].label; break; }
            }
            if (!label) return;

            let vc = VERDICT_RING_COLORS[status] || 'rgba(239,83,80,0.85)';
            let header = label + ' \u2014 ' + status;
            let detail = (scanState.verdictDetails && scanState.verdictDetails[hoverNode.id]) ||
                'No stored headline for this protocol.';
            let rfc = VERDICT_RFCS[hoverNode.id] || '';

            ctx.font = '11px -apple-system, BlinkMacSystemFont, monospace';
            let bodyMaxW = 260;
            let bodyLines = wrapPopoverText(detail, bodyMaxW);
            if (rfc) bodyLines.push(rfc);

            ctx.font = 'bold 12px -apple-system, BlinkMacSystemFont, sans-serif';
            let maxW = ctx.measureText(header).width;
            ctx.font = '11px -apple-system, BlinkMacSystemFont, monospace';
            for (let j = 0; j < bodyLines.length; j++) {
                let lw = ctx.measureText(bodyLines[j]).width;
                if (lw > maxW) maxW = lw;
            }

            let lineH = 17;
            let headerH = lineH + 4;
            let tipW = maxW + 24;
            let tipH = headerH + bodyLines.length * lineH + 12;
            let tipX = hoverNode.x + effRadius(hoverNode) + 16;
            let tipY = hoverNode.y - tipH / 2;
            // W is the canvas width, not the USABLE width: the scan console
            // is a DOM panel absolutely positioned OVER the canvas's right
            // side, and a popover that only respects W slides beneath it and
            // clips mid-sentence (measured on the 2026-08-16 hover series —
            // DKIM, MTA-STS and BIMI all buried under the console). The
            // console is a DOM element; measure it, per the layout code's
            // own rule. In vertical flow it sits full-width at the top, so
            // an edge that low collapses to W and the old behaviour stands.
            let limitR = W;
            let cEl = document.getElementById('topoScanConsole');
            let cvs = ctx.canvas.getBoundingClientRect();
            if (cEl && cvs.width > 0) {
                let pr = cEl.getBoundingClientRect();
                if (pr.width > 0 && pr.bottom > cvs.top && pr.top < cvs.bottom) {
                    let edge = (pr.left - cvs.left) * (W / cvs.width);
                    if (edge > W * 0.3 && edge < W) limitR = edge;
                }
            }
            if (tipX + tipW > limitR - 10) tipX = hoverNode.x - effRadius(hoverNode) - 16 - tipW;
            if (tipX + tipW > limitR - 10) tipX = limitR - 10 - tipW;
            if (tipX < 10) tipX = 10;
            if (tipY < 10) tipY = 10;
            if (tipY + tipH > H - 10) tipY = H - tipH - 10;

            ctx.save();
            ctx.shadowColor = 'rgba(0,0,0,0.6)';
            ctx.shadowBlur = 12;
            ctx.shadowOffsetX = 2;
            ctx.shadowOffsetY = 2;
            roundRect(tipX, tipY, tipW, tipH, 6);
            ctx.fillStyle = 'rgba(12, 16, 28, 0.95)';
            ctx.fill();
            ctx.restore();

            roundRect(tipX, tipY, tipW, tipH, 6);
            ctx.strokeStyle = vc;
            ctx.lineWidth = 1;
            ctx.stroke();

            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            ctx.font = 'bold 12px -apple-system, BlinkMacSystemFont, sans-serif';
            ctx.fillStyle = vc;
            ctx.fillText(header, tipX + 12, tipY + headerH / 2 + 2);

            ctx.font = '11px -apple-system, BlinkMacSystemFont, monospace';
            for (let j = 0; j < bodyLines.length; j++) {
                let isRfc = rfc && j === bodyLines.length - 1;
                ctx.fillStyle = isRfc ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,0.75)';
                ctx.fillText(bodyLines[j], tipX + 12, tipY + headerH + j * lineH + lineH / 2 + 2);
            }
        }

        function drawScanRings() {
            if (!scanState.ringsOn) return;
            for (let g in GROUP_NODES) {
                let ph = scanState.groups[g];
                if (!ph) continue;
                let ids = GROUP_NODES[g];
                for (let i = 0; i < ids.length; i++) {
                    let n = allNodes[ids[i]];
                    if (!n) continue;
                    if (i === 0) {
                        let lbl = scanPhaseLabel(ph);
                        if (lbl) drawScanNodeLabel(n, lbl.text, lbl.color);
                    }
                    if (scanState.verdicts && scanState.verdicts[ids[i]]) {
                        drawVerdictRings(n, scanState.verdicts[ids[i]]);
                        continue;
                    }
                    if (ph.status === 'running' || ph.status === 'started') {
                        drawRunningRing(n);
                    } else {
                        let c = scanRingColor(ph.status);
                        if (c) drawRingCircle(n, c, 1.6);
                    }
                }
            }
        }

        function setHidden(el, hide) { if (el) el.hidden = hide; }

        function scanReset() {
            if (scanState.pollId) clearInterval(scanState.pollId);
            scanState.gen++;
            scanState.active = false;
            scanState.ringsOn = false;
            scanState.token = null;
            scanState.pollId = 0;
            scanState.failures = 0;
            scanState.lastPollMs = 0;
            scanState.groups = {};
            scanState.verdicts = null;
            scanState.verdictAt = 0;
            scanState.verdictDetails = null;
            scanState.verdictRings = null;
            if (scanEls.phaseBar) scanEls.phaseBar.style.width = '0%';
            if (scanEls.taskBar) scanEls.taskBar.style.width = '0%';
            if (scanEls.latency) scanEls.latency.textContent = 'acquisition \u2014';
            HUD_ACTIVE = false;
            FIXTURE_SCAN = null;
            SCAN_NOTICE = '';
            setHidden(scanEls.stamp, true);
            setHidden(scanEls.fixtureHud, true);
            setHidden(scanEls.fixtureVerdict, true);
            setHidden(scanEls.hud, true);
            setHidden(scanEls.error, true);
            setHidden(scanEls.verdict, true);
            setHidden(scanEls.note, true);
            if (scanEls.chips) scanEls.chips.textContent = '';
            if (scanEls.links) scanEls.links.textContent = '';
            tickerReset();
            owlsReset();
            if (scanEls.run) scanEls.run.disabled = false;
            if (scanEls.status) {
                scanEls.status.textContent = 'Scanning';
                scanEls.status.classList.remove('is-complete', 'is-failed');
            }
            if (scanEls.cancel) scanEls.cancel.textContent = 'Cancel';
        }

        function scanShowError(msg) {
            scanEls.error.textContent = msg;
            setHidden(scanEls.error, false);
        }

        function scanStopPolling() {
            if (scanState.pollId) clearInterval(scanState.pollId);
            scanState.pollId = 0;
            scanState.active = false;
        }

        function scanFail(msg) {
            scanStopPolling();
            scanEls.status.textContent = 'Failed';
            scanEls.status.classList.add('is-failed');
            scanEls.cancel.textContent = 'Reset';
            scanEls.run.disabled = false;
            scanShowError(msg);
        }

        function scanUpdateHud(data) {
            let phases = data.phases || {};
            let total = 0;
            let done = 0;
            let tTotal = 0;
            let tDone = 0;
            let durSum = 0;
            let durMax = 0;
            let durN = 0;
            for (let k in phases) {
                total++;
                let ph = phases[k];
                if (ph.status === 'done' || ph.status === 'complete') {
                    done++;
                    if (typeof ph.duration_ms === 'number') {
                        durSum += ph.duration_ms;
                        durN++;
                        if (ph.duration_ms > durMax) durMax = ph.duration_ms;
                    }
                }
                tTotal += ph.tasks_total || 0;
                tDone += ph.tasks_done || 0;
            }
            scanEls.phases.textContent = 'phases ' + done + '/' + total + ' \u00b7 tasks ' + tDone + '/' + tTotal;
            if (scanEls.phaseBar) scanEls.phaseBar.style.width = (total > 0 ? Math.round((done / total) * 100) : 0) + '%';
            if (scanEls.taskBar) scanEls.taskBar.style.width = (tTotal > 0 ? Math.round((tDone / tTotal) * 100) : 0) + '%';
            if (scanEls.latency) {
                let parts = [];
                if (scanState.lastPollMs > 0) parts.push('poll ' + fmtScanDur(scanState.lastPollMs));
                if (durN > 0) parts.push('phase avg ' + fmtScanDur(durSum / durN) + ' \u00b7 max ' + fmtScanDur(durMax));
                scanEls.latency.textContent = parts.length ? 'acquisition ' + parts.join(' \u00b7 ') : 'acquisition \u2014';
            }
            if (typeof data.elapsed_ms === 'number') {
                scanEls.elapsed.textContent = (data.elapsed_ms / 1000).toFixed(1) + 's';
            }
        }

        function verdictClass(canon) {
            if (canon === 'success') return 'topo-v-ok';
            if (canon === 'warning') return 'topo-v-warn';
            if (canon === 'indeterminate' || canon === 'info') return 'topo-v-ind';
            return 'topo-v-bad';
        }

        function scanBuildChips(fr) {
            _absentThisScan = {};
            scanState.verdicts = {};
            scanState.verdictDetails = {};
            scanState.verdictRings = {};
            scanState.verdictAt = Date.now();
            for (let i = 0; i < VERDICT_PROTOCOLS.length; i++) {
                let vp = VERDICT_PROTOCOLS[i];
                let section = fr[vp.key];
                let chip = document.createElement('span');
                if (section && typeof section.status === 'string') {
                    // Canonicalise once, here. Everything downstream — chips,
                    // node tint, rings — reads the canonical state, while the
                    // tooltip still shows the analyzer's own word so nothing
                    // is hidden by the translation.
                    let canon = canonicalVerdict(vp.node, section.status);
                    let spec = vp.node === 'dnssec' ? dnssecRingSpec(section) : null;
                    if (spec) {
                        // Ring construction: the producer's display fields
                        // outrank the flattening status string, and the chip
                        // follows the ring so the console never contradicts
                        // the canvas. Both words stay visible in the title.
                        canon = ringSpecCanon(spec);
                        scanState.verdictRings[vp.node] = spec;
                        chip.title = vp.label + ': ' + (spec.label || section.status) +
                            ' — analyzer status: ' + section.status;
                    } else {
                        chip.title = vp.label + ': ' + section.status;
                    }
                    chip.className = 'topo-vchip ' + verdictClass(canon);
                    scanState.verdicts[vp.node] = canon;
                    if (typeof section.message === 'string' && section.message) {
                        scanState.verdictDetails[vp.node] = section.message;
                    }
                } else {
                    chip.className = 'topo-vchip topo-v-ind';
                    chip.title = vp.label + ': no data in stored analysis';
                    scanState.verdicts[vp.node] = 'indeterminate';
                }
                chip.textContent = vp.label;
                scanEls.chips.appendChild(chip);
            }
        }

        function scanAddLink(href, text, title) {
            let a = document.createElement('a');
            a.href = href;
            a.textContent = text;
            if (title) a.title = title;
            scanEls.links.appendChild(a);
        }

        // sub renders VISIBLY under the label. It used to be passed as
        // a.title — a hover tooltip, which nobody sees on touch and few see on
        // desktop. Right after a 60-second scan the reader needs to know which
        // door to open, so the difference between the reports has to be legible
        // without hovering.
        // onClick makes a CTA an action rather than a destination — used by Play
        // Again, which restarts the timeline in place instead of navigating. It
        // keeps anchor styling and keyboard behaviour; the href stays '#' and the
        // default is prevented.
        function scanAddCTA(href, text, sub, extraClass, onClick) {
            let a = document.createElement('a');
            a.className = 'topo-scan-cta' + (extraClass ? ' ' + extraClass : '');
            a.href = href;
            if (onClick) {
                a.addEventListener('click', function(ev) { ev.preventDefault(); onClick(); });
            }
            let label = document.createElement('span');
            label.className = 'topo-scan-cta-label';
            label.textContent = text;
            a.appendChild(label);
            if (sub) {
                let s = document.createElement('span');
                s.className = 'topo-scan-cta-sub';
                s.textContent = sub;
                a.appendChild(s);
            }
            scanEls.links.appendChild(a);
        }

        // Stamps the subject and the moment under the page title, where there
        // is open space — the instrument should say what it measured and when.
        function scanSetStamp(domain, seconds) {
            if (!scanEls.stamp) return;
            if (!domain) { scanEls.stamp.hidden = true; return; }
            scanEls.stamp.textContent = '';
            let d = document.createElement('span');
            d.className = 'topo-stamp-domain';
            d.textContent = domain;
            scanEls.stamp.appendChild(d);
            let meta = document.createElement('span');
            meta.className = 'topo-stamp-meta';
            let now = new Date();
            let hh = String(now.getUTCHours()).padStart(2, '0');
            let mm = String(now.getUTCMinutes()).padStart(2, '0');
            meta.textContent = (seconds ? 'analysed in ' + seconds + ' · ' : '') + hh + ':' + mm + ' UTC';
            scanEls.stamp.appendChild(meta);
            scanEls.stamp.hidden = false;
        }

        // Builds the per-scan notice: fixture disclosure (annotated when the
        // match came via a parent domain) and/or a plain subdomain heads-up
        // for www.-prefixed inputs. The www rule is deliberately narrow — a
        // general registrable-domain test needs the PSL, and bbc.co.uk must
        // not be called a subdomain.
        function scanNotices(domain) {
            let d = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
            let fx = fixtureLookup(d);
            let exact = FIXTURE_CORPUS && FIXTURE_CORPUS[d];
            let text = '';
            if (fx) {
                text = fx.badge + ' — ' + fx.note;
                if (!exact) text += ' (Matched via its parent domain — you are scanning a subdomain.)';
            } else if (d.indexOf('www.') === 0) {
                text = 'Heads-up: ' + d + ' is a subdomain — email posture is typically evaluated at the registrable domain (' + d.slice(4) + ').';
            }
            return { fx: fx, text: text };
        }

        function scanShowNotice(el) {
            if (!el) return;
            if (SCAN_NOTICE) {
                el.textContent = SCAN_NOTICE;
                el.hidden = false;
            } else {
                el.hidden = true;
            }
        }

        function scanLoadVerdicts(analysisID, redirectURL, isRestore) {
            let myGen = scanState.gen;
            let base = redirectURL || ('/analysis/' + analysisID);
            setHidden(scanEls.verdict, false);
            scanShowNotice(scanEls.fixtureVerdict);
            // isRestore: re-writing the record here would stamp a new ts on
            // every page view, so the 6-hour expiry could never elapse — the
            // panel would persist indefinitely for anyone who keeps returning.
            // Only a real scan may (re)start that clock.
            if (!REPLAY && !isRestore) {
                // Survive refresh: the report links shouldn't evaporate on
                // reload. Restored at init from sessionStorage.
                try {
                    sessionStorage.setItem('topoLastScan', JSON.stringify({
                        id: analysisID, base: base,
                        domain: scanEls.target ? scanEls.target.textContent : '',
                        ts: Date.now()
                    }));
                } catch (e) { /* private mode \u2014 restore is best-effort */ }
            }
            scanAddCTA(base, 'Engineer\u2019s Report', 'The deepest technical findings \u2014 every record, every RFC', 'topo-scan-cta--flagship');
            scanAddCTA('/analysis/' + analysisID + '/view/B', 'Executive Brief', 'The same findings in plain English \u2014 built to hand to a decision-maker');
            // Remediation and Replay share one row: what to fix next, and how
            // it was measured. Remediation is the tool's next most important
            // output after the reports themselves.
            scanAddCTA('/remediation?analysis_id=' + analysisID, 'Remediation', 'Prioritised, actionable fixes for what this scan found', 'topo-scan-cta--half topo-scan-cta--fix');
            // The half-width pair needs BOTH halves or flexbox grows the survivor
            // to fill the row, which silently undoes the split. In replay the
            // Replay link would point at the page you are already on, so the
            // partner becomes Play Again \u2014 the same replayStart() the Restart
            // control runs, placed where the eye already is.
            if (!REPLAY) {
                scanAddCTA('/replay/' + analysisID, '\u25b6 Replay', 'Shareable timeline replay of this scan on the pipeline topology', 'topo-scan-cta--half');
            } else {
                scanAddCTA('#', '\u21bb Play Again', 'Run this recorded timeline from the beginning, at the current speed', 'topo-scan-cta--half', function() {
                    if (replayState.data) replayStart();
                });
            }
            scanAddCTA('/history', 'History', 'Every scan this tool has run \u2014 watch a domain change, or hold it against its own past');
            let recon = document.createElement('a');
            recon.className = 'topo-scan-recon';
            recon.href = '/analysis/' + analysisID + '/view/C';
            recon.textContent = '\u25b6 Recon Report \u00b7 Red Team \u00b7 Scotopic';
            recon.title = 'Covert Recon Report \u2014 red-team perspective in the scotopic-preserving covert interface';
            scanEls.links.appendChild(recon);
            // The rl05 caption anchors to the flagship card's MEASURED rect,
            // and that card did not exist when the last layout ran \u2014 without
            // this kick the caption freezes wherever the half-built console
            // happened to put it (observed: pointing at the owl row). Same
            // wrap-changed-without-resize class the observer below handles.
            requestAnimationFrame(relayout);
            fetch('/api/analysis/' + analysisID, { headers: { 'Accept': 'application/json' } }).then(function(resp) {
                return resp.ok ? resp.json() : null;
            }).then(function(data) {
                if (scanState.gen !== myGen) return;
                let fr = data && data.full_results;
                if (data && data.owl_semaphore) scanBuildOwls(data.owl_semaphore);
                if (fr) {
                    scanBuildChips(fr);
                } else {
                    scanEls.note.textContent = 'Verdict summary unavailable \u2014 open the full report for results.';
                    setHidden(scanEls.note, false);
                }
                // Owls + chips render ABOVE the report cards, so this fetch
                // moves the flagship card rl05 is anchored to \u2014 the first
                // kick (after the CTA block) measured a console still under
                // construction: observed 103px low. Re-anchor now that the
                // console has its final shape.
                requestAnimationFrame(relayout);
            }).catch(function() {
                if (scanState.gen !== myGen) return;
                scanEls.note.textContent = 'Verdict summary unavailable \u2014 open the full report for results.';
                setHidden(scanEls.note, false);
            });
        }

        function scanComplete(data) {
            scanStopPolling();
            for (let g in scanState.groups) {
                if (scanState.groups[g] && (scanState.groups[g].status === 'running' || scanState.groups[g].status === 'started')) {
                    scanState.groups[g].status = 'done';
                }
            }
            scanEls.status.textContent = 'Complete';
            scanEls.status.classList.add('is-complete');
            scanEls.cancel.textContent = 'Reset';
            scanEls.run.disabled = false;
            scanSetStamp(scanEls.target ? scanEls.target.textContent : '', scanEls.elapsed ? scanEls.elapsed.textContent : '');
            if (data.analysis_id) {
                scanLoadVerdicts(data.analysis_id, data.redirect_url);
            } else {
                setHidden(scanEls.verdict, false);
                // Non-persisted scans (e.g. the thisdoesnotexist negative
                // control) still owe the fixture disclosure in the verdict.
                scanShowNotice(scanEls.fixtureVerdict);
                scanEls.note.textContent = 'Scan complete \u2014 results were not persisted, so there is no stored report to link. /dev/null scans, unauthenticated custom-selector scans, and non-existent domains are analyzed without being written to the database.';
                setHidden(scanEls.note, false);
            }
        }

        function scanCheckFailures() {
            if (scanState.failures >= 4) {
                scanFail('Lost contact with the scan progress endpoint. The scan may still be running on the server.');
            }
        }

        function scanHandlePoll(data) {
            if (!scanState.active) return;
            if (!data) { scanCheckFailures(); return; }
            scanState.groups = data.phases || {};
            scanUpdateHud(data);
            tickerDiffLive(data);
            if (data.status === 'failed') {
                tickerFail(data.error || '');
                scanFail(data.error || 'Analysis failed. Please try again.');
                return;
            }
            if (data.status === 'complete') {
                scanComplete(data);
            }
        }

        function scanPollOnce() {
            let t0 = performance.now();
            fetch('/api/scan/progress/' + scanState.token).then(function(resp) {
                scanState.lastPollMs = performance.now() - t0;
                if (!resp.ok) { scanState.failures++; return null; }
                scanState.failures = 0;
                return resp.json();
            }).then(function(data) {
                scanHandlePoll(data);
            }).catch(function() {
                scanState.failures++;
                scanCheckFailures();
            });
        }

        function scanStart() {
            let domain = scanEls.domain.value.trim();
            if (!domain) { scanEls.domain.focus(); return; }
            scanReset();
            // Fold the advanced panel the moment a scan starts: its values
            // still ride the FormData below (hidden containers serialize),
            // and the console returns to its default height so the verdict
            // cards and report CTAs stay in the viewing area instead of
            // pushing the Engineer's Report below the fold.
            if (scanEls.adv && !scanEls.adv.hidden) {
                scanEls.adv.hidden = true;
                scanEls.advBtn.setAttribute('aria-expanded', 'false');
            }
            let myGen = scanState.gen;
            scanState.startedAt = Date.now();
            scanEls.target.textContent = domain;
            scanEls.elapsed.textContent = '0.0s';
            scanEls.phases.textContent = 'phases 0/9 \u00b7 tasks 0/0';
            setHidden(scanEls.hud, false);
            HUD_ACTIVE = true;
            let notice = scanNotices(domain);
            FIXTURE_SCAN = notice.fx;
            SCAN_NOTICE = notice.text;
            scanShowNotice(scanEls.fixtureHud);
            scanEls.run.disabled = true;
            let fd = new FormData(scanEls.form);
            fetch('/analyze', {
                method: 'POST',
                body: fd,
                headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
                redirect: 'follow'
            }).then(function(resp) {
                let ct = resp.headers.get('content-type') || '';
                let isJSON = ct.indexOf('application/json') !== -1;
                if (resp.status === 202 && isJSON) return resp.json();
                if (resp.status === 429 && isJSON) {
                    return resp.json().then(function(d) {
                        throw new Error(d && d.error ? d.error : 'Rate limited \u2014 please wait and try again.');
                    });
                }
                throw new Error('Scan did not start \u2014 the server declined the request (invalid domain, rate limit, or expired session). Reload the page if this persists.');
            }).then(function(data) {
                if (scanState.gen !== myGen) return;
                if (!data || !data.token) {
                    throw new Error('Scan did not start \u2014 no progress token returned.');
                }
                scanState.token = data.token;
                scanState.active = true;
                scanState.ringsOn = true;
                scanState.pollId = setInterval(scanPollOnce, 500);
            }).catch(function(err) {
                if (scanState.gen !== myGen) return;
                scanState.active = false;
                scanState.ringsOn = false;
                // The HUD hides on a failed start, so release its claims too \u2014
                // otherwise the output nodes stay hidden and a fixture-domain
                // pulse flashes forever with no scan running.
                HUD_ACTIVE = false;
                FIXTURE_SCAN = null;
                SCAN_NOTICE = '';
                setHidden(scanEls.fixtureHud, true);
                setHidden(scanEls.hud, true);
                scanEls.run.disabled = false;
                scanShowError(err && err.message ? err.message : 'Network error \u2014 please check your connection and try again.');
            });
        }

        if (!REPLAY && scanEls.form && scanEls.domain && scanEls.run && scanEls.hud) {
            scanEls.form.addEventListener('submit', function(e) {
                e.preventDefault();
                if (scanState.active) return;
                scanStart();
            });
            scanEls.advBtn.addEventListener('click', function() {
                let open = scanEls.adv.hidden;
                scanEls.adv.hidden = !open;
                scanEls.advBtn.setAttribute('aria-expanded', String(open));
            });
            scanEls.devnull.addEventListener('change', function() {
                if (scanEls.devnull.checked) scanEls.exposure.checked = true;
            });
            scanEls.cancel.addEventListener('click', function() { scanReset(); });
            document.addEventListener('keydown', function(e) {
                if (e.key !== 'Escape') return;
                if (!scanEls.adv.hidden && !scanState.active && !scanState.ringsOn) {
                    scanEls.adv.hidden = true;
                    scanEls.advBtn.setAttribute('aria-expanded', 'false');
                    return;
                }
                if (scanState.active || scanState.ringsOn || !scanEls.error.hidden) scanReset();
            });
        }

        /* ---- Scan replay ------------------------------------------------
           Replay mode (/replay/:id) drives the SAME scanState + HUD + ring
           pipeline as a live scan, but from the recorded phase telemetry
           served by /api/replay/:id. Every frame is synthesized purely from
           stored event offsets and durations — nothing is invented. */

        let replayState = { data: null, T: 0, speed: 8, timerId: 0, done: false };

        function replayFrame(events, T, totalMs) {
            let phases = {};
            for (let i = 0; i < events.length; i++) {
                let ev = events[i];
                if (!ev.group) continue;
                let ph = phases[ev.group];
                if (!ph) {
                    ph = { status: 'pending', tasks_total: 0, tasks_done: 0, _t0: Infinity, _t1: 0 };
                    phases[ev.group] = ph;
                }
                ph.tasks_total++;
                let evEnd = ev.t + (ev.dur || 0);
                if (ev.t < ph._t0) ph._t0 = ev.t;
                if (evEnd > ph._t1) ph._t1 = evEnd;
                if (evEnd <= T) ph.tasks_done++;
            }
            for (let g in phases) {
                let ph = phases[g];
                if (T >= ph._t1) {
                    ph.status = 'done';
                    ph.duration_ms = ph._t1 - ph._t0;
                } else if (T >= ph._t0) {
                    ph.status = 'running';
                }
            }
            return {
                phases: phases,
                elapsed_ms: Math.min(T, totalMs),
                status: T >= totalMs ? 'complete' : 'running'
            };
        }

        function replayApplyFrame() {
            let d = replayState.data;
            let fr = replayFrame(d.events, replayState.T, d.total_ms);
            scanState.groups = fr.phases;
            scanUpdateHud(fr);
            tickerReplayFrame(d.events, replayState.T);
            if (scanEls.latency) {
                scanEls.latency.textContent = 'replay ' + replayState.speed + '\u00d7 \u00b7 recorded ' + fmtScanDur(d.total_ms);
            }
            if (fr.status === 'complete' && !replayState.done) replayComplete();
        }

        function replayComplete() {
            replayState.done = true;
            if (replayState.timerId) { clearInterval(replayState.timerId); replayState.timerId = 0; }
            scanEls.status.textContent = 'Replay Complete';
            scanEls.status.classList.add('is-complete');
            let d = replayState.data;
            if (d.verdicts) {
                scanState.verdicts = {};
                // Replay statuses come from the same analyzer vocabulary, so
                // they need the same canonicalisation as a live scan.
                _absentThisScan = {};
                for (let k in d.verdicts) scanState.verdicts[k] = canonicalVerdict(k, d.verdicts[k]);
                // verdict_detail carries the producer's display derivation
                // (analysis_replay.go), so the ring construction holds even
                // when the follow-up analysis fetch fails or the row is
                // access-restricted for this viewer.
                scanState.verdictRings = {};
                let replaySpec = d.verdict_detail && d.verdict_detail.dnssec ?
                    dnssecRingSpec(d.verdict_detail.dnssec) : null;
                if (replaySpec) {
                    scanState.verdictRings.dnssec = replaySpec;
                    scanState.verdicts.dnssec = ringSpecCanon(replaySpec);
                }
                scanState.verdictAt = Date.now();
            }
            scanLoadVerdicts(d.analysis_id || REPLAY.id, null);
        }

        function replayStart() {
            if (replayState.timerId) { clearInterval(replayState.timerId); replayState.timerId = 0; }
            scanState.gen++;
            replayState.done = false;
            replayState.T = 0;
            scanState.verdicts = null;
            scanState.verdictAt = 0;
            scanState.verdictDetails = null;
            scanState.verdictRings = null;
            scanState.groups = {};
            scanState.ringsOn = true;
            if (scanEls.chips) scanEls.chips.textContent = '';
            if (scanEls.links) scanEls.links.textContent = '';
            tickerReset();
            owlsReset();
            setHidden(scanEls.verdict, true);
            setHidden(scanEls.note, true);
            setHidden(scanEls.error, true);
            scanEls.status.textContent = 'Replaying';
            scanEls.status.classList.remove('is-complete', 'is-failed');
            replayApplyFrame();
            replayState.timerId = setInterval(function() {
                replayState.T += 100 * replayState.speed;
                replayApplyFrame();
            }, 100);
        }

        // Arriving with ?domain= — prefill and run immediately. This is the
        // entry point the homepage form, the results-page Topology button and
        // history all land on: the scan starts on arrival rather than showing
        // an empty box whose placeholder reads like a wrong prefill.
        //
        // The autorun itself is gated SERVER-SIDE: the /topology handler
        // injects window.__TOPO_AUTORUN=true only for botverify-HumanVerified
        // page loads (completed classification, zero bot signal). JS-executing
        // crawlers (Ahrefs Site Audit, Chrome-Lighthouse) render this page
        // with ?domain= from history links — they get the prefill, never the
        // auto-start. Missing/undefined flag (stale cache, replay, error)
        // means NO autorun: fail closed.
        let AUTORUN_DOMAIN = null;
        if (!REPLAY && scanEls.form && scanEls.domain) {
            let raw = new URLSearchParams(location.search).get('domain') || '';
            // Permissive pre-clean ONLY, to decide whether this arrival should
            // autorun. A pasted URL is the commonest way anyone enters a
            // domain, and the strict test below would otherwise leave the page
            // idle with a prefilled box that looks like it failed.
            //
            // This is deliberately NOT the authority: the server re-extracts
            // with net/url and records what it scanned versus what was given
            // (results._input_normalization). Duplicating the parse here would
            // create a second answer that can disagree with the recorded one;
            // this only has to be good enough to recognise "that is a URL".
            let pre = raw.trim();
            if (pre.indexOf('://') !== -1) { pre = pre.slice(pre.indexOf('://') + 3); }
            if (pre.indexOf('@') !== -1) { pre = pre.slice(pre.lastIndexOf('@') + 1); }
            pre = pre.split(/[/?#]/)[0].replace(/:\d+$/, '');
            let d = pre.toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
            if (d && d.length <= 253 && /^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(d)) {
                // Send the RAW input, not the pre-cleaned form. The pre-clean
                // decided whether to autorun; it must not become the value the
                // server records, or the server sees already-clean input,
                // reports no normalization, and the pasted URL disappears from
                // the record — a silent substitution created by the very code
                // meant to disclose one. (Measured: a userinfo URL scanned the
                // right host and stored an EMPTY _input_normalization until
                // this line sent raw.)
                let rawTrimmed = raw.trim();
                AUTORUN_DOMAIN = rawTrimmed;
                scanEls.domain.value = rawTrimmed;
            }
        }

        // A restored panel is a record of a PREVIOUS scan, not the state of
        // this page. Say so, name the domain, timestamp it, and give the reader
        // one click to clear it — a bare /topology should not carry findings
        // the user did not ask for on this visit.
        function scanMarkRestored(domain, ageMs) {
            if (!scanEls.verdict) return;
            let mins = Math.round(ageMs / 60000);
            let when = mins < 1 ? 'moments ago'
                : mins < 60 ? mins + ' min ago'
                : Math.round(mins / 60) + ' h ago';
            let bar = document.createElement('div');
            bar.className = 'topo-scan-restored';
            bar.setAttribute('role', 'note');
            let txt = document.createElement('span');
            txt.textContent = 'Previous scan — ' + domain + ' · ' + when + '. Not a live result.';
            let clear = document.createElement('button');
            clear.type = 'button';
            clear.className = 'topo-scan-restored-clear';
            clear.textContent = 'Clear';
            clear.addEventListener('click', function() {
                try { sessionStorage.removeItem('topoLastScan'); } catch (e) { /* private mode */ }
                setHidden(scanEls.verdict, true);
                if (scanEls.links) scanEls.links.innerHTML = '';
                if (scanEls.target) scanEls.target.textContent = '';
                FIXTURE_SCAN = false;
                SCAN_NOTICE = '';
                if (scanEls.fixtureVerdict) setHidden(scanEls.fixtureVerdict, true);
                bar.remove();
            });
            bar.appendChild(txt);
            bar.appendChild(clear);
            scanEls.verdict.insertBefore(bar, scanEls.verdict.firstChild);
        }

        // Restore the last completed scan's verdict panel across refresh —
        // the report links shouldn't evaporate on reload (6 h window). Skipped
        // when a fresh scan is inbound, so stale results never sit under a
        // running scan.
        if (!REPLAY && !AUTORUN_DOMAIN && scanEls.verdict && scanEls.links) {
            try {
                let last = JSON.parse(sessionStorage.getItem('topoLastScan') || 'null');
                let age = Date.now() - (last && last.ts ? last.ts : 0);
                // A restored panel MUST name its subject. Without a domain the
                // page asserts findings about nothing — a fixture-corpus notice
                // sitting beside an empty input reads as a claim about whatever
                // the reader assumes, including the placeholder. If we cannot
                // say which domain a finding is about, we do not show it.
                if (last && last.id && last.domain && age < 6 * 3600 * 1000) {
                    let restoredNotice = scanNotices(last.domain);
                    FIXTURE_SCAN = restoredNotice.fx;
                    SCAN_NOTICE = restoredNotice.text;
                    if (scanEls.target) scanEls.target.textContent = last.domain;
                    scanLoadVerdicts(last.id, last.base || null, true);
                    scanMarkRestored(last.domain, age);
                } else if (last && (!last.domain || age >= 6 * 3600 * 1000)) {
                    // Unusable or expired: drop it rather than leave a record
                    // that can be half-restored on a later visit.
                    sessionStorage.removeItem('topoLastScan');
                }
            } catch (e) { /* restore is best-effort */ }
        }

        if (AUTORUN_DOMAIN && window.__TOPO_AUTORUN === true && scanEls.run && scanEls.hud) {
            scanStart();
        }

        if (REPLAY && scanEls.hud && scanEls.status && scanEls.cancel) {
            if (scanEls.form) scanEls.form.hidden = true;
            scanEls.target.textContent = REPLAY.domain || '';
            scanEls.elapsed.textContent = '0.0s';
            scanEls.status.textContent = 'Loading Replay';
            setHidden(scanEls.hud, false);
            HUD_ACTIVE = true;
            let replayNotice = scanNotices(REPLAY.domain);
            FIXTURE_SCAN = replayNotice.fx;
            SCAN_NOTICE = replayNotice.text;
            scanShowNotice(scanEls.fixtureHud);
            scanEls.cancel.textContent = 'Restart';
            scanEls.cancel.title = 'Restart the replay from the beginning.';
            scanEls.cancel.addEventListener('click', function() {
                if (replayState.data) replayStart();
            });
            let spdBtn = document.createElement('button');
            spdBtn.type = 'button';
            spdBtn.className = scanEls.cancel.className;
            spdBtn.textContent = '8\u00d7 speed';
            spdBtn.title = 'Toggle between true recorded speed (1\u00d7) and scaled speed (8\u00d7).';
            spdBtn.addEventListener('click', function() {
                replayState.speed = replayState.speed === 8 ? 1 : 8;
                spdBtn.textContent = replayState.speed + '\u00d7 speed';
                if (replayState.data && !replayState.done) replayApplyFrame();
            });
            scanEls.cancel.parentNode.insertBefore(spdBtn, scanEls.cancel);
            fetch('/api/replay/' + REPLAY.id, { headers: { 'Accept': 'application/json' } }).then(function(resp) {
                if (!resp.ok) return null;
                return resp.json();
            }).then(function(d) {
                if (!d || !d.events || !d.events.length || typeof d.total_ms !== 'number') {
                    throw new Error('Replay data unavailable \u2014 this analysis has no recorded scan timeline.');
                }
                replayState.data = d;
                replayStart();
            }).catch(function(err) {
                scanEls.status.textContent = 'Replay Unavailable';
                scanEls.status.classList.add('is-failed');
                scanShowError(err && err.message ? err.message : 'Replay data unavailable \u2014 this analysis has no recorded scan timeline.');
            });
        }

        let debugBounds = window.location.search.indexOf('debug=bounds') !== -1;
        let paused = false;

        function loop() {
            if (!paused) {
                update();
                draw();
            }
            requestAnimationFrame(loop);
        }

        document.addEventListener('visibilitychange', function() {
            paused = document.hidden;
        });

        resize();
        initAmbient();
        initFlowParticles();
        initSignalParticles();
        function relayout() {
            resize();
            initAmbient();
        }
        window.addEventListener('resize', relayout);
        // The wrap can change size without a window resize event (panel
        // toggles, scrollbar appearance, embedded panes). A layout computed
        // at a stale width strands mobile/tablet node targets on a grown
        // canvas — the protocol circles and their curved edges then sit on
        // top of the source column. Watch the wrap itself, not just the window.
        if (typeof ResizeObserver !== 'undefined') {
            let roRect = wrap.getBoundingClientRect();
            let roW = roRect.width, roH = roRect.height, roTimer = null;
            let ro = new ResizeObserver(function(entries) {
                let r = entries[entries.length - 1].contentRect;
                if (Math.abs(r.width - roW) < 1 && Math.abs(r.height - roH) < 1) return;
                roW = r.width; roH = r.height;
                if (roTimer) clearTimeout(roTimer);
                roTimer = setTimeout(relayout, 120);
            });
            ro.observe(wrap);
        }
        // Embedded panes and some hosts size the document AFTER script
        // eval, so the boot resize() can run against a zero-width wrap and
        // the layout collapses onto x=4. No window resize event follows and
        // a ResizeObserver whose baseline is taken after the late sizing
        // never fires either — the collapsed layout sticks (measured live:
        // W=0 with the wrap at its final size moments later). Poll until
        // the wrap's size and the laid-out size agree.
        (function healBootSize() {
            let tries = 0;
            function check() {
                let r = wrap.getBoundingClientRect();
                let mismatch = Math.abs(r.width - W) >= 1 || Math.abs(r.height - H) >= 1;
                if (mismatch && r.width > 0 && r.height > 0) relayout();
                else if (W > 0 && !mismatch) return;
                if (++tries < 300) requestAnimationFrame(check);
            }
            requestAnimationFrame(check);
        })();
        loop();
    })();
