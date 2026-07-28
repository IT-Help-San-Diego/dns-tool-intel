        function layoutAll() {
            computeScaling();

            let titleSafe = Math.max(H * 0.07, 42);
            let legendSafe = H * 0.95;
            let usableH = legendSafe - titleSafe;

            let globeR = Math.min(W * 0.13 * SCL, H * 0.25 * SCL, 180);
            globe.R = globeR;
            globe.cx = W * 0.04 + globeR;
            globe.cy = titleSafe + usableH * 0.42;

            let pipeStart = globe.cx + globeR + W * 0.02;
            // The scan console is a fixed 360px card pinned top-right. Treat it
            // as occupied space rather than letting the graph run underneath
            // it — that is what put the console on top of DANE and TLS-RPT.
            // Below 1000px the console goes near-full-width and overlaying is
            // unavoidable, so reserve nothing and let it sit above.
            let consoleReserve = W >= 1000 ? 386 : 0;
            let pipeEnd = W * 0.99 - consoleReserve;
            let pipeTotal = pipeEnd - pipeStart;
            let colGap = Math.max(4, pipeTotal * 0.01);
            // Size the source and confidence columns to what they ACTUALLY
            // contain rather than to fixed fractions. The source tags carry two
            // lines of sub-text and measured ~170px against a 13% column of
            // ~100px, so they overflowed their zone and collided with the
            // confidence diamonds no matter how the clamping was tuned.
            SOURCES.forEach(measureNodeBox);
            measureNodeBox(HUB);
            CONFIDENCE.forEach(measureNodeBox);
            let srcNeed = Math.max.apply(null, SOURCES.map(function(n) { return n._boxW; }).concat([HUB._boxW])) + 26;
            let confNeed = Math.max.apply(null, CONFIDENCE.map(function(n) { return n._boxW; })) + 26;

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

            let storeY = titleSafe + usableH * 0.78;
            let storeSpread = Math.max(confSpread * 0.8, 60);
            STORAGE[0].targetX = procCx;
            STORAGE[0].targetY = storeY;
            STORAGE[1].targetX = procCx - storeSpread;
            STORAGE[1].targetY = storeY + usableH * 0.10;
            STORAGE[2].targetX = procCx + storeSpread;
            STORAGE[2].targetY = storeY + usableH * 0.10;

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
                    bounds: { x1: col2L, x2: col2R, y1: titleSafe + usableH * 0.25, y2: titleSafe + usableH * 0.75 }
                },
                'storage': {
                    gx: procCx, gy: storeY,
                    gravity: 0.35,
                    bounds: { x1: col2L - c2w * 0.3, x2: col2R + c2w * 0.3, y1: titleSafe + usableH * 0.68, y2: legendSafe }
                },
                'protocol': {
                    gx: protoCx, gy: protoCy,
                    gravity: 0.18,
                    bounds: { x1: col3L, x2: col3R, y1: titleSafe, y2: titleSafe + usableH * 0.88 }
                },
                'output': {
                    gx: outCx, gy: titleSafe + usableH * 0.5,
                    gravity: 0.35,
                    bounds: { x1: col4L, x2: col4R, y1: titleSafe, y2: legendSafe }
                }
            };

            allLayoutNodes = SOURCES.concat([HUB, ENGINE], CONFIDENCE, STORAGE, PROTOCOLS, OUTPUTS);
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
                    if (!needs) return; // cannot fit even at pad 0 — keep bands
                    let leftover = (bottom - top) - needs.reduce(function(s, v) { return s + v; }, 0) - usedPad * (stack.length - 1);
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

            if (solverData) {
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
                let usableW = W - consoleReserve;
                allLayoutNodes.forEach(function(nd) {
                    let pos = solverData[nd.id];
                    if (pos) {
                        nd.targetX = (pos.x / ref.w) * usableW;
                        nd.targetY = titleSafe + (pos.y / ref.h) * (legendSafe - titleSafe);
                        let z = zones[nd.zone || nd.id];
                        if (z && z.bounds) {
                            let zw = z.bounds.x2 - z.bounds.x1;
                            let zh = z.bounds.y2 - z.bounds.y1;
                            let zpx = Math.min(30, zw * 0.15);
                            let zpy = Math.min(20, zh * 0.15);
                            if (z.bounds.x1 + zpx < z.bounds.x2 - zpx) {
                                nd.targetX = Math.max(z.bounds.x1 + zpx, Math.min(z.bounds.x2 - zpx, nd.targetX));
                            }
                            if (z.bounds.y1 + zpy < z.bounds.y2 - zpy) {
                                nd.targetY = Math.max(z.bounds.y1 + zpy, Math.min(z.bounds.y2 - zpy, nd.targetY));
                            }
                        }
                        nd.targetX = Math.max(globalBounds.x1 + 10, Math.min(globalBounds.x2 - 10, nd.targetX));
                        nd.targetY = Math.max(globalBounds.y1 + 10, Math.min(globalBounds.y2 - 10, nd.targetY));
                    }
                });
                // The solver's protocol ellipse was authored for a canvas with
                // four live columns. Rescale it to actually FILL the protocol
                // zone, so the nine circles spread out and their relationship
                // edges are legible instead of overlapping in a column.
                let pxs = PROTOCOLS.map(function(p) { return p.targetX; });
                let pys = PROTOCOLS.map(function(p) { return p.targetY; });
                let minPX = Math.min.apply(null, pxs), maxPX = Math.max.apply(null, pxs);
                let minPY = Math.min.apply(null, pys), maxPY = Math.max.apply(null, pys);
                let pz = zones.protocol.bounds;
                let padX = 52 * SCL, padY = 44 * SCL;
                let tx1 = pz.x1 + padX, tx2 = pz.x2 - padX;
                let ty1 = pz.y1 + padY, ty2 = pz.y2 - padY;
                if (maxPX - minPX > 1 && tx2 - tx1 > 40) {
                    PROTOCOLS.forEach(function(p) {
                        p.targetX = tx1 + ((p.targetX - minPX) / (maxPX - minPX)) * (tx2 - tx1);
                    });
                }
                if (maxPY - minPY > 1 && ty2 - ty1 > 40) {
                    PROTOCOLS.forEach(function(p) {
                        p.targetY = ty1 + ((p.targetY - minPY) / (maxPY - minPY)) * (ty2 - ty1);
                    });
                }
            } else {
                SOLVER_ACTIVE = false;
                console.log('Topology: using FR fallback');
                forceDirectedLayout(allLayoutNodes, allLayoutEdges, zones, globalBounds, 120);
            }

            let overlapPad = 14;
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
                            let overX = ohw - odx;
                            let overY = ohh - ody;
                            let pushStr = 0.7;
                            if (overX < overY) {
                                let sx = (nb.targetX >= na.targetX ? 1 : -1) * overX * pushStr;
                                na.targetX -= sx;
                                nb.targetX += sx;
                            } else {
                                let sy = (nb.targetY >= na.targetY ? 1 : -1) * overY * pushStr;
                                na.targetY -= sy;
                                nb.targetY += sy;
                            }
                            anyOverlap = true;
                        }
                    }
                }
                if (!anyOverlap) break;
                allLayoutNodes.forEach(function(nd) {
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

            // ?debug=bounds introspection: expose the exact layout the solver
            // produced so rendering bugs can be measured instead of eyeballed.
            if (typeof debugBounds !== 'undefined' && debugBounds) {
                try {
                    window.__topoDbg = {
                        W: W, H: H, scl: SCL, solver: SOLVER_ACTIVE,
                        zones: (function() {
                            let z = {};
                            for (let k in zones) { z[k] = zones[k].bounds; }
                            return z;
                        })(),
                        boxes: allLayoutNodes.map(function(n) {
                            return { id: n.id, zone: n.zone, hw: n._halfW || n.radius, hh: n._halfH || n.radius };
                        }),
                        globe: { cx: globe.cx, cy: globe.cy, R: globe.R },
                        nodes: allLayoutNodes.map(function(n) {
                            return { id: n.id, zone: n.zone, x: Math.round(n.x), y: Math.round(n.y),
                                     tx: Math.round(n.targetX), ty: Math.round(n.targetY) };
                        })
                    };
                } catch (e) { /* diagnostics only */ }
            }
        }
