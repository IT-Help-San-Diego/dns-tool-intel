(function() {
    'use strict';

    var DEG = Math.PI / 180;
    var GLOBE_RES = 360;
    var LIGHT_DIR = { x: 0.42, y: 0.28, z: 0.86 };

    var RESOLVER_POPS = [
        { resolver: 'Cloudflare', tag: 'CF', color: '#f6821f', lat: 37.77, lon: -122.42, city: 'San Francisco' },
        { resolver: 'Cloudflare', tag: 'CF', color: '#f6821f', lat: 51.51, lon: -0.13, city: 'London' },
        { resolver: 'Cloudflare', tag: 'CF', color: '#f6821f', lat: 35.68, lon: 139.69, city: 'Tokyo' },
        { resolver: 'Cloudflare', tag: 'CF', color: '#f6821f', lat: 1.35, lon: 103.82, city: 'Singapore' },
        { resolver: 'Cloudflare', tag: 'CF', color: '#f6821f', lat: -23.55, lon: -46.63, city: 'S\u00e3o Paulo' },
        { resolver: 'Google', tag: 'G', color: '#4285f4', lat: 41.26, lon: -95.86, city: 'Council Bluffs' },
        { resolver: 'Google', tag: 'G', color: '#4285f4', lat: 53.35, lon: -6.26, city: 'Dublin' },
        { resolver: 'Google', tag: 'G', color: '#4285f4', lat: -33.87, lon: 151.21, city: 'Sydney' },
        { resolver: 'Google', tag: 'G', color: '#4285f4', lat: 25.03, lon: 121.57, city: 'Taipei' },
        { resolver: 'Quad9', tag: 'Q9', color: '#0078d4', lat: 47.38, lon: 8.54, city: 'Zurich' },
        { resolver: 'Quad9', tag: 'Q9', color: '#0078d4', lat: 50.11, lon: 8.68, city: 'Frankfurt' },
        { resolver: 'Quad9', tag: 'Q9', color: '#0078d4', lat: 1.35, lon: 103.82, city: 'Singapore' },
        { resolver: 'OpenDNS', tag: 'OD', color: '#ff6a00', lat: 37.34, lon: -121.89, city: 'San Jose' },
        { resolver: 'OpenDNS', tag: 'OD', color: '#ff6a00', lat: 51.51, lon: -0.13, city: 'London' },
        { resolver: 'OpenDNS', tag: 'OD', color: '#ff6a00', lat: 22.32, lon: 114.17, city: 'Hong Kong' },
        { resolver: 'DNS4EU', tag: 'EU', color: '#003399', lat: 50.85, lon: 4.35, city: 'Brussels' },
        { resolver: 'DNS4EU', tag: 'EU', color: '#003399', lat: 48.86, lon: 2.35, city: 'Paris' },
        { resolver: 'DNS4EU', tag: 'EU', color: '#003399', lat: 52.52, lon: 13.41, city: 'Berlin' }
    ];

    var OWN_PROBES = [
        { id: 'probe-01', label: 'Probe 01 \u2014 US-East', color: '#4ade80', lat: 42.36, lon: -71.06, city: 'Boston' },
        { id: 'probe-02', label: 'Probe 02 \u2014 France', color: '#4ade80', lat: 48.57, lon: 2.82, city: 'France' }
    ];

    function hexToRgba(hex, a) {
        var r = parseInt(hex.slice(1, 3), 16);
        var g = parseInt(hex.slice(3, 5), 16);
        var b = parseInt(hex.slice(5, 7), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
    }

    function roundRect(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.lineTo(x + w - r, y);
        ctx.quadraticCurveTo(x + w, y, x + w, y + r);
        ctx.lineTo(x + w, y + h - r);
        ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
        ctx.lineTo(x + r, y + h);
        ctx.quadraticCurveTo(x, y + h, x, y + h - r);
        ctx.lineTo(x, y + r);
        ctx.quadraticCurveTo(x, y, x + r, y);
        ctx.closePath();
    }

    function createGlobeState() {
        return {
            cx: 0, cy: 0, R: 0, rotLon: -58,
            _earthTexData: null,
            _earthTexW: 0,
            _earthTexH: 0,
            _texLoaded: false,
            _offGlobe: null,
            _offGlobeCtx: null,
            _cachedRotLon: null,
            _cachedR: null
        };
    }

    function loadTexture(gs) {
        var img = new Image();
        img.onload = function() {
            var tc = document.createElement('canvas');
            tc.width = img.naturalWidth;
            tc.height = img.naturalHeight;
            var tctx = tc.getContext('2d');
            tctx.drawImage(img, 0, 0);
            gs._earthTexData = tctx.getImageData(0, 0, tc.width, tc.height);
            gs._earthTexW = tc.width;
            gs._earthTexH = tc.height;
            gs._texLoaded = true;
        };
        img.src = '/static/img/earth-blue-marble.jpg';
    }

    function projectPt(gs, lat, lon) {
        var phi = lat * DEG;
        var lam = (lon - gs.rotLon) * DEG;
        var cosPhi = Math.cos(phi);
        return {
            x: gs.cx + gs.R * cosPhi * Math.sin(lam),
            y: gs.cy - gs.R * Math.sin(phi),
            vis: cosPhi * Math.cos(lam) > 0,
            depth: cosPhi * Math.cos(lam)
        };
    }

    function renderTexturedGlobe(gs) { // NOSONAR
        if (!gs._texLoaded) return null;
        var snapR = Math.round(gs.R);
        var snapLon = Math.round(gs.rotLon * 2) / 2;
        if (gs._cachedRotLon === snapLon && gs._cachedR === snapR && gs._offGlobe) return gs._offGlobe;
        gs._cachedRotLon = snapLon;
        gs._cachedR = snapR;
        var sz = GLOBE_RES;
        if (!gs._offGlobe) {
            gs._offGlobe = document.createElement('canvas');
            gs._offGlobe.width = sz;
            gs._offGlobe.height = sz;
            gs._offGlobeCtx = gs._offGlobe.getContext('2d');
        }
        var octx = gs._offGlobeCtx;
        var id = octx.createImageData(sz, sz);
        var px = id.data;
        var half = sz / 2;
        var invHalf = 1.0 / half;
        var td = gs._earthTexData.data;
        var tw = gs._earthTexW;
        var th = gs._earthTexH;
        var rotRad = snapLon * DEG;
        var PI = Math.PI;
        var TWO_PI = PI * 2;
        var lx = LIGHT_DIR.x, ly = LIGHT_DIR.y, lz = LIGHT_DIR.z;

        for (var py = 0; py < sz; py++) {
            var ny = (half - py) * invHalf;
            var ny2 = ny * ny;
            if (ny2 > 1) continue;
            for (var pxx = 0; pxx < sz; pxx++) {
                var nx = (pxx - half) * invHalf;
                var r2 = nx * nx + ny2;
                if (r2 > 1) continue;
                var nz = Math.sqrt(1 - r2);

                var lat = Math.asin(ny);
                var lon = Math.atan2(nx, nz) - rotRad;
                lon = lon - TWO_PI * Math.floor((lon + PI) / TWO_PI);

                var u = (lon + PI) / TWO_PI;
                var v = (PI / 2 - lat) / PI;
                var tx = Math.min(tw - 1, Math.max(0, (u * tw) | 0));
                var ty = Math.min(th - 1, Math.max(0, (v * th) | 0));
                var ti = (ty * tw + tx) * 4;

                var tr = td[ti], tg = td[ti + 1], tb = td[ti + 2];

                var diffuse = Math.max(0, nx * lx + ny * ly + nz * lz);
                var ambient = 0.08;
                var lit = ambient + diffuse * 0.92;

                var fresnel = 1.0 - nz;
                var fr4 = fresnel * fresnel * fresnel * fresnel;
                var rimR = 60, rimG = 120, rimB = 220;
                var rimStr = fr4 * 0.45;

                var idx = (py * sz + pxx) * 4;
                px[idx] = Math.min(255, (tr * lit + rimR * rimStr) | 0);
                px[idx + 1] = Math.min(255, (tg * lit + rimG * rimStr) | 0);
                px[idx + 2] = Math.min(255, (tb * lit + rimB * rimStr) | 0);
                px[idx + 3] = 255;
            }
        }
        octx.putImageData(id, 0, 0);
        return gs._offGlobe;
    }

    function drawGlobeSphere(ctx, gs) {
        var R = gs.R;
        var cx = gs.cx;
        var cy = gs.cy;

        var grd = ctx.createRadialGradient(cx, cy, R * 0.95, cx, cy, R * 1.55);
        grd.addColorStop(0, 'rgba(60,130,240,0.18)');
        grd.addColorStop(0.3, 'rgba(40,100,200,0.10)');
        grd.addColorStop(0.65, 'rgba(20,60,160,0.04)');
        grd.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(cx, cy, R * 1.55, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        var texCanvas = renderTexturedGlobe(gs);
        if (texCanvas) {
            ctx.save();
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, Math.PI * 2);
            ctx.clip();
            ctx.drawImage(texCanvas, cx - R, cy - R, R * 2, R * 2);
            ctx.restore();
        } else {
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(8,15,35,0.95)';
            ctx.fill();
        }

        var edgeGrd = ctx.createRadialGradient(cx, cy, R * 0.7, cx, cy, R);
        edgeGrd.addColorStop(0, 'rgba(0,0,0,0)');
        edgeGrd.addColorStop(0.6, 'rgba(0,0,0,0)');
        edgeGrd.addColorStop(0.85, 'rgba(30,80,180,0.06)');
        edgeGrd.addColorStop(1, 'rgba(60,140,255,0.15)');
        ctx.beginPath();
        ctx.arc(cx, cy, R, 0, Math.PI * 2);
        ctx.fillStyle = edgeGrd;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(cx, cy, R, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(80,150,255,0.18)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
    }

    function initSignalParticles(pops) {
        var particles = [];
        for (var i = 0; i < pops.length; i++) {
            for (var j = 0; j < 3; j++) {
                particles.push({
                    popIdx: i,
                    t: Math.random(),
                    speed: 0.003 + Math.random() * 0.004,
                    size: 1.5 + Math.random() * 1.5
                });
            }
        }
        return particles;
    }

    function placeLabel(opts) { // NOSONAR
        var dotX = opts.dotX;
        var dotY = opts.dotY;
        var tagW = opts.tagW;
        var tagH = opts.tagH;
        var globeCx = opts.globeCx;
        var globeCy = opts.globeCy;
        var globeR = opts.globeR;
        var placedBoxes = opts.placedBoxes;
        var labelGap = opts.labelGap;
        var labelBand = opts.labelBand;
        var candidateAngles = opts.candidateAngles || [0, 15, -15, 30, -30, 45, -45, 60, -60, 75, -75, 90, -90, 105, -105, 120, -120, 135, -135, 150, -150, 165, -165, 180];
        var candidateDists = opts.candidateDists || [globeR * 0.15 + labelGap, globeR * 0.25 + labelGap, globeR * 0.35 + labelGap];

        var maxLabelRight = globeCx + globeR + labelBand + labelGap;
        var maxLabelLeft = globeCx - globeR - labelBand - labelGap;
        var maxLabelTop = globeCy - globeR - labelBand;
        var maxLabelBottom = globeCy + globeR + labelBand;

        var baseAngle = Math.atan2(dotY - globeCy, dotX - globeCx);
        var bestX = null, bestY = null, bestScore = Infinity;

        for (var di = 0; di < candidateDists.length; di++) {
            for (var ci = 0; ci < candidateAngles.length; ci++) {
                var ca = baseAngle + candidateAngles[ci] * DEG;
                var dist = candidateDists[di];
                var cx = dotX + Math.cos(ca) * dist;
                var cy = dotY + Math.sin(ca) * dist;

                if (Math.cos(ca) < 0) cx -= tagW;

                cx = Math.max(Math.max(4, maxLabelLeft), Math.min(cx, maxLabelRight - tagW));
                cy = Math.max(Math.max(4, maxLabelTop), Math.min(cy, maxLabelBottom - tagH));

                var hasCollision = false;
                for (var pi = 0; pi < placedBoxes.length; pi++) {
                    var pb = placedBoxes[pi];
                    if (cx < pb.x + pb.w + 3 && cx + tagW > pb.x - 3 &&
                        cy < pb.y + pb.h + 3 && cy + tagH > pb.y - 3) {
                        hasCollision = true;
                        break;
                    }
                }

                var distFromDot = Math.sqrt((cx + tagW / 2 - dotX) * (cx + tagW / 2 - dotX) + (cy + tagH / 2 - dotY) * (cy + tagH / 2 - dotY));
                var score = (hasCollision ? 10000 : 0) + distFromDot;

                if (score < bestScore) {
                    bestScore = score;
                    bestX = cx;
                    bestY = cy;
                }
            }
        }

        if (bestScore >= 10000) {
            for (var ri = 0; ri < 8; ri++) {
                var shifted = false;
                for (var bi = 0; bi < placedBoxes.length; bi++) {
                    var pb2 = placedBoxes[bi];
                    var ovX = Math.min(bestX + tagW, pb2.x + pb2.w) - Math.max(bestX, pb2.x);
                    var ovY = Math.min(bestY + tagH, pb2.y + pb2.h) - Math.max(bestY, pb2.y);
                    if (ovX > 0 && ovY > 0) {
                        if (ovY < ovX) {
                            bestY += (bestY < pb2.y ? -(ovY + 4) : (ovY + 4));
                        } else {
                            bestX += (bestX < pb2.x ? -(ovX + 4) : (ovX + 4));
                        }
                        shifted = true;
                    }
                }
                if (!shifted) break;
            }
            bestX = Math.max(4, Math.min(bestX, maxLabelRight - tagW));
            bestY = Math.max(4, Math.min(bestY, maxLabelBottom - tagH));
        }

        return { x: bestX, y: bestY, score: bestScore };
    }

    globalThis.GlobeCore = {
        DEG: DEG,
        RESOLVER_POPS: RESOLVER_POPS,
        OWN_PROBES: OWN_PROBES,
        hexToRgba: hexToRgba,
        roundRect: roundRect,
        createGlobeState: createGlobeState,
        loadTexture: loadTexture,
        projectPt: projectPt,
        renderTexturedGlobe: renderTexturedGlobe,
        drawGlobeSphere: drawGlobeSphere,
        initSignalParticles: initSignalParticles,
        placeLabel: placeLabel
    };
})();
