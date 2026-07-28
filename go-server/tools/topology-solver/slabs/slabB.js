        function effRadius(n) {
            let hw = (n._drawW || n.radius * 2.2) / 2;
            let hh = (n._drawH || n.radius * 1.4) / 2;
            return Math.max(hw, hh, n.radius) + 6;
        }

        function computeScaling() {
            SCL = Math.max(0.65, Math.min(1.15, W / 1400));
            FONT_LABEL = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
            FONT_SUB = Math.round(Math.max(8, Math.min(12, 10 * SCL)));
            FONT_TAG = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
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
                h = radius * 1.5 + 16 + subExtra;
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

        function measureNodeBox(n) {
            let box = computeNodeBox(n.shape, n.radius, n.label, n.sub || null, SCL, FONT_LABEL, FONT_SUB, canvasMeasureText);
            n._boxW = box.w;
            n._boxH = box.h;
            n._halfW = box.halfW;
            n._halfH = box.halfH;
            return { w: box.w, h: box.h };
        }
