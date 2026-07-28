            if (e.label && (isHL || e.type !== 'flow')) {
                let t = e.labelT || 0.5;
                let lx, ly;
                if (curve) {
                    lx = (1 - t) * (1 - t) * from.x + 2 * (1 - t) * t * curve.cx + t * t * to.x;
                    ly = (1 - t) * (1 - t) * from.y + 2 * (1 - t) * t * curve.cy + t * t * to.y;
                } else {
                    lx = from.x + (to.x - from.x) * t;
                    ly = from.y + (to.y - from.y) * t;
                }
                ly -= 8 * SCL;

                for (let nri = 0; nri < allLayoutNodes.length; nri++) {
                    let nn = allLayoutNodes[nri];
                    let nhw = (nn._halfW || nn._boxW / 2 || nn.radius) + 12;
                    let nhh = (nn._halfH || nn._boxH / 2 || nn.radius) + 12;
                    if (nn.shape === 'circle') {
                        let ldx = lx - nn.x;
                        let ldy = ly - nn.y;
                        let ldist = Math.sqrt(ldx * ldx + ldy * ldy);
                        if (ldist < nn.radius + 24 && ldist > 0.1) {
                            let lnorm = (nn.radius + 28) / ldist;
                            lx = nn.x + ldx * lnorm;
                            ly = nn.y + ldy * lnorm;
                        }
                    } else {
                        let ndx = lx - nn.x;
                        let ndy = ly - nn.y;
                        if (Math.abs(ndx) < nhw && Math.abs(ndy) < nhh) {
                            if (Math.abs(ndx) / nhw > Math.abs(ndy) / nhh) {
                                lx = nn.x + (ndx >= 0 ? 1 : -1) * (nhw + 6);
                            } else {
                                ly = nn.y + (ndy >= 0 ? 1 : -1) * (nhh + 6);
                            }
                        }
                    }
                }

                let edgeFontSize = Math.max(8, FONT_SUB - 1);
                ctx.font = edgeFontSize + 'px -apple-system, BlinkMacSystemFont, sans-serif';
                let tw = ctx.measureText(e.label).width;
                let pw = tw + 10 * SCL;
                let ph = edgeFontSize + 8 * SCL;

                for (let llPass = 0; llPass < 3; llPass++) {
                    let llMoved = false;
                    for (let pli = 0; pli < placedEdgeLabels.length; pli++) {
                        let pl = placedEdgeLabels[pli];
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
                    if (!llMoved) break;
                }

                ly = Math.max(20, Math.min(H - 20, ly));
                lx = Math.max(30, Math.min(W - 30, lx));
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
                placedEdgeLabels.push({ x: lx, y: ly, w: pw, h: ph });
            }
