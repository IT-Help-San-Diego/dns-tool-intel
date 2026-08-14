// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package badgepkg

import (
        "strings"
        "fmt"
        "math"
        "time"
)

func PluralS(n int) string {
        if n == 1 {
                return ""
        }
        return "s"
}

type ProtocolNode struct {
        Abbrev     string
        Status     string
        ColorHex   string
        X, Y       int
        GroupColor string
}

func ProtocolGroupColor(abbrev string) string {
        switch abbrev {
        case "SPF", "DKIM", protoDMARC:
                return "#4fc3f7"
        case protoDNSSEC, "CAA":
                return "#ffb74d"
        case "DANE", protoMTASTS, protoTLSRPT:
                return "#81c784"
        case "BIMI":
                return "#ce93d8"
        case "Web3":
                return "#d4a853"
        default:
                return "#484f58"
        }
}

func ProtocolStatusToNodeColor(status, groupColor string) string {
        switch status {
        case "success":
                return groupColor
        case "warning":
                return hexYellow
        case "error":
                return hexRed
        case "info":
                return groupColor
        default:
                return hexDimGrey
        }
}

func ExtractProtocolIndicators(results map[string]any) []ProtocolNode {
        protocols := []struct {
                key    string
                abbrev string
        }{
                {"spf_analysis", "SPF"},
                {"dkim_analysis", "DKIM"},
                {"dmarc_analysis", protoDMARC},
                {"dnssec_analysis", protoDNSSEC},
                {"dane_analysis", "DANE"},
                {"mta_sts_analysis", protoMTASTS},
                {"tlsrpt_analysis", protoTLSRPT},
                {"bimi_analysis", "BIMI"},
                {"caa_analysis", "CAA"},
        }

        protocols = append(protocols, struct {
                key    string
                abbrev string
        }{"web3_analysis", "Web3"})

        web3St := ExtractWeb3Status(results)

        nodes := make([]ProtocolNode, 0, len(protocols))
        for _, p := range protocols {
                status := "missing"
                if p.key == "web3_analysis" {
                        if web3St == "success" {
                                status = "success"
                        } else {
                                status = "info"
                        }
                } else if analysisRaw, ok := results[p.key]; ok {
                        if analysis, ok := analysisRaw.(map[string]any); ok {
                                if s, ok := analysis["status"].(string); ok {
                                        status = s
                                }
                        }
                }
                gc := ProtocolGroupColor(p.abbrev)
                nc := ProtocolStatusToNodeColor(status, gc)
                nodes = append(nodes, ProtocolNode{
                        Abbrev:     p.abbrev,
                        Status:     status,
                        ColorHex:   nc,
                        GroupColor: gc,
                })
        }
        return nodes
}

type ExposureFinding struct {
        FindingType string
        Severity    string
        Redacted    string
}

type ExposureData struct {
        Status       string
        FindingCount int
        Findings     []ExposureFinding
}

func ExtractExposure(results map[string]any) ExposureData {
        secRaw, ok := results["secret_exposure"]
        if !ok {
                return ExposureData{Status: "clear"}
        }
        sec, ok := secRaw.(map[string]any)
        if !ok {
                return ExposureData{Status: "clear"}
        }
        status, _ := sec["status"].(string)
        if status == "" {
                status = "clear"
        }
        count := 0
        if c, ok := sec["finding_count"].(float64); ok {
                count = int(c)
        }
        var findings []ExposureFinding
        if fRaw, ok := sec["findings"].([]any); ok {
                for _, item := range fRaw {
                        f, ok := item.(map[string]any)
                        if !ok {
                                continue
                        }
                        ft, _ := f["type"].(string)
                        sev, _ := f["severity"].(string)
                        red, _ := f["redacted"].(string)
                        findings = append(findings, ExposureFinding{
                                FindingType: ft,
                                Severity:    sev,
                                Redacted:    red,
                        })
                }
        }
        return ExposureData{
                Status:       status,
                FindingCount: count,
                Findings:     findings,
        }
}

func ExtractPostureScore(results map[string]any) int {
        postureRaw, ok := results["posture"]
        if !ok {
                return -1
        }
        posture, ok := postureRaw.(map[string]any)
        if !ok {
                return -1
        }
        if s, ok := posture["score"].(float64); ok {
                v := int(s)
                if v < 0 {
                        v = 0
                }
                if v > 100 {
                        v = 100
                }
                return v
        }
        return -1
}

// ExtractUnmeasurableCount reports how many controls the posture score could
// not measure. The score's denominator excludes unmeasurable controls (an
// unmeasurable protocol can neither inflate nor depress the score), so a high
// score over a partial measurement must not read as a clean bill of health:
// the badge surfaces the count so an embedded badge stays honest
// (e.g. "Low Risk (90/100) · 3 unmeasured").
func ExtractUnmeasurableCount(results map[string]any) int {
        postureRaw, ok := results["posture"]
        if !ok {
                return 0
        }
        posture, ok := postureRaw.(map[string]any)
        if !ok {
                return 0
        }
        switch u := posture["unmeasurable"].(type) {
        case []string:
                return len(u)
        case []any:
                return len(u)
        }
        return 0
}

func ScoreColor(score int) string {
        if score >= 80 {
                return hexGreen
        }
        if score >= 50 {
                return hexYellow
        }
        if score >= 0 {
                return hexRed
        }
        return "#484f58"
}

func BuildPostureContext(nodes []ProtocolNode, missing, controlCount int) string {
        if missing <= 0 {
                return fmt.Sprintf("All %d controls verified", controlCount)
        }
        first := FirstMissingProtocol(nodes)
        if first != "" {
                return fmt.Sprintf("%d/%d controls missing — %s not found", missing, controlCount, first)
        }
        return fmt.Sprintf("%d/%d controls missing", missing, controlCount)
}

func FirstMissingProtocol(nodes []ProtocolNode) string {
        for _, n := range nodes {
                if n.Status == "missing" || n.Status == "error" {
                        return n.Abbrev
                }
        }
        return ""
}

type NodePos struct {
        X, Y int
}

type TopoEdge struct {
        From, To int
        Label    string
        Hard     bool
        LabelX   int
        LabelY   int
}

func RenderTopoEdges(svg *strings.Builder, edges []TopoEdge, nodes []ProtocolNode, positions []NodePos, nodeR int) {
        for _, e := range edges {
                if e.From >= len(nodes) || e.To >= len(nodes) {
                        continue
                }
                fp := positions[e.From]
                tp := positions[e.To]
                dn := nodes[e.To]

                lineColor, lineOpacity, lineW, packetColor := TopoEdgeColors(dn)

                pathD := fmt.Sprintf("M%d,%d L%d,%d", fp.X, fp.Y, tp.X, tp.Y)
                dashArray := "4 6"
                if e.Hard {
                        dashArray = "none"
                }
                svg.WriteString(fmt.Sprintf(
                        `<path d="%s" fill="none" stroke="%s" stroke-opacity="%s" stroke-width="%.1f" stroke-dasharray="%s"/>`,
                        pathD, lineColor, lineOpacity, lineW, dashArray,
                ))

                RenderArrowHead(svg, fp, tp, nodeR, lineColor, lineOpacity)

                if e.Label != "" && e.LabelX > 0 {
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" text-anchor="middle" fill="#c9d1d9" font-size="7.5" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                                e.LabelX, e.LabelY, e.Label,
                        ))
                }

                if dn.Status == "success" || dn.Status == "warning" {
                        dur := fmt.Sprintf("%.1fs", 1.8+float64(e.From)*0.3)
                        svg.WriteString(fmt.Sprintf(
                                `<circle r="2.5" fill="%s" opacity="0.85"><animateMotion dur="%s" repeatCount="indefinite" path="%s"/></circle>`,
                                packetColor, dur, pathD,
                        ))
                }
        }
}

func TopoEdgeColors(dn ProtocolNode) (lineColor, lineOpacity string, lineW float64, packetColor string) {
        groupColor := ProtocolGroupColor(dn.Abbrev)
        switch dn.Status {
        case "success", "warning":
                return dn.ColorHex, "0.40", 1.8, dn.ColorHex
        case "error":
                return hexRed, "0.35", 1.8, hexRed
        default:
                return groupColor, "0.18", 1.5, groupColor
        }
}

func RenderArrowHead(svg *strings.Builder, fp, tp NodePos, nodeR int, lineColor, lineOpacity string) {
        arrowDx := float64(tp.X - fp.X)
        arrowDy := float64(tp.Y - fp.Y)
        dist := math.Sqrt(arrowDx*arrowDx + arrowDy*arrowDy)
        if dist == 0 {
                return
        }
        nx := arrowDx / dist
        ny := arrowDy / dist
        arrowR := float64(nodeR) + 3
        arrowTipX := float64(tp.X) - nx*arrowR
        arrowTipY := float64(tp.Y) - ny*arrowR
        perpX := -ny * 3.5
        perpY := nx * 3.5
        svg.WriteString(fmt.Sprintf(
                `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s" fill-opacity="%s"/>`,
                arrowTipX, arrowTipY,
                arrowTipX-nx*7+perpX, arrowTipY-ny*7+perpY,
                arrowTipX-nx*7-perpX, arrowTipY-ny*7-perpY,
                lineColor, lineOpacity,
        ))
}

type TopoNodeStyle struct {
        NodeColor     string
        StrokeColor   string
        FillOpacity   string
        StrokeOpacity string
        StrokeW       float64
        GlowOpacity   string
        TextColor     string
}

func TopoNodeStyleFor(n ProtocolNode) TopoNodeStyle {
        s := TopoNodeStyle{
                NodeColor:     n.GroupColor,
                StrokeColor:   n.GroupColor,
                FillOpacity:   "0.10",
                StrokeOpacity: "0.45",
                StrokeW:       1.5,
                GlowOpacity:   "0.10",
                TextColor:     "#e6edf3",
        }
        switch n.Status {
        case "error", "missing":
                s.NodeColor = hexRed
                s.StrokeColor = hexRed
                s.FillOpacity = "0.06"
                s.StrokeOpacity = "0.25"
                s.StrokeW = 1
                s.GlowOpacity = "0.06"
                s.TextColor = hexRed
        case "warning", "success":
                s.FillOpacity = "0.14"
                s.StrokeOpacity = "0.55"
                s.GlowOpacity = "0.12"
        }
        return s
}

func AbbrevFontSize(abbrev string) int {
        switch {
        case len(abbrev) > 6:
                return 7
        case len(abbrev) > 4:
                return 8
        default:
                return 9
        }
}

func RenderTopoNodes(nodeSVG, glowDefs *strings.Builder, nodes []ProtocolNode, positions []NodePos, nodeR int) {
        for i, n := range nodes {
                if i >= len(positions) {
                        break
                }
                pos := positions[i]
                s := TopoNodeStyleFor(n)

                glowDefs.WriteString(fmt.Sprintf(
                        `<radialGradient id="ng%d" cx="%d" cy="%d" r="%d" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%s" stop-opacity="%s"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>`,
                        i, pos.X, pos.Y, nodeR+8, s.NodeColor, s.GlowOpacity, s.NodeColor,
                ))

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="url(#ng%d)"/>`,
                        pos.X, pos.Y, nodeR+8, i,
                ))

                if n.Status == "success" || n.Status == "warning" {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.04"><animate attributeName="r" values="%d;%d;%d" dur="3s" repeatCount="indefinite"/><animate attributeName="fill-opacity" values="0.04;0.08;0.04" dur="3s" repeatCount="indefinite"/></circle>`,
                                pos.X, pos.Y, nodeR+6, s.NodeColor, nodeR+6, nodeR+10, nodeR+6,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="%s" stroke="%s" stroke-opacity="%s" stroke-width="%.1f"/>`,
                        pos.X, pos.Y, nodeR, s.NodeColor, s.FillOpacity, s.StrokeColor, s.StrokeOpacity, s.StrokeW,
                ))

                if n.Status == "missing" || n.Status == "error" {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%d" cy="%d" r="%d" fill="none" stroke="%s" stroke-opacity="0.6" stroke-width="1.5" stroke-dasharray="3 2"><animate attributeName="stroke-opacity" values="0.6;0.3;0.6" dur="2s" repeatCount="indefinite"/></circle>`,
                                pos.X, pos.Y, nodeR+4, hexRed,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                        pos.X, pos.Y+3, s.TextColor, AbbrevFontSize(n.Abbrev), n.Abbrev,
                ))
        }
}

func BadgeSVGDetailed(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash, baseURL string) []byte {
        riskLabel, riskColorName := ExtractPostureRisk(results)
        if IsGatewayDerivedResult(results) {
                // Provenance beside posture, not in its place (Science's ruling).
                riskLabel += " · gateway-derived"
        }
        riskColorName = NormalizeRiskColor(riskLabel, riskColorName)
        nodes := ExtractProtocolIndicators(results)
        exposure := ExtractExposure(results)

        riskHex := RiskColorToHex(riskColorName)
        riskLabelHex := ReportRiskColor(riskColorName)
        borderColor := RiskBorderColor(riskColorName)
        missing := CountMissing(nodes)

        domainDisplay := domain
        if len(domainDisplay) > 30 {
                domainDisplay = domainDisplay[:27] + "..."
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        hashDisplay := postureHash
        if len(hashDisplay) > 8 {
                hashDisplay = hashDisplay[:8]
        }
        if hashDisplay == "" {
                hashDisplay = "--------"
        }

        hasExposure := exposure.Status == "exposed" && exposure.FindingCount > 0

        controlCount := 10

        postureContext := BuildPostureContext(nodes, missing, controlCount)

        const (
                vbWidth  = 600
                vbHeight = 230
                scale    = 4.0 / 3.0
                pad      = 16
                nodeR    = 18
        )
        width := vbWidth
        height := vbHeight
        if hasExposure {
                height = 260
        }
        renderW := int(float64(width) * scale)
        renderH := int(float64(height) * scale)

        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)

        owlCX := 70
        owlCY := 110

        nodePositions := []NodePos{
                {250, 78},
                {332, 78},
                {414, 78},
                {250, 178},
                {373, 178},
                {310, 128},
                {414, 128},
                {496, 78},
                {496, 178},
                {558, 178},
        }

        edges := []TopoEdge{
                {2, 0, "alignment", true, 291, 66},
                {2, 1, "", true, 0, 0},
                {7, 2, "p=quarantine+", true, 455, 66},
                {6, 5, "reports", false, 362, 118},
                {6, 4, "", false, 0, 0},
                {4, 3, "requires", true, 311, 168},
                {8, 3, "strengthens", false, 440, 168},
                {9, 8, "", false, 0, 0},
        }

        icieCX := 200
        icieCY := 54
        icieR := 13
        resolverCX := 136
        resolverCY := 54
        resolverW := 56
        resolverH := 18

        var nodeSVG strings.Builder

        resolverColor := "#5c6bc0"
        icieColor := "#e0e0e0"

        nodeSVG.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1"/>`,
                resolverCX-resolverW/2, resolverCY-resolverH/2, resolverW, resolverH, resolverColor, resolverColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="8" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">Resolvers</text>`,
                resolverCX, resolverCY+3, resolverColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1.2"/>`,
                icieCX, icieCY, icieR, icieColor, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="8" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">ICIE</text>`,
                icieCX, icieCY+3, icieColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<path d="M%d,%d L%d,%d" fill="none" stroke="%s" stroke-opacity="0.3" stroke-width="1" stroke-dasharray="3 2"/>`,
                resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<circle r="2" fill="%s" opacity="0.8"><animateMotion dur="1.2s" repeatCount="indefinite" path="M%d,%d L%d,%d"/></circle>`,
                icieColor, resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY,
        ))

        type fanTarget struct {
                x, y int
        }
        fanTargetIdx := []int{0, 5, 3}
        fanTargets := []fanTarget{
                {nodePositions[0].X, nodePositions[0].Y},
                {nodePositions[5].X, nodePositions[5].Y},
                {nodePositions[3].X, nodePositions[3].Y},
        }
        for fi, ft := range fanTargets {
                fx := float64(ft.x - icieCX)
                fy := float64(ft.y - icieCY)
                fd := math.Sqrt(fx*fx + fy*fy)
                if fd == 0 {
                        continue
                }
                fnx := fx / fd
                fny := fy / fd
                startX := float64(icieCX) + fnx*float64(icieR)
                startY := float64(icieCY) + fny*float64(icieR)
                endX := float64(ft.x) - fnx*float64(nodeR+2)
                endY := float64(ft.y) - fny*float64(nodeR+2)
                targetColor := ProtocolGroupColor(nodes[fanTargetIdx[fi]].Abbrev)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<path d="M%.0f,%.0f L%.0f,%.0f" fill="none" stroke="%s" stroke-opacity="0.15" stroke-width="1" stroke-dasharray="3 2"/>`,
                        startX, startY, endX, endY, targetColor,
                ))
                dur := fmt.Sprintf("%.1fs", 2.0+float64(fi)*0.5)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle r="2" fill="%s" opacity="0.6"><animateMotion dur="%s" repeatCount="indefinite" path="M%.0f,%.0f L%.0f,%.0f"/></circle>`,
                        targetColor, dur, startX, startY, endX, endY,
                ))
        }

        RenderTopoEdges(&nodeSVG, edges, nodes, nodePositions, nodeR)

        var glowDefs strings.Builder
        RenderTopoNodes(&nodeSVG, &glowDefs, nodes, nodePositions, nodeR)

        totalControls := len(nodes)
        missingSVG := ""
        if missing > 0 {
                missingSVG = fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="9" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%d of %d missing</text>`,
                        width-pad, 218, hexRed, missing, totalControls,
                )
        }

        exposureSVG := ""
        exposureAnchor := fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
        if hasExposure {
                label := fmt.Sprintf("⚠ %d secret%s exposed", exposure.FindingCount, PluralS(exposure.FindingCount))
                eY := 215
                boxW := width - pad*2
                exposureSVG = fmt.Sprintf(
                        `<a href="%s" target="_blank">
  <rect x="%d" y="%d" width="%d" height="22" rx="4" fill="%s" fill-opacity="0.10" stroke="%s" stroke-width="1" cursor="pointer"/>
  <text x="%d" y="%d" fill="#ff6b6b" font-size="10" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="middle" cursor="pointer">%s</text>
</a>`,
                        exposureAnchor,
                        pad, eY, boxW, hexRed, hexRed,
                        width/2, eY+15, label,
                )
        }

        hashURL := fmt.Sprintf("%s/analysis/%d/view/C#intelligence-metadata", baseURL, scanID)

        riskLine := riskLabel

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="xMidYMid meet" role="img" aria-label="DNS Tool: %s — %s">
  <title>DNS Tool: %s — %s</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#161b22"/>
      <stop offset="1" stop-color="#0d1117"/>
    </linearGradient>
    <radialGradient id="owlGlow" cx="50%%" cy="50%%" r="50%%">
      <stop offset="0" stop-color="%s" stop-opacity=".12"/>
      <stop offset="1" stop-color="%s" stop-opacity="0"/>
    </radialGradient>
    %s
  </defs>
  <style>
    .topo-flow { stroke-dasharray: 4 3; animation: topodata 1.2s linear infinite; }
    @keyframes topodata { to { stroke-dashoffset: -7; } }
  </style>

  <rect width="%d" height="%d" rx="8" fill="url(#bg)"/>
  <rect x="1" y="1" width="%d" height="%d" rx="8" fill="none" stroke="%s" stroke-width="1.5"/>

  <text x="%d" y="26" fill="#e6edf3" font-size="14" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="26" fill="#484f58" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>

  <line x1="%d" y1="34" x2="%d" y2="34" stroke="#21262d" stroke-width="1"/>

  <circle cx="%d" cy="%d" r="52" fill="url(#owlGlow)"/>
  <a href="%s" target="_blank">
    <image x="%d" y="%d" width="80" height="80" href="%s" cursor="pointer"/>
  </a>

  <rect x="%d" y="%d" width="3" height="14" rx="1.5" fill="%s"/>
  <text x="%d" y="%d" fill="%s" font-size="12" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="%d" fill="#8b949e" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  <text x="228" y="58" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">AUTH</text>
  <text x="228" y="108" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">TRANSPORT</text>
  <text x="228" y="158" fill="#8b949e" font-size="7.5" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.7" letter-spacing="0.5">DNS</text>
  <line x1="228" y1="60" x2="524" y2="60" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="108" x2="450" y2="108" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="158" x2="586" y2="158" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>

  %s

  %s

  %s

  <a href="%s" target="_blank">
    <text x="%d" y="%d" fill="#484f58" font-size="8" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace" cursor="pointer">sha3:%s</text>
  </a>
  <a href="%s" target="_blank">
    <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif" cursor="pointer">dnstool.it-help.tech</text>
  </a>
</svg>`,
                renderW, renderH, width, height,
                domain, riskLabel,
                domain, riskLabel,
                riskHex, riskHex,
                glowDefs.String(),
                width, height,
                width-2, height-2, borderColor,
                pad, domainDisplay,
                width-pad, scanDate,
                pad, width-pad,
                owlCX, owlCY,
                reportURL,
                owlCX-40, owlCY-40, OwlBadgePNG,
                20, 176, riskLabelHex,
                26, 188, riskLabelHex, riskLine,
                26, 202, postureContext,
                nodeSVG.String(),
                missingSVG,
                exposureSVG,
                hashURL,
                pad, height-6, hashDisplay,
                reportURL,
                pad+70, height-6,
        )

        return []byte(svg)
}

func IsGatewayDerivedResult(results map[string]any) bool {
        if results == nil {
                return false
        }
        if scope, ok := results["analysis_scope"].(string); ok {
                return scope == "gateway_derived" || scope == "core_dns_only"
        }
        if postureRaw, ok := results["posture"].(map[string]any); ok {
                if reason, ok := postureRaw["reason"].(string); ok && reason == "gateway_derived" {
                        return true
                }
        }
        return false
}

func ExtractWeb3Status(results map[string]any) string {
        web3Raw, ok := results["web3_analysis"]
        if !ok {
                return ""
        }
        web3, ok := web3Raw.(map[string]any)
        if !ok {
                return ""
        }
        detected, _ := web3["detected"].(bool)
        if detected {
                return "success"
        }
        return ""
}
