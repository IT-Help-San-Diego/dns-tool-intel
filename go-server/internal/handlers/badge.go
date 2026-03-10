// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "log/slog"
        "math"
        "net/http"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        colorDanger    = "#e05d44"
        colorGrey      = "#9f9f9f"
        contentTypeSVG = "image/svg+xml; charset=utf-8"
        labelDNSTool   = "DNS Tool"

        mapKeyColor      = "color"
        mapKeyLabel      = "label"
        mapKeyLightgrey  = "lightgrey"
        strSchemaversion = "schemaVersion"
)

type BadgeHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewBadgeHandler(database *db.Database, cfg *config.Config) *BadgeHandler {
        return &BadgeHandler{DB: database, Config: cfg}
}

func (h *BadgeHandler) resolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, ok bool) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "missing domain or id", colorDanger))
                return "", nil, time.Time{}, false
        }

        ctx := c.Request.Context()

        if idQ != "" {
                scanID, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid scan id", colorDanger))
                        return "", nil, time.Time{}, false
                }
                analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(scanID))
                if err != nil || analysis.Private {
                        c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "scan not found", colorGrey))
                        return "", nil, time.Time{}, false
                }
                results := unmarshalResults(analysis.FullResults, "Badge")
                return analysis.Domain, results, analysis.CreatedAt.Time, true
        }

        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid domain", colorDanger))
                return "", nil, time.Time{}, false
        }

        analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "not scanned", colorGrey))
                return "", nil, time.Time{}, false
        }
        res := unmarshalResults(analysis.FullResults, "Badge")
        return ascii, res, analysis.CreatedAt.Time, true
}

func (h *BadgeHandler) Badge(c *gin.Context) {
        domain, results, scanTime, ok := h.resolveAnalysis(c)
        if !ok {
                return
        }
        if results == nil {
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(labelDNSTool, "no data", colorGrey))
                return
        }

        riskLabel, riskColor := extractPostureRisk(results)
        riskHex := riskColorToHex(riskColor)
        style := c.DefaultQuery("style", "flat")

        c.Header("Cache-Control", "public, max-age=3600, s-maxage=3600")
        c.Header("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGCovert(domain, riskLabel, riskHex))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGDetailed(domain, results, scanTime))
        default:
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(domain, riskLabel, riskHex))
        }
}

func (h *BadgeHandler) BadgeEmbed(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        c.HTML(http.StatusOK, "badge_embed.html", gin.H{
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "AppVersion":      h.Config.AppVersion,
                "BaseURL":         h.Config.BaseURL,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
        })
}

func unmarshalResults(fullResults []byte, caller string) map[string]any {
        if len(fullResults) == 0 {
                return nil
        }
        var results map[string]any
        if err := json.Unmarshal(fullResults, &results); err != nil {
                slog.Warn(caller+": unmarshal full_results", mapKeyError, err)
                return nil
        }
        return results
}

func extractPostureRisk(results map[string]any) (string, string) {
        riskLabel := "Unknown"
        riskColor := ""
        if results == nil {
                return riskLabel, riskColor
        }
        postureRaw, ok := results["posture"]
        if !ok {
                return riskLabel, riskColor
        }
        posture, ok := postureRaw.(map[string]any)
        if !ok {
                return riskLabel, riskColor
        }
        if rl, ok := posture[mapKeyLabel].(string); ok && rl != "" {
                riskLabel = rl
        } else if rl, ok := posture["grade"].(string); ok && rl != "" {
                riskLabel = rl
        }
        if rc, ok := posture[mapKeyColor].(string); ok {
                riskColor = rc
        }
        return riskLabel, riskColor
}

func riskColorToHex(color string) string {
        switch color {
        case "success":
                return "#3fb950"
        case "warning":
                return "#d29922"
        case "danger":
                return colorDanger
        default:
                return colorGrey
        }
}

func badgeSVG(label, value, color string) []byte {
        labelWidth := len(label)*7 + 10
        valueWidth := len(value)*7 + 10
        totalWidth := labelWidth + valueWidth

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
    <text aria-hidden="true" x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>`,
                totalWidth, label, value, label, value,
                totalWidth,
                labelWidth,
                labelWidth, valueWidth, color,
                totalWidth,
                labelWidth/2+1, label,
                labelWidth/2+1, label,
                labelWidth+valueWidth/2-1, value,
                labelWidth+valueWidth/2-1, value,
        )
        return []byte(svg)
}

func (h *BadgeHandler) BadgeShieldsIO(c *gin.Context) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.JSON(http.StatusOK, gin.H{
                        strSchemaversion: 1,
                        mapKeyLabel:      labelDNSTool,
                        mapKeyMessage:    "missing domain or id",
                        mapKeyColor:      mapKeyLightgrey,
                        "isError":        true,
                })
                return
        }

        ctx := c.Request.Context()
        var results map[string]any

        if idQ != "" {
                scanID, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        c.JSON(http.StatusOK, gin.H{
                                strSchemaversion: 1,
                                mapKeyLabel:      labelDNSTool,
                                mapKeyMessage:    "invalid scan id",
                                mapKeyColor:      mapKeyLightgrey,
                                "isError":        true,
                        })
                        return
                }
                analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(scanID))
                if err != nil || analysis.Private {
                        c.JSON(http.StatusOK, gin.H{
                                strSchemaversion: 1,
                                mapKeyLabel:      labelDNSTool,
                                mapKeyMessage:    "scan not found",
                                mapKeyColor:      mapKeyLightgrey,
                        })
                        return
                }
                results = unmarshalResults(analysis.FullResults, "BadgeShieldsIO")
        } else {
                ascii, err := dnsclient.DomainToASCII(domainQ)
                if err != nil || !dnsclient.ValidateDomain(ascii) {
                        c.JSON(http.StatusOK, gin.H{
                                strSchemaversion: 1,
                                mapKeyLabel:      labelDNSTool,
                                mapKeyMessage:    "invalid domain",
                                mapKeyColor:      mapKeyLightgrey,
                                "isError":        true,
                        })
                        return
                }

                analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, ascii)
                if err != nil || analysis.Private {
                        c.JSON(http.StatusOK, gin.H{
                                strSchemaversion: 1,
                                mapKeyLabel:      labelDNSTool,
                                mapKeyMessage:    "not scanned",
                                mapKeyColor:      mapKeyLightgrey,
                        })
                        return
                }
                results = unmarshalResults(analysis.FullResults, "BadgeShieldsIO")
        }

        riskLabel, riskColorRaw := extractPostureRisk(results)
        shieldsColor := riskColorToShields(riskColorRaw)

        c.Header("Cache-Control", "public, max-age=3600, s-maxage=3600")
        c.Header("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))

        resp := gin.H{
                strSchemaversion: 1,
                mapKeyLabel:      labelDNSTool,
                mapKeyMessage:    riskLabel,
                mapKeyColor:      shieldsColor,
                "namedLogo":      "shield",
                "cacheSeconds":   3600,
        }

        c.JSON(http.StatusOK, resp)
}

func riskColorToShields(color string) string {
        switch color {
        case "success":
                return "brightgreen"
        case "warning":
                return "yellow"
        case "danger":
                return "red"
        default:
                return mapKeyLightgrey
        }
}

func covertRiskLabel(riskLabel string) string {
        switch riskLabel {
        case "Low Risk":
                return "Hardened"
        case "Medium Risk":
                return "Patching"
        case "High Risk":
                return "Exposed"
        case "Critical Risk":
                return "Wide Open"
        default:
                return riskLabel
        }
}

func covertTagline(riskLabel string) string {
        switch riskLabel {
        case "Low Risk":
                return "Good luck with that."
        case "Medium Risk":
                return "Getting there."
        case "High Risk":
                return "Work to do."
        case "Critical Risk":
                return "Yikes."
        default:
                return ""
        }
}

func badgeSVGCovert(domain, riskLabel, riskHex string) []byte {
        covertLabel := covertRiskLabel(riskLabel)
        tagline := covertTagline(riskLabel)

        domainDisplay := domain
        if len(domainDisplay) > 28 {
                domainDisplay = domainDisplay[:25] + "..."
        }

        const (
                width  = 320
                height = 56
        )

        taglineSVG := ""
        taglineX := width - 12
        if tagline != "" {
                taglineSVG = fmt.Sprintf(`<text x="%d" y="46" fill="#6e7681" font-size="9" font-family="'Courier New',monospace" text-anchor="end">%s</text>`, taglineX, tagline)
        }

        lineX2 := width - 12
        rectX := width - len(covertLabel)*8 - 16
        endTextX := width - 12

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <rect width="%d" height="%d" rx="4" fill="#0a0a0a"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="4" fill="none" stroke="#1a1a1a"/>
  <line x1="12" y1="30" x2="%d" y2="30" stroke="#1a1a1a" stroke-width="1"/>
  <text x="12" y="20" fill="#c9d1d9" font-size="13" font-weight="600" font-family="'Courier New',monospace">%s</text>
  <rect x="%d" y="8" width="4" height="16" rx="2" fill="%s"/>
  <text x="%d" y="20" fill="%s" font-size="12" font-weight="700" font-family="'Courier New',monospace" text-anchor="end">%s</text>
  <text x="12" y="46" fill="#484f58" font-size="9" font-family="'Courier New',monospace">$ dns-tool scan</text>
  %s
</svg>`,
                width, height, width, height,
                domain, covertLabel,
                domain, covertLabel,
                width, height,
                width-1, height-1,
                lineX2,
                domainDisplay,
                rectX, riskHex,
                endTextX, riskHex, covertLabel,
                taglineSVG,
        )
        return []byte(svg)
}

type protocolNode struct {
        abbrev     string
        status     string
        colorHex   string
        x, y       int
        groupColor string
}

func protocolGroupColor(abbrev string) string {
        switch abbrev {
        case "SPF", "DKIM", "DMARC":
                return "#4a8fe7"
        case "DNSSEC":
                return "#d29922"
        case "DANE", "MTA-STS", "TLS-RPT":
                return "#3fb950"
        case "BIMI":
                return "#a371f7"
        case "CAA":
                return "#39d4d4"
        default:
                return "#484f58"
        }
}

func protocolStatusToNodeColor(status, groupColor string) string {
        switch status {
        case "success":
                return groupColor
        case "warning":
                return "#d29922"
        case "error":
                return "#f85149"
        default:
                return "#30363d"
        }
}

func extractProtocolIndicators(results map[string]any) []protocolNode {
        protocols := []struct {
                key    string
                abbrev string
        }{
                {"spf_analysis", "SPF"},
                {"dkim_analysis", "DKIM"},
                {"dmarc_analysis", "DMARC"},
                {"dnssec_analysis", "DNSSEC"},
                {"dane_analysis", "DANE"},
                {"mta_sts_analysis", "MTA-STS"},
                {"tls_rpt_analysis", "TLS-RPT"},
                {"bimi_analysis", "BIMI"},
                {"caa_analysis", "CAA"},
        }

        nodes := make([]protocolNode, 0, len(protocols))
        for _, p := range protocols {
                status := "missing"
                if analysisRaw, ok := results[p.key]; ok {
                        if analysis, ok := analysisRaw.(map[string]any); ok {
                                if s, ok := analysis["status"].(string); ok {
                                        status = s
                                }
                        }
                }
                gc := protocolGroupColor(p.abbrev)
                nc := protocolStatusToNodeColor(status, gc)
                nodes = append(nodes, protocolNode{
                        abbrev:     p.abbrev,
                        status:     status,
                        colorHex:   nc,
                        groupColor: gc,
                })
        }
        return nodes
}

func extractPostureScore(results map[string]any) int {
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

func scoreColor(score int) string {
        if score >= 80 {
                return "#3fb950"
        }
        if score >= 50 {
                return "#d29922"
        }
        if score >= 0 {
                return "#f85149"
        }
        return "#484f58"
}

func badgeSVGDetailed(domain string, results map[string]any, scanTime time.Time) []byte {
        riskLabel, riskColorName := extractPostureRisk(results)
        score := extractPostureScore(results)
        nodes := extractProtocolIndicators(results)

        sc := scoreColor(score)
        riskHex := riskColorToHex(riskColorName)

        domainDisplay := domain
        if len(domainDisplay) > 30 {
                domainDisplay = domainDisplay[:27] + "..."
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width  = 440
                height = 186
                pad    = 16

                gaugeR  = 34
                gaugeCX = 58
                gaugeCY = 100
        )

        arcPath := func(cx, cy, r int, startDeg, endDeg float64) string {
                s := startDeg * math.Pi / 180
                e := endDeg * math.Pi / 180
                x1 := float64(cx) + float64(r)*math.Cos(s)
                y1 := float64(cy) + float64(r)*math.Sin(s)
                x2 := float64(cx) + float64(r)*math.Cos(e)
                y2 := float64(cy) + float64(r)*math.Sin(e)
                largeArc := 0
                if endDeg-startDeg > 180 {
                        largeArc = 1
                }
                return fmt.Sprintf("M%.1f,%.1f A%d,%d 0 %d,1 %.1f,%.1f", x1, y1, r, r, largeArc, x2, y2)
        }

        const startAngle = 135.0
        const endAngle = 405.0
        bgTrack := arcPath(gaugeCX, gaugeCY, gaugeR, startAngle, endAngle)

        scoreAngle := startAngle
        if score >= 0 {
                scoreAngle = startAngle + (endAngle-startAngle)*float64(score)/100.0
        }
        scoreFill := arcPath(gaugeCX, gaugeCY, gaugeR, startAngle, scoreAngle)

        scoreText := "--"
        if score >= 0 {
                scoreText = strconv.Itoa(score)
        }

        nodePositions := []struct{ x, y int }{
                {148, 56},
                {208, 56},
                {268, 56},
                {346, 56},
                {346, 96},
                {148, 96},
                {208, 96},
                {268, 96},
                {148, 136},
        }

        var nodeSVG strings.Builder

        connLines := [][4]int{
                {148, 56, 208, 56},
                {208, 56, 268, 56},
                {148, 96, 208, 96},
                {268, 96, 346, 96},
                {268, 56, 268, 96},
                {346, 56, 346, 96},
        }
        for _, cl := range connLines {
                nodeSVG.WriteString(fmt.Sprintf(
                        `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#21262d" stroke-width="1" stroke-dasharray="4,3"/>`,
                        cl[0], cl[1], cl[2], cl[3],
                ))
        }

        for i, n := range nodes {
                if i >= len(nodePositions) {
                        break
                }
                pos := nodePositions[i]

                r := 16
                filled := n.status == "success" || n.status == "warning"
                fillColor := "none"
                fillOpacity := "0"
                strokeColor := n.colorHex
                strokeW := 2

                if filled {
                        fillColor = n.colorHex
                        fillOpacity = "0.15"
                        strokeW = 2
                } else if n.status == "error" {
                        fillColor = "#f85149"
                        fillOpacity = "0.1"
                        strokeColor = "#f85149"
                } else {
                        strokeColor = "#30363d"
                        strokeW = 1
                }

                abbrevSize := 8
                if len(n.abbrev) > 4 {
                        abbrevSize = 7
                }
                if len(n.abbrev) > 6 {
                        abbrevSize = 6
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="%s" stroke="%s" stroke-width="%d"/>`,
                        pos.x, pos.y, r, fillColor, fillOpacity, strokeColor, strokeW,
                ))
                nodeSVG.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                        pos.x, pos.y+3, strokeColor, abbrevSize, n.abbrev,
                ))
        }

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Tool: %s — %s (Score: %s)">
  <title>DNS Tool: %s — %s (Score: %s)</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#161b22"/>
      <stop offset="1" stop-color="#0d1117"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%%" cy="50%%" r="50%%">
      <stop offset="0" stop-color="%s" stop-opacity=".06"/>
      <stop offset="1" stop-color="%s" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="%d" height="%d" rx="8" fill="url(#bg)"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="8" fill="none" stroke="#30363d" stroke-width="1"/>

  <circle cx="%d" cy="%d" r="60" fill="url(#glow)"/>

  <text x="%d" y="26" fill="#e6edf3" font-size="14" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="26" fill="#484f58" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>

  <line x1="%d" y1="34" x2="%d" y2="34" stroke="#21262d" stroke-width="1"/>

  <path d="%s" fill="none" stroke="#21262d" stroke-width="6" stroke-linecap="round"/>
  <path d="%s" fill="none" stroke="%s" stroke-width="6" stroke-linecap="round"/>

  <text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="20" font-weight="700" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace">%s</text>
  <text x="%d" y="%d" text-anchor="middle" fill="#484f58" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">/ 100</text>

  <rect x="%d" y="%d" width="3" height="14" rx="1.5" fill="%s"/>
  <text x="%d" y="%d" fill="%s" font-size="11" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  <text x="120" y="44" fill="#6e7681" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">Email Auth</text>
  <text x="320" y="44" fill="#6e7681" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">Integrity</text>
  <text x="120" y="124" fill="#6e7681" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">Brand</text>
  <text x="200" y="124" fill="#6e7681" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">Transport</text>

  %s

  <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">dnstool.it-help.tech</text>
  <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">Scanned %s</text>
</svg>`,
                width, height, width, height,
                domain, riskLabel, scoreText,
                domain, riskLabel, scoreText,
                sc, sc,
                width, height,
                width-1, height-1,
                gaugeCX, gaugeCY,
                pad, domainDisplay,
                width-pad, scanDate,
                pad, width-pad,
                bgTrack,
                scoreFill, sc,
                gaugeCX, gaugeCY+6, sc, scoreText,
                gaugeCX, gaugeCY+16,
                20, 148, riskHex,
                26, 159, riskHex, riskLabel,
                nodeSVG.String(),
                pad, height-6,
                width-pad, height-6, scanDate,
        )

        return []byte(svg)
}
