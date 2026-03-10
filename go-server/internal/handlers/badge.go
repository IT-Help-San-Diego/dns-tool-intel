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
        riskColor = riskColorToHex(riskColor)
        style := c.DefaultQuery("style", "flat")

        c.Header("Cache-Control", "public, max-age=3600, s-maxage=3600")
        c.Header("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGCovert(domain, riskLabel, riskColor))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGDetailed(domain, results, scanTime))
        default:
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(labelDNSTool, riskLabel, riskColor))
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
                return "#4c1"
        case "warning":
                return "#dfb317"
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

func badgeSVGCovert(domain, riskLabel, color string) []byte {
        label := "DNS Tool // " + domain
        labelWidth := len(label)*6 + 14
        valueWidth := len(riskLabel)*7 + 10
        totalWidth := labelWidth + valueWidth

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#1a0808"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#c43c3c" text-anchor="middle" font-family="'Courier New',monospace" text-rendering="geometricPrecision" font-size="11">
    <text x="%d" y="14">%s</text>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="%d" y="14">%s</text>
  </g>
</svg>`,
                totalWidth, domain, riskLabel, domain, riskLabel,
                totalWidth,
                labelWidth,
                labelWidth, valueWidth, color,
                totalWidth,
                labelWidth/2+1, label,
                labelWidth+valueWidth/2-1, riskLabel,
        )
        return []byte(svg)
}

type protocolIndicator struct {
        abbrev string
        status string
}

func extractProtocolIndicators(results map[string]any) []protocolIndicator {
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

        indicators := make([]protocolIndicator, 0, len(protocols))
        for _, p := range protocols {
                status := "missing"
                if analysisRaw, ok := results[p.key]; ok {
                        if analysis, ok := analysisRaw.(map[string]any); ok {
                                if s, ok := analysis["status"].(string); ok {
                                        status = s
                                }
                        }
                }
                indicators = append(indicators, protocolIndicator{abbrev: p.abbrev, status: status})
        }
        return indicators
}

func protocolStatusColor(status string) string {
        switch status {
        case "success":
                return "#3fb950"
        case "warning":
                return "#d29922"
        case "error":
                return "#f85149"
        case "info":
                return "#4a8fe7"
        default:
                return "#484f58"
        }
}

func protocolStatusIcon(status string) string {
        switch status {
        case "success":
                return "&#x2713;"
        case "warning":
                return "&#x25B2;"
        case "error":
                return "&#x2717;"
        case "info":
                return "&#x2139;"
        default:
                return "&#x2014;"
        }
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
        _ = riskColorName
        score := extractPostureScore(results)
        indicators := extractProtocolIndicators(results)

        sc := scoreColor(score)
        riskHex := riskColorToHex(riskColorName)

        domainDisplay := domain
        if len(domainDisplay) > 32 {
                domainDisplay = domainDisplay[:29] + "..."
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width       = 380
                height      = 160
                pad         = 16
                gaugeR      = 38
                gaugeCX     = 64
                gaugeCY     = 92
                startAngle  = 135.0
                endAngle    = 405.0
                protStartX  = 140
                protStartY  = 48
                protColW    = 80
                protRowH    = 22
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

        var protRows strings.Builder
        for i, ind := range indicators {
                col := i / 3
                row := i % 3
                x := protStartX + col*protColW
                y := protStartY + row*protRowH
                iconColor := protocolStatusColor(ind.status)
                icon := protocolStatusIcon(ind.status)
                protRows.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="12" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace">%s</text>`+
                                `<text x="%d" y="%d" fill="#c9d1d9" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                        x, y, iconColor, icon,
                        x+16, y, ind.abbrev,
                ))
        }

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Tool Security Assessment: %s — %s (Score: %s)">
  <title>DNS Tool: %s — %s (Score: %s)</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#161b22"/>
      <stop offset="1" stop-color="#0d1117"/>
    </linearGradient>
    <linearGradient id="shine" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fff" stop-opacity=".03"/>
      <stop offset="1" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <rect width="%d" height="%d" rx="8" fill="url(#bg)"/>
  <rect width="%d" height="%d" rx="8" fill="url(#shine)"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="8" fill="none" stroke="#30363d" stroke-width="1"/>

  <text x="%d" y="24" fill="#c9d1d9" font-size="13" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="24" fill="#484f58" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>

  <line x1="%d" y1="32" x2="%d" y2="32" stroke="#21262d" stroke-width="1"/>

  <path d="%s" fill="none" stroke="#21262d" stroke-width="7" stroke-linecap="round"/>
  <path d="%s" fill="none" stroke="%s" stroke-width="7" stroke-linecap="round"/>

  <text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="22" font-weight="700" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace">%s</text>
  <text x="%d" y="%d" text-anchor="middle" fill="#484f58" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">/ 100</text>

  <rect x="%d" y="%d" width="4" height="14" rx="2" fill="%s"/>
  <text x="%d" y="%d" fill="%s" font-size="11" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  %s

  <text x="%d" y="%d" fill="#484f58" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">dnstool.it-help.tech</text>
  <text x="%d" y="%d" fill="#484f58" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">Scanned %s</text>
</svg>`,
                width, height, width, height, domain, riskLabel, scoreText,
                domain, riskLabel, scoreText,
                width, height,
                width, height,
                width-1, height-1,
                pad, domainDisplay,
                width-pad, scanDate,
                pad, width-pad,
                bgTrack,
                scoreFill, sc,
                gaugeCX, gaugeCY+6, sc, scoreText,
                gaugeCX, gaugeCY+18, 
                24, 136, riskHex,
                32, 147, riskHex, riskLabel,
                protRows.String(),
                pad, height-8,
                width-pad, height-8, scanDate,
        )

        return []byte(svg)
}
