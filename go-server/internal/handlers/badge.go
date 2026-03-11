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

        hexRed       = "#f85149"
        hexGreen     = "#3fb950"
        hexYellow    = "#d29922"
        hexScGreen   = "#58E790"
        hexScYellow  = "#C7C400"
        hexScRed     = "#B43C29"
        hexDimGrey   = "#30363d"

        protoMTASTS = "MTA-STS"
        protoTLSRPT = "TLS-RPT"
        protoDMARC  = "DMARC"
        protoDNSSEC = "DNSSEC"
)

type BadgeHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewBadgeHandler(database *db.Database, cfg *config.Config) *BadgeHandler {
        return &BadgeHandler{DB: database, Config: cfg}
}

func (h *BadgeHandler) resolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, ok bool) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "missing domain or id", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        ctx := c.Request.Context()

        if idQ != "" {
                sid, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid scan id", colorDanger))
                        return "", nil, time.Time{}, 0, "", false
                }
                analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(sid))
                if err != nil || analysis.Private {
                        c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "scan not found", colorGrey))
                        return "", nil, time.Time{}, 0, "", false
                }
                results := unmarshalResults(analysis.FullResults, "Badge")
                return analysis.Domain, results, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
        }

        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                c.Data(http.StatusBadRequest, contentTypeSVG, badgeSVG(mapKeyError, "invalid domain", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        analysis, err := h.DB.Queries.GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                c.Data(http.StatusNotFound, contentTypeSVG, badgeSVG(labelDNSTool, "not scanned", colorGrey))
                return "", nil, time.Time{}, 0, "", false
        }
        res := unmarshalResults(analysis.FullResults, "Badge")
        return ascii, res, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
}

func (h *BadgeHandler) Badge(c *gin.Context) {
        domain, results, scanTime, scanID, postureHash, ok := h.resolveAnalysis(c)
        if !ok {
                return
        }
        if results == nil {
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(labelDNSTool, "no data", colorGrey))
                return
        }

        riskLabel, riskColor := extractPostureRisk(results)
        riskHex := riskColorToHex(riskColor)
        score := extractPostureScore(results)
        exposure := extractExposure(results)
        style := c.DefaultQuery("style", "flat")

        compactValue := riskLabel
        if score >= 0 {
                compactValue = fmt.Sprintf("%s (%d/100)", riskLabel, score)
        }
        if exposure.status == "exposed" && exposure.findingCount > 0 {
                compactValue += fmt.Sprintf(" · %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
                riskHex = hexRed
        }

        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGCovert(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGDetailed(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        default:
                c.Data(http.StatusOK, contentTypeSVG, badgeSVG(domain, compactValue, riskHex))
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
                return hexGreen
        case "warning":
                return hexYellow
        case "danger":
                return colorDanger
        default:
                return colorGrey
        }
}

func normalizeRiskColor(label, color string) string {
        switch color {
        case "success", "warning", "danger":
                return color
        }
        ll := strings.ToLower(label)
        switch {
        case strings.Contains(ll, "low"):
                return "success"
        case strings.Contains(ll, "medium"):
                return "warning"
        case strings.Contains(ll, "high"), strings.Contains(ll, "critical"):
                return "danger"
        }
        return color
}

func reportRiskColor(color string) string {
        switch color {
        case "success":
                return "#198754"
        case "warning":
                return "#ffc107"
        case "danger":
                return "#dc3545"
        default:
                return colorGrey
        }
}

func scotopicRiskColor(color string) string {
        switch color {
        case "success":
                return hexScGreen
        case "warning":
                return hexScYellow
        case "danger":
                return hexScRed
        default:
                return "#9C7645"
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

        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")

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
                return "Partial"
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
                return "Gaps in the armor."
        case "High Risk":
                return "Door's open."
        case "Critical Risk":
                return "Free real estate."
        default:
                return ""
        }
}

func riskBorderColor(riskColorName string) string {
        switch riskColorName {
        case "success":
                return "#238636"
        case "warning":
                return "#9e6a03"
        case "danger":
                return "#da3633"
        default:
                return hexDimGrey
        }
}

func countMissing(nodes []protocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.status == "missing" || n.status == "error" {
                        count++
                }
        }
        return count
}

func countVulnerable(nodes []protocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.status != "success" && n.status != "warning" {
                        count++
                }
        }
        return count
}

type covertLine struct {
        prefix      string
        text        string
        color       string
        prefixColor string
        desc        string
        descColor   string
        link        string
}

func covertProtocolLine(abbrev, status string) covertLine {
        pad := 10 - len(abbrev)
        if pad < 1 {
                pad = 1
        }
        dots := strings.Repeat(".", pad)

        sRed := hexScRed

        label := abbrev + " " + dots + " "

        switch abbrev {
        case "SPF":
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "can't forge sender envelope", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "partial — spoofing harder", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "sender spoofing possible", descColor: sRed}
        case "DKIM":
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "can't forge signatures", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "weak key — forgery harder", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "message forgery possible", descColor: sRed}
        case protoDMARC:
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "spoofing rejected at gate", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "monitoring only — not blocking", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "email spoofing wide open", descColor: sRed}
        case protoDNSSEC:
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "can't poison DNS cache", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "partial — some zones exposed", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "DNS cache poisoning possible", descColor: sRed}
        case "DANE":
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "can't downgrade TLS", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "TLSA present but weak", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "TLS downgrade possible", descColor: sRed}
        case protoMTASTS:
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "can't intercept mail", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "testing mode — not enforcing", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "mail interception possible", descColor: sRed}
        case protoTLSRPT:
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "transport monitored", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "partial reporting", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "no transport monitoring", descColor: sRed}
        case "BIMI":
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "brand verification active", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "present but no VMC cert", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "brand impersonation possible", descColor: sRed}
        case "CAA":
                if status == "success" {
                        return covertLine{prefix: "[+]", text: label, color: sRed, desc: "cert issuance locked", descColor: sRed}
                }
                if status == "warning" {
                        return covertLine{prefix: "[~]", text: label, color: sRed, desc: "policy present but weak", descColor: sRed}
                }
                return covertLine{prefix: "[-]", text: label, color: sRed, desc: "anyone can issue certs", descColor: sRed}
        default:
                return covertLine{prefix: "[?]", text: abbrev + " " + dots + " ", color: sRed, desc: "unknown", descColor: sRed}
        }
}

func badgeSVGCovert(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, baseURL string) []byte {
        riskLabel, riskColorName := extractPostureRisk(results)
        score := extractPostureScore(results)
        nodes := extractProtocolIndicators(results)
        vulnerable := countVulnerable(nodes)
        exposure := extractExposure(results)

        covertLabel := covertRiskLabel(riskLabel)
        tagline := covertTagline(riskLabel)

        domainDisplay := domain
        if len(domainDisplay) > 35 {
                domainDisplay = domainDisplay[:32] + "..."
        }

        scoreText := "--"
        if score >= 0 {
                scoreText = strconv.Itoa(score)
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width    = 460
                lineH    = 15
                fontSize = 11
                xPad     = 14
                charW    = 7
                monoFont = "'Hack','Fira Code','JetBrains Mono','Menlo','Monaco','Source Code Pro','SF Mono','Ubuntu Mono','Courier New',monospace"
        )

        sRed := hexScRed
        alt := "#664d2e"
        locked := "#58E790"
        dimLocked := "#2d7a47"

        cl := func(pfx, txt, c string) covertLine {
                return covertLine{prefix: pfx, text: txt, color: c}
        }

        var lines []covertLine

        lines = append(lines, cl("", "", ""))

        lines = append(lines, cl("[*]", fmt.Sprintf("Target: %s", domainDisplay), alt))
        lines = append(lines, cl("[*]", fmt.Sprintf("Score: %s/100 — %s", scoreText, covertLabel), scotopicRiskColor(riskColorName)))
        lines = append(lines, cl("", "", ""))

        protocols := []string{"SPF", "DKIM", protoDMARC, protoDNSSEC, "DANE", protoMTASTS, protoTLSRPT, "BIMI", "CAA"}
        for i, p := range protocols {
                if i < len(nodes) {
                        lines = append(lines, covertProtocolLine(p, nodes[i].status))
                }
        }

        if exposure.status == "exposed" && exposure.findingCount > 0 {
                lines = append(lines, cl("", "", ""))
                lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
                lines = append(lines, cl("[!!]", fmt.Sprintf("SECRET EXPOSURE — %d credential%s found", exposure.findingCount, pluralS(exposure.findingCount)), sRed))
                lines = append(lines, cl("", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", alt))
                for _, f := range exposure.findings {
                        label := f.findingType
                        if label == "" {
                                label = "Secret"
                        }
                        redacted := f.redacted
                        if len(redacted) > 24 {
                                redacted = redacted[:21] + "..."
                        }
                        sevTag := ""
                        if f.severity == "critical" {
                                sevTag = " [CRITICAL]"
                        } else if f.severity == "high" {
                                sevTag = " [HIGH]"
                        }
                        findingLine := cl("[!!]", fmt.Sprintf("  >>> %s: %s%s", label, redacted, sevTag), alt)
                        findingLine.link = fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
                        lines = append(lines, findingLine)
                }
                lines = append(lines, cl("[!!]", "  Credentials are publicly accessible.", sRed))
        }

        lines = append(lines, cl("", "", ""))

        if vulnerable == 0 && exposure.findingCount == 0 {
                lines = append(lines, cl("[!]", "All 9 protocols configured — target is hardened", locked))
                lines = append(lines, cl("[!]", tagline, dimLocked))
        } else if vulnerable == 0 && exposure.findingCount > 0 {
                lines = append(lines, cl("[!]", "Protocols hardened — but secrets are leaking", sRed))
                lines = append(lines, cl("[!]", "Rotate exposed credentials immediately.", alt))
        } else {
                vectors := vulnerable + exposure.findingCount
                if vectors <= 2 {
                        lines = append(lines, cl("[!]", fmt.Sprintf("%d attack vector%s available — mostly locked down", vectors, pluralS(vectors)), sRed))
                } else {
                        lines = append(lines, cl("[!]", fmt.Sprintf("%d of 9 attack vectors available", vectors), sRed))
                }
                if exposure.findingCount > 0 {
                        lines = append(lines, cl("[!]", "Leaked secrets make protocol gaps worse.", alt))
                } else if tagline != "" {
                        lines = append(lines, cl("[!]", tagline, alt))
                }
        }

        lines = append(lines, cl("", "", ""))
        hashDisplay := postureHash
        if len(hashDisplay) > 8 {
                hashDisplay = hashDisplay[:8]
        }
        if hashDisplay == "" {
                hashDisplay = "--------"
        }
        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)
        hashURL := fmt.Sprintf("%s/analysis/%d/view/C#intelligence-metadata", baseURL, scanID)
        scanLine := cl("", fmt.Sprintf("[*] %s sha3:%s | scan #%d", scanDate, hashDisplay, scanID), alt)
        scanLine.link = reportURL
        lines = append(lines, scanLine)
        shaLine := cl("", "[*] SHA-3 (Keccak-512) NIST FIPS 202", sRed)
        shaLine.link = hashURL
        lines = append(lines, shaLine)
        planetLine := cl("&amp;&amp;", "#HackThePlanet!   |  #2600", sRed)
        planetLine.prefixColor = sRed
        planetLine.link = baseURL
        lines = append(lines, planetLine)

        height := len(lines)*lineH + 24 + 2*lineH + 4 + 2*lineH + 10

        var svg strings.Builder

        cmdText := fmt.Sprintf("dnstool -R -BC %s", domainDisplay)
        cmdLen := len(cmdText)
        typeTime := float64(cmdLen) * 0.06
        cmdDoneAt := 0.8 + typeTime
        resultStartAt := cmdDoneAt + 0.4

        svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Recon: %s — %s">
  <title>DNS Recon: %s — %s</title>
  <defs>
    <linearGradient id="tbg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1a0505"/>
      <stop offset="1" stop-color="#0a0000"/>
    </linearGradient>
  </defs>
  <style>
    @keyframes blink { 0%%,49%% {opacity:1} 50%%,100%% {opacity:0} }
    @keyframes typeIn { from {opacity:0} to {opacity:1} }
    @keyframes fadeIn { from {opacity:0} to {opacity:1} }
    .cursor { animation: blink 0.8s step-end infinite; animation-delay: 0s; }
    .cursor-hide { animation: blink 0.8s step-end infinite; }
  </style>
  <rect width="%d" height="%d" rx="6" fill="url(#tbg)"/>
  <rect x=".5" y=".5" width="%d" height="%d" rx="6" fill="none" stroke="#3a1515"/>`,
                width, height, width, height,
                domain, covertLabel,
                domain, covertLabel,
                width, height,
                width-1, height-1,
        ))

        svg.WriteString(fmt.Sprintf(`
  <circle cx="16" cy="10" r="4" fill="#ff5f57"/>
  <circle cx="28" cy="10" r="4" fill="#febc2e"/>
  <circle cx="40" cy="10" r="4" fill="#28c840"/>
  <text x="60" y="13" fill="%s" font-size="9" font-family="%s">kali@kali: ~/recon/%s</text>`,
                alt, monoFont, domainDisplay,
        ))

        scanTimeStr := scanTime.UTC().Format("15:04") + "Z"

        promptY := 28
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                xPad, promptY, alt, fontSize, monoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                width-xPad, promptY, alt, fontSize, monoFont, scanTimeStr,
        ))
        promptY2 := promptY + lineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                xPad, promptY2, alt, fontSize, monoFont,
        ))

        cmdX := xPad + 4*charW
        for i, ch := range cmdText {
                delay := 0.8 + float64(i)*0.06
                svg.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.01s" begin="%.2fs" fill="freeze"/>%c</text>`,
                        cmdX+i*charW, promptY2, sRed, fontSize, monoFont, delay, ch,
                ))
        }

        lineIdx := 0
        y := promptY2 + lineH + 4
        for _, line := range lines {
                if line.text == "" && line.prefix == "" {
                        y += lineH / 2
                        continue
                }

                delay := resultStartAt + float64(lineIdx)*0.12

                color := line.color
                if color == "" {
                        color = alt
                }

                pfxColor := line.prefixColor
                if pfxColor == "" && line.prefix != "" {
                        pfxColor = alt
                        if line.prefix == "[+]" {
                                pfxColor = dimLocked
                        } else if line.prefix == "[~]" {
                                pfxColor = "#8a8a00"
                        } else if line.prefix == "[-]" {
                                pfxColor = "#7a2419"
                        } else if line.prefix == "[!!]" {
                                pfxColor = sRed
                        } else if line.prefix == "[*]" {
                                pfxColor = alt
                        } else if line.prefix == "[!]" {
                                pfxColor = sRed
                        }
                }

                svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, delay))

                if line.link != "" {
                        svg.WriteString(fmt.Sprintf(`<a href="%s" target="_blank">`, line.link))
                }

                if line.prefix != "" {
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                xPad, y, pfxColor, fontSize, monoFont, line.prefix,
                        ))

                        if line.desc != "" {
                                svg.WriteString(fmt.Sprintf(
                                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                        xPad+28, y, color, fontSize, monoFont, line.text,
                                ))
                                descX := xPad + 28 + len(line.text)*charW
                                dc := line.descColor
                                if dc == "" {
                                        dc = color
                                }
                                svg.WriteString(fmt.Sprintf(
                                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                        descX, y, dc, fontSize, monoFont, line.desc,
                                ))
                        } else {
                                svg.WriteString(fmt.Sprintf(
                                        `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                        xPad+28, y, color, fontSize, monoFont, line.text,
                                ))
                        }
                } else {
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                xPad, y, color, fontSize, monoFont, line.text,
                        ))
                }

                if line.link != "" {
                        svg.WriteString(`</a>`)
                }
                svg.WriteString(`</g>`)
                y += lineH
                lineIdx++
        }

        planetText := "#HackThePlanet!   |  #2600"
        owlDelay := resultStartAt + float64(lineIdx)*0.12
        owlY := y - lineH + 2
        owlX := xPad + 28 + len(planetText)*charW - 14
        svg.WriteString(fmt.Sprintf(`<g opacity="0" transform="translate(%d,%d) scale(0.8)"><animate attributeName="opacity" from="0" to="0.9" dur="0.3s" begin="%.2fs" fill="freeze"/>`, owlX, owlY-11, owlDelay))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="3" fill="none" stroke="%s" stroke-width="1"/>`, alt))
        svg.WriteString(fmt.Sprintf(`<circle cx="4" cy="5" r="1.2" fill="%s"/>`, sRed))
        svg.WriteString(fmt.Sprintf(`<circle cx="12" cy="5" r="1.2" fill="%s"/>`, sRed))
        svg.WriteString(fmt.Sprintf(`<path d="M7,3 L8,0 L9,3" fill="none" stroke="%s" stroke-width="0.8"/>`, alt))
        svg.WriteString(fmt.Sprintf(`<path d="M3,8 Q8,14 13,8" fill="none" stroke="%s" stroke-width="0.8"/>`, alt))
        svg.WriteString(`</g>`)

        bottomY1 := y + 6
        bottomDelay := owlDelay + 0.3
        svg.WriteString(fmt.Sprintf(`<g opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.15s" begin="%.2fs" fill="freeze"/>`, bottomDelay))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">┌──(kali㉿kali)-[~/recon/%s]</text>`,
                xPad, bottomY1, alt, fontSize, monoFont, domainDisplay,
        ))
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s" text-anchor="end">%s</text>`,
                width-xPad, bottomY1, alt, fontSize, monoFont, scanTimeStr,
        ))
        bottomY2 := bottomY1 + lineH
        svg.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">└─$</text>`,
                xPad, bottomY2, alt, fontSize, monoFont,
        ))
        svg.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="2" height="%d" fill="%s" class="cursor"/>`,
                xPad+4*charW, bottomY2-10, 12, sRed,
        ))
        svg.WriteString(`</g>`)

        svg.WriteString(`</svg>`)

        return []byte(svg.String())
}

func pluralS(n int) string {
        if n == 1 {
                return ""
        }
        return "s"
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
        case "SPF", "DKIM", protoDMARC:
                return "#4fc3f7"
        case protoDNSSEC, "CAA":
                return "#ffb74d"
        case "DANE", protoMTASTS, protoTLSRPT:
                return "#81c784"
        case "BIMI":
                return "#ce93d8"
        default:
                return "#484f58"
        }
}

func protocolStatusToNodeColor(status, groupColor string) string {
        switch status {
        case "success":
                return groupColor
        case "warning":
                return hexYellow
        case "error":
                return hexRed
        default:
                return hexDimGrey
        }
}

func extractProtocolIndicators(results map[string]any) []protocolNode {
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

type exposureFinding struct {
        findingType string
        severity    string
        redacted    string
}

type exposureData struct {
        status       string
        findingCount int
        findings     []exposureFinding
}

func extractExposure(results map[string]any) exposureData {
        secRaw, ok := results["secret_exposure"]
        if !ok {
                return exposureData{status: "clear"}
        }
        sec, ok := secRaw.(map[string]any)
        if !ok {
                return exposureData{status: "clear"}
        }
        status, _ := sec["status"].(string)
        if status == "" {
                status = "clear"
        }
        count := 0
        if c, ok := sec["finding_count"].(float64); ok {
                count = int(c)
        }
        var findings []exposureFinding
        if fRaw, ok := sec["findings"].([]any); ok {
                for _, item := range fRaw {
                        f, ok := item.(map[string]any)
                        if !ok {
                                continue
                        }
                        ft, _ := f["type"].(string)
                        sev, _ := f["severity"].(string)
                        red, _ := f["redacted"].(string)
                        findings = append(findings, exposureFinding{
                                findingType: ft,
                                severity:    sev,
                                redacted:    red,
                        })
                }
        }
        return exposureData{
                status:       status,
                findingCount: count,
                findings:     findings,
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

func firstMissingProtocol(nodes []protocolNode) string {
        for _, n := range nodes {
                if n.status == "missing" || n.status == "error" {
                        return n.abbrev
                }
        }
        return ""
}

func badgeSVGDetailed(domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash, baseURL string) []byte {
        riskLabel, riskColorName := extractPostureRisk(results)
        riskColorName = normalizeRiskColor(riskLabel, riskColorName)
        nodes := extractProtocolIndicators(results)
        exposure := extractExposure(results)

        riskHex := riskColorToHex(riskColorName)
        riskLabelHex := reportRiskColor(riskColorName)
        borderColor := riskBorderColor(riskColorName)
        missing := countMissing(nodes)

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

        hasExposure := exposure.status == "exposed" && exposure.findingCount > 0

        postureContext := ""
        if missing > 0 {
                first := firstMissingProtocol(nodes)
                if first != "" {
                        postureContext = fmt.Sprintf("%d/9 controls missing — %s not found", missing, first)
                } else {
                        postureContext = fmt.Sprintf("%d/9 controls missing", missing)
                }
        } else {
                postureContext = "All 9 controls verified"
        }

        const (
                width = 540
                pad   = 16
                nodeR = 16
        )
        height := 230
        if hasExposure {
                height = 260
        }

        reportURL := fmt.Sprintf("%s/analyze?domain=%s", baseURL, domain)

        owlCX := 70
        owlCY := 110

        type nodePos struct {
                x, y int
        }
        nodePositions := []nodePos{
                {250, 78},
                {332, 78},
                {414, 78},
                {250, 178},
                {373, 178},
                {310, 128},
                {414, 128},
                {496, 78},
                {496, 178},
        }

        type topoEdge struct {
                from, to int
                label    string
                hard     bool
                labelX   int
                labelY   int
        }
        edges := []topoEdge{
                {2, 0, "alignment", true, 291, 66},
                {2, 1, "", true, 0, 0},
                {7, 2, "p=quarantine+", true, 455, 66},
                {6, 5, "reports", false, 362, 118},
                {6, 4, "", false, 0, 0},
                {4, 3, "requires", true, 311, 168},
                {8, 3, "strengthens", false, 440, 168},
        }

        icieCX := 200
        icieCY := 54
        icieR := 11
        resolverCX := 136
        resolverCY := 54
        resolverW := 52
        resolverH := 16

        var nodeSVG strings.Builder

        resolverColor := "#5c6bc0"
        icieColor := "#e0e0e0"

        nodeSVG.WriteString(fmt.Sprintf(
                `<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1"/>`,
                resolverCX-resolverW/2, resolverCY-resolverH/2, resolverW, resolverH, resolverColor, resolverColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="7" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">Resolvers</text>`,
                resolverCX, resolverCY+3, resolverColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.10" stroke="%s" stroke-opacity="0.45" stroke-width="1.2"/>`,
                icieCX, icieCY, icieR, icieColor, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="7" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">ICIE</text>`,
                icieCX, icieCY+3, icieColor,
        ))

        nodeSVG.WriteString(fmt.Sprintf(
                `<path d="M%d,%d L%d,%d" fill="none" stroke="%s" stroke-opacity="0.3" stroke-width="1" stroke-dasharray="3 2"/>`,
                resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY, icieColor,
        ))
        nodeSVG.WriteString(fmt.Sprintf(
                `<circle r="1.5" fill="%s" opacity="0.7"><animateMotion dur="1.2s" repeatCount="indefinite" path="M%d,%d L%d,%d"/></circle>`,
                icieColor, resolverCX+resolverW/2, resolverCY, icieCX-icieR, icieCY,
        ))

        type fanTarget struct {
                x, y int
        }
        fanTargetIdx := []int{0, 5, 3}
        fanTargets := []fanTarget{
                {nodePositions[0].x, nodePositions[0].y},
                {nodePositions[5].x, nodePositions[5].y},
                {nodePositions[3].x, nodePositions[3].y},
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
                targetColor := protocolGroupColor(nodes[fanTargetIdx[fi]].abbrev)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<path d="M%.0f,%.0f L%.0f,%.0f" fill="none" stroke="%s" stroke-opacity="0.15" stroke-width="1" stroke-dasharray="3 2"/>`,
                        startX, startY, endX, endY, targetColor,
                ))
                dur := fmt.Sprintf("%.1fs", 2.0+float64(fi)*0.5)
                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle r="1.5" fill="%s" opacity="0.5"><animateMotion dur="%s" repeatCount="indefinite" path="M%.0f,%.0f L%.0f,%.0f"/></circle>`,
                        targetColor, dur, startX, startY, endX, endY,
                ))
        }

        for _, e := range edges {
                if e.from >= len(nodes) || e.to >= len(nodes) {
                        continue
                }
                fp := nodePositions[e.from]
                tp := nodePositions[e.to]
                dn := nodes[e.to]

                groupColor := protocolGroupColor(dn.abbrev)
                lineColor := groupColor
                lineOpacity := "0.15"
                lineW := 1.5
                packetColor := groupColor
                if dn.status == "success" || dn.status == "warning" {
                        lineColor = dn.colorHex
                        lineOpacity = "0.35"
                        lineW = 1.5
                        packetColor = dn.colorHex
                } else if dn.status == "error" {
                        lineColor = hexRed
                        lineOpacity = "0.3"
                        packetColor = hexRed
                }

                pathD := fmt.Sprintf("M%d,%d L%d,%d", fp.x, fp.y, tp.x, tp.y)
                dashArray := "4 6"
                if e.hard {
                        dashArray = "none"
                }
                nodeSVG.WriteString(fmt.Sprintf(
                        `<path d="%s" fill="none" stroke="%s" stroke-opacity="%s" stroke-width="%.1f" stroke-dasharray="%s"/>`,
                        pathD, lineColor, lineOpacity, lineW, dashArray,
                ))

                arrowDx := float64(tp.x - fp.x)
                arrowDy := float64(tp.y - fp.y)
                dist := math.Sqrt(arrowDx*arrowDx + arrowDy*arrowDy)
                if dist > 0 {
                        nx := arrowDx / dist
                        ny := arrowDy / dist
                        arrowR := float64(nodeR) + 3
                        arrowTipX := float64(tp.x) - nx*arrowR
                        arrowTipY := float64(tp.y) - ny*arrowR
                        perpX := -ny * 3.5
                        perpY := nx * 3.5
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s" fill-opacity="%s"/>`,
                                arrowTipX, arrowTipY,
                                arrowTipX-nx*7+perpX, arrowTipY-ny*7+perpY,
                                arrowTipX-nx*7-perpX, arrowTipY-ny*7-perpY,
                                lineColor, lineOpacity,
                        ))
                }

                if e.label != "" && e.labelX > 0 {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" text-anchor="middle" fill="#8b949e" font-size="7" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                                e.labelX, e.labelY, e.label,
                        ))
                }

                if dn.status == "success" || dn.status == "warning" {
                        dur := fmt.Sprintf("%.1fs", 1.8+float64(e.from)*0.3)
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle r="2" fill="%s" opacity="0.8"><animateMotion dur="%s" repeatCount="indefinite" path="%s"/></circle>`,
                                packetColor, dur, pathD,
                        ))
                }
        }

        var glowDefs strings.Builder
        for i, n := range nodes {
                if i >= len(nodePositions) {
                        break
                }
                pos := nodePositions[i]

                nodeColor := n.groupColor
                strokeColor := n.groupColor
                fillOpacity := "0.10"
                strokeOpacity := "0.45"
                strokeW := 1.5
                glowOpacity := "0.10"
                textColor := "#e6edf3"

                if n.status == "error" || n.status == "missing" {
                        nodeColor = hexRed
                        strokeColor = hexRed
                        fillOpacity = "0.06"
                        strokeOpacity = "0.25"
                        strokeW = 1
                        glowOpacity = "0.06"
                        textColor = hexRed
                } else if n.status == "warning" {
                        fillOpacity = "0.14"
                        strokeOpacity = "0.55"
                        glowOpacity = "0.12"
                } else if n.status == "success" {
                        fillOpacity = "0.14"
                        strokeOpacity = "0.55"
                        glowOpacity = "0.12"
                }

                glowDefs.WriteString(fmt.Sprintf(
                        `<radialGradient id="ng%d" cx="%d" cy="%d" r="%d" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%s" stop-opacity="%s"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>`,
                        i, pos.x, pos.y, nodeR+8, nodeColor, glowOpacity, nodeColor,
                ))

                abbrevSize := 8
                if len(n.abbrev) > 4 {
                        abbrevSize = 7
                }
                if len(n.abbrev) > 6 {
                        abbrevSize = 6
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="url(#ng%d)"/>`,
                        pos.x, pos.y, nodeR+8, i,
                ))

                if n.status == "success" || n.status == "warning" {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="0.04"><animate attributeName="r" values="%d;%d;%d" dur="3s" repeatCount="indefinite"/><animate attributeName="fill-opacity" values="0.04;0.08;0.04" dur="3s" repeatCount="indefinite"/></circle>`,
                                pos.x, pos.y, nodeR+6, nodeColor, nodeR+6, nodeR+10, nodeR+6,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<circle cx="%d" cy="%d" r="%d" fill="%s" fill-opacity="%s" stroke="%s" stroke-opacity="%s" stroke-width="%.1f"/>`,
                        pos.x, pos.y, nodeR, nodeColor, fillOpacity, strokeColor, strokeOpacity, strokeW,
                ))

                if n.status == "missing" || n.status == "error" {
                        xOff := 5
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5" stroke-linecap="round"/>`,
                                pos.x-xOff, pos.y-xOff, pos.x+xOff, pos.y+xOff, hexRed,
                        ))
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5" stroke-linecap="round"/>`,
                                pos.x+xOff, pos.y-xOff, pos.x-xOff, pos.y+xOff, hexRed,
                        ))
                }

                nodeSVG.WriteString(fmt.Sprintf(
                        `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                        pos.x, pos.y+3, textColor, abbrevSize, n.abbrev,
                ))
        }

        missingSVG := ""
        if missing > 0 {
                missingSVG = fmt.Sprintf(
                        `<text x="%d" y="%d" fill="%s" font-size="9" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%d of 9 missing</text>`,
                        width-pad, 198, hexRed, missing,
                )
        }

        exposureSVG := ""
        exposureAnchor := fmt.Sprintf("%s/analysis/%d/view/C#secret-exposure", baseURL, scanID)
        if hasExposure {
                label := fmt.Sprintf("⚠ %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
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

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Tool: %s — %s">
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
  <text x="%d" y="%d" fill="%s" font-size="11" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="%d" fill="#8b949e" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  <text x="228" y="58" fill="#8b949e" font-size="7" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.6">AUTH</text>
  <text x="228" y="108" fill="#8b949e" font-size="7" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.6">TRANSPORT</text>
  <text x="228" y="158" fill="#8b949e" font-size="7" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="start" opacity="0.6">DNS</text>
  <line x1="228" y1="60" x2="524" y2="60" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="108" x2="450" y2="108" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>
  <line x1="228" y1="158" x2="524" y2="158" stroke="#21262d" stroke-width="0.5" stroke-dasharray="2 3"/>

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
                width, height, width, height,
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
                owlCX-40, owlCY-40, owlBadgePNG,
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
