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
        score := extractPostureScore(results)
        exposure := extractExposure(results)
        style := c.DefaultQuery("style", "flat")

        compactValue := riskLabel
        if score >= 0 {
                compactValue = fmt.Sprintf("%s (%d/100)", riskLabel, score)
        }
        if exposure.status == "exposed" && exposure.findingCount > 0 {
                compactValue += fmt.Sprintf(" · %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
                riskHex = "#f85149"
        }

        c.Header("Cache-Control", "public, max-age=3600, s-maxage=3600")
        c.Header("Expires", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGCovert(domain, results, scanTime))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, badgeSVGDetailed(domain, results, scanTime))
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
                return "#3fb950"
        case "warning":
                return "#d29922"
        case "danger":
                return colorDanger
        default:
                return colorGrey
        }
}

func scotopicRiskColor(color string) string {
        switch color {
        case "success":
                return "#58E790"
        case "warning":
                return "#C7C400"
        case "danger":
                return "#B43C29"
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
                return "#30363d"
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
        prefix  string
        text    string
        color   string
}

func covertProtocolLine(abbrev, status string) covertLine {
        pad := 10 - len(abbrev)
        if pad < 1 {
                pad = 1
        }
        dots := strings.Repeat(".", pad)

        vuln := "#B43C29"
        locked := "#58E790"
        partial := "#C7C400"

        switch abbrev {
        case "SPF":
                if status == "success" {
                        return covertLine{"[+]", "SPF " + dots + " can't forge sender envelope", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "SPF " + dots + " partial — spoofing harder", partial}
                }
                return covertLine{"[-]", "SPF " + dots + " sender spoofing possible", vuln}
        case "DKIM":
                if status == "success" {
                        return covertLine{"[+]", "DKIM " + dots + " can't forge signatures", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "DKIM " + dots + " weak key — forgery harder", partial}
                }
                return covertLine{"[-]", "DKIM " + dots + " message forgery possible", vuln}
        case "DMARC":
                if status == "success" {
                        return covertLine{"[+]", "DMARC " + dots + " spoofing rejected at gate", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "DMARC " + dots + " monitoring only — not blocking", partial}
                }
                return covertLine{"[-]", "DMARC " + dots + " email spoofing wide open", vuln}
        case "DNSSEC":
                if status == "success" {
                        return covertLine{"[+]", "DNSSEC " + dots + " can't poison DNS cache", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "DNSSEC " + dots + " partial — some zones exposed", partial}
                }
                return covertLine{"[-]", "DNSSEC " + dots + " DNS cache poisoning possible", vuln}
        case "DANE":
                if status == "success" {
                        return covertLine{"[+]", "DANE " + dots + " can't downgrade TLS", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "DANE " + dots + " TLSA present but weak", partial}
                }
                return covertLine{"[-]", "DANE " + dots + " TLS downgrade possible", vuln}
        case "MTA-STS":
                if status == "success" {
                        return covertLine{"[+]", "MTA-STS " + dots + " can't intercept mail", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "MTA-STS " + dots + " testing mode — not enforcing", partial}
                }
                return covertLine{"[-]", "MTA-STS " + dots + " mail interception possible", vuln}
        case "TLS-RPT":
                if status == "success" {
                        return covertLine{"[+]", "TLS-RPT " + dots + " transport monitored", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "TLS-RPT " + dots + " partial reporting", partial}
                }
                return covertLine{"[-]", "TLS-RPT " + dots + " no transport monitoring", vuln}
        case "BIMI":
                if status == "success" {
                        return covertLine{"[+]", "BIMI " + dots + " brand verification active", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "BIMI " + dots + " present but no VMC cert", partial}
                }
                return covertLine{"[-]", "BIMI " + dots + " brand impersonation possible", vuln}
        case "CAA":
                if status == "success" {
                        return covertLine{"[+]", "CAA " + dots + " cert issuance locked", locked}
                }
                if status == "warning" {
                        return covertLine{"[~]", "CAA " + dots + " policy present but weak", partial}
                }
                return covertLine{"[-]", "CAA " + dots + " anyone can issue certs", vuln}
        default:
                return covertLine{"[?]", abbrev + " " + dots + " unknown", "#664d2e"}
        }
}

func badgeSVGCovert(domain string, results map[string]any, scanTime time.Time) []byte {
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
                monoFont = "'JetBrains Mono','Fira Code','SF Mono','Courier New',monospace"
        )

        amber := "#9C7645"
        dimAmber := "#664d2e"
        vuln := "#B43C29"
        locked := "#58E790"
        dimLocked := "#2d7a47"
        partial := "#C7C400"
        exposureHi := "#DD7975"
        exposureBright := "#ff6b6b"

        var lines []covertLine

        lines = append(lines, covertLine{"", fmt.Sprintf("┌──(kali㉿kali)-[~/recon/%s]", domainDisplay), dimAmber})
        lines = append(lines, covertLine{"", fmt.Sprintf("└─$ dnstool -R %s", domainDisplay), amber})
        lines = append(lines, covertLine{"", "", ""})

        lines = append(lines, covertLine{"[*]", fmt.Sprintf("Target: %s", domainDisplay), amber})
        lines = append(lines, covertLine{"[*]", fmt.Sprintf("Score: %s/100 — %s", scoreText, covertLabel), scotopicRiskColor(riskColorName)})
        lines = append(lines, covertLine{"", "", ""})

        protocols := []string{"SPF", "DKIM", "DMARC", "DNSSEC", "DANE", "MTA-STS", "TLS-RPT", "BIMI", "CAA"}
        for i, p := range protocols {
                if i < len(nodes) {
                        lines = append(lines, covertProtocolLine(p, nodes[i].status))
                }
        }

        if exposure.status == "exposed" && exposure.findingCount > 0 {
                lines = append(lines, covertLine{"", "", ""})
                lines = append(lines, covertLine{"", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", vuln})
                lines = append(lines, covertLine{"[!!]", fmt.Sprintf("SECRET EXPOSURE — %d credential%s found", exposure.findingCount, pluralS(exposure.findingCount)), exposureBright})
                lines = append(lines, covertLine{"", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", vuln})
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
                        lines = append(lines, covertLine{"[!!]", fmt.Sprintf("  >>> %s: %s%s", label, redacted, sevTag), exposureHi})
                }
                lines = append(lines, covertLine{"[!!]", "  Credentials are publicly accessible.", exposureHi})
        }

        lines = append(lines, covertLine{"", "", ""})

        if vulnerable == 0 && exposure.findingCount == 0 {
                lines = append(lines, covertLine{"[!]", "All 9 protocols configured — target is hardened", locked})
                lines = append(lines, covertLine{"[!]", tagline, dimLocked})
        } else if vulnerable == 0 && exposure.findingCount > 0 {
                lines = append(lines, covertLine{"[!]", "Protocols hardened — but secrets are leaking", exposureBright})
                lines = append(lines, covertLine{"[!]", "Rotate exposed credentials immediately.", exposureHi})
        } else if vulnerable <= 2 {
                lines = append(lines, covertLine{"[!]", fmt.Sprintf("%d attack vector%s available — mostly locked down", vulnerable, pluralS(vulnerable)), partial})
                if exposure.findingCount > 0 {
                        lines = append(lines, covertLine{"[!]", "Leaked secrets make protocol gaps worse.", exposureHi})
                } else if tagline != "" {
                        lines = append(lines, covertLine{"[!]", tagline, dimAmber})
                }
        } else {
                lines = append(lines, covertLine{"[!]", fmt.Sprintf("%d of 9 attack vectors available", vulnerable), vuln})
                if exposure.findingCount > 0 {
                        lines = append(lines, covertLine{"[!]", "Leaked secrets on top of open vectors.", exposureBright})
                } else if tagline != "" {
                        lines = append(lines, covertLine{"[!]", tagline, vuln})
                }
        }

        lines = append(lines, covertLine{"", "", ""})
        lines = append(lines, covertLine{"", fmt.Sprintf("[*] Scan: %s — dnstool.it-help.tech", scanDate), dimAmber})

        height := len(lines)*lineH + 24

        var svg strings.Builder

        svg.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Recon: %s — %s">
  <title>DNS Recon: %s — %s</title>
  <defs>
    <linearGradient id="tbg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1a0505"/>
      <stop offset="1" stop-color="#0a0000"/>
    </linearGradient>
  </defs>
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
  <text x="60" y="13" fill="%s" font-size="9" font-family=%s>kali@kali: ~/recon/%s</text>`,
                dimAmber, `"`+monoFont+`"`, domainDisplay,
        ))

        y := 32
        for _, line := range lines {
                if line.text == "" && line.prefix == "" {
                        y += lineH / 2
                        continue
                }

                color := line.color
                if color == "" {
                        color = dimAmber
                }

                if line.prefix != "" {
                        prefixColor := dimAmber
                        if line.prefix == "[+]" {
                                prefixColor = dimLocked
                        } else if line.prefix == "[~]" {
                                prefixColor = "#8a8a00"
                        } else if line.prefix == "[-]" {
                                prefixColor = "#7a2419"
                        } else if line.prefix == "[!!]" {
                                prefixColor = exposureBright
                        } else if line.prefix == "[*]" {
                                prefixColor = dimAmber
                        } else if line.prefix == "[!]" {
                                prefixColor = amber
                        }
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                xPad, y, prefixColor, fontSize, monoFont, line.prefix,
                        ))
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                xPad+28, y, color, fontSize, monoFont, line.text,
                        ))
                } else {
                        svg.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" fill="%s" font-size="%d" font-family="%s">%s</text>`,
                                xPad, y, color, fontSize, monoFont, line.text,
                        ))
                }
                y += lineH
        }

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
                {"tlsrpt_analysis", "TLS-RPT"},
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
        exposure := extractExposure(results)

        sc := scoreColor(score)
        riskHex := riskColorToHex(riskColorName)
        borderColor := riskBorderColor(riskColorName)
        missing := countMissing(nodes)

        domainDisplay := domain
        if len(domainDisplay) > 30 {
                domainDisplay = domainDisplay[:27] + "..."
        }

        scanDate := scanTime.UTC().Format("2006-01-02")

        const (
                width  = 460
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
                {148, 60},
                {208, 60},
                {268, 60},
                {356, 60},
                {356, 100},
                {148, 100},
                {208, 100},
                {268, 100},
                {148, 140},
        }

        var nodeSVG strings.Builder

        connLines := [][4]int{
                {148, 60, 208, 60},
                {208, 60, 268, 60},
                {148, 100, 208, 100},
                {268, 100, 356, 100},
                {268, 60, 268, 100},
                {356, 60, 356, 100},
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

                r := 17
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
                        fillOpacity = "0.12"
                        strokeColor = "#f85149"
                        strokeW = 2
                } else {
                        fillColor = "#f8514910"
                        fillOpacity = "0.05"
                        strokeColor = "#f85149"
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

                if n.status == "missing" || n.status == "error" {
                        xOff := 5
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#f85149" stroke-width="1.5" stroke-linecap="round"/>`,
                                pos.x-xOff, pos.y-xOff, pos.x+xOff, pos.y+xOff,
                        ))
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#f85149" stroke-width="1.5" stroke-linecap="round"/>`,
                                pos.x+xOff, pos.y-xOff, pos.x-xOff, pos.y+xOff,
                        ))
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" text-anchor="middle" fill="#f85149" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" opacity="0.6">%s</text>`,
                                pos.x, pos.y+r+10, abbrevSize, n.abbrev,
                        ))
                } else {
                        nodeSVG.WriteString(fmt.Sprintf(
                                `<text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="%d" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>`,
                                pos.x, pos.y+3, strokeColor, abbrevSize, n.abbrev,
                        ))
                }
        }

        missingSVG := ""
        if missing > 0 {
                missingSVG = fmt.Sprintf(
                        `<text x="%d" y="%d" fill="#f85149" font-size="9" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%d of 9 missing</text>`,
                        width-pad, 170, missing,
                )
        }

        exposureSVG := ""
        if exposure.status == "exposed" && exposure.findingCount > 0 {
                label := fmt.Sprintf("⚠ %d secret%s exposed", exposure.findingCount, pluralS(exposure.findingCount))
                yPos := 158
                if missing > 0 {
                        yPos = 158
                }
                exposureSVG = fmt.Sprintf(
                        `<rect x="%d" y="%d" width="%d" height="16" rx="3" fill="#f85149" fill-opacity="0.12"/>
  <text x="%d" y="%d" fill="#ff6b6b" font-size="8" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>`,
                        width-pad-len(label)*5-4, yPos-11, len(label)*5+8,
                        width-pad, yPos, label,
                )
        }

        svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="DNS Tool: %s — %s (Score: %s)">
  <title>DNS Tool: %s — %s (Score: %s)</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#161b22"/>
      <stop offset="1" stop-color="#0d1117"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%%" cy="50%%" r="50%%">
      <stop offset="0" stop-color="%s" stop-opacity=".08"/>
      <stop offset="1" stop-color="%s" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="%d" height="%d" rx="8" fill="url(#bg)"/>
  <rect x="1" y="1" width="%d" height="%d" rx="8" fill="none" stroke="%s" stroke-width="1.5"/>

  <circle cx="%d" cy="%d" r="60" fill="url(#glow)"/>

  <text x="%d" y="26" fill="#e6edf3" font-size="14" font-weight="700" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>
  <text x="%d" y="26" fill="#484f58" font-size="10" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">%s</text>

  <line x1="%d" y1="34" x2="%d" y2="34" stroke="#21262d" stroke-width="1"/>

  <path d="%s" fill="none" stroke="#21262d" stroke-width="6" stroke-linecap="round"/>
  <path d="%s" fill="none" stroke="%s" stroke-width="6" stroke-linecap="round"/>

  <text x="%d" y="%d" text-anchor="middle" fill="%s" font-size="22" font-weight="700" font-family="'JetBrains Mono','Fira Code','SF Mono',monospace">%s</text>
  <text x="%d" y="%d" text-anchor="middle" fill="#484f58" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">/ 100</text>

  <rect x="%d" y="%d" width="3" height="14" rx="1.5" fill="%s"/>
  <text x="%d" y="%d" fill="%s" font-size="11" font-weight="600" font-family="'Inter','Segoe UI',system-ui,sans-serif">%s</text>

  <text x="126" y="46" fill="#6e7681" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">Email Auth</text>
  <text x="330" y="46" fill="#6e7681" font-size="8" font-family="'Inter','Segoe UI',system-ui,sans-serif">Integrity</text>

  %s

  %s

  %s

  <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif">dnstool.it-help.tech</text>
  <text x="%d" y="%d" fill="#30363d" font-size="9" font-family="'Inter','Segoe UI',system-ui,sans-serif" text-anchor="end">Scanned %s</text>
</svg>`,
                width, height, width, height,
                domain, riskLabel, scoreText,
                domain, riskLabel, scoreText,
                sc, sc,
                width, height,
                width-2, height-2, borderColor,
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
                missingSVG,
                exposureSVG,
                pad, height-6,
                width-pad, height-6, scanDate,
        )

        return []byte(svg)
}
