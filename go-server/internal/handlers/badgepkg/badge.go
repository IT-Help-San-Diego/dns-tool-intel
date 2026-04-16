// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package badgepkg

import (
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "strconv"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        dbq "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

type TemplateDataFunc func(c *gin.Context, cfg *config.Config, activePage string) gin.H

type LookupStore interface {
        GetAnalysisByID(ctx context.Context, id int32) (dbq.DomainAnalysis, error)
        GetRecentAnalysisByDomain(ctx context.Context, domain string) (dbq.DomainAnalysis, error)
}

const (
        colorDanger    = "#e05d44"
        colorGrey      = "#9f9f9f"
        contentTypeSVG = "image/svg+xml; charset=utf-8"
        labelDNSTool   = "DNS Tool"

        mapKeyColor     = "color"
        mapKeyLabel     = "label"
        mapKeyLightgrey = "lightgrey"
        mapKeyDomain    = "domain"
        mapKeyMessage   = "message"
        mapKeyError     = "error"
        mapKeyStatus    = "status"

        strSchemaversion = "schemaVersion"

        hexRed      = "#f85149"
        hexGreen    = "#3fb950"
        hexYellow   = "#d29922"
        hexScGreen  = "#58E790"
        hexScYellow = "#C7C400"
        hexScRed    = "#B43C29"
        hexDimGrey  = "#30363d"

        labelGatewayDerived = "Gateway Derived"

        protoMTASTS = "MTA-STS"
        protoTLSRPT = "TLS-RPT"
        protoDMARC  = "DMARC"
        protoDNSSEC = "DNSSEC"
)

func derefString(p *string) string {
        if p == nil {
                return ""
        }
        return *p
}

type BadgeHandler struct {
        DB              *db.Database
        Config          *config.Config
        lookupStore     LookupStore
        templateDataFn  TemplateDataFunc
}

func (h *BadgeHandler) store() LookupStore {
        if h.lookupStore != nil {
                return h.lookupStore
        }
        if h.DB != nil {
                return h.DB.Queries
        }
        return nil
}

func defaultBadgeTemplateData() TemplateDataFunc {
        return func(c *gin.Context, cfg *config.Config, activePage string) gin.H {
                return gin.H{}
        }
}

func NewBadgeHandler(database *db.Database, cfg *config.Config, tdFn TemplateDataFunc) *BadgeHandler {
        if tdFn == nil {
                tdFn = defaultBadgeTemplateData()
        }
        return &BadgeHandler{DB: database, Config: cfg, templateDataFn: tdFn}
}

func NewBadgeHandlerWithStore(s LookupStore, cfg *config.Config, tdFn TemplateDataFunc) *BadgeHandler {
        if tdFn == nil {
                tdFn = defaultBadgeTemplateData()
        }
        return &BadgeHandler{Config: cfg, lookupStore: s, templateDataFn: tdFn}
}

func (h *BadgeHandler) SetStore(s LookupStore) {
        h.lookupStore = s
}

func (h *BadgeHandler) resolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, ok bool) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.Data(http.StatusBadRequest, contentTypeSVG, BadgeSVG(mapKeyError, "missing domain or id", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        ctx := c.Request.Context()

        if idQ != "" {
                sid, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        c.Data(http.StatusBadRequest, contentTypeSVG, BadgeSVG(mapKeyError, "invalid scan id", colorDanger))
                        return "", nil, time.Time{}, 0, "", false
                }
                analysis, err := h.store().GetAnalysisByID(ctx, int32(sid))
                if err != nil || analysis.Private {
                        c.Data(http.StatusNotFound, contentTypeSVG, BadgeSVG(labelDNSTool, "scan not found", colorGrey))
                        return "", nil, time.Time{}, 0, "", false
                }
                results := UnmarshalResults(analysis.FullResults, "Badge")
                return analysis.Domain, results, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
        }

        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                c.Data(http.StatusBadRequest, contentTypeSVG, BadgeSVG(mapKeyError, "invalid domain", colorDanger))
                return "", nil, time.Time{}, 0, "", false
        }

        analysis, err := h.store().GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                c.Data(http.StatusNotFound, contentTypeSVG, BadgeSVG(labelDNSTool, "not scanned", colorGrey))
                return "", nil, time.Time{}, 0, "", false
        }
        res := UnmarshalResults(analysis.FullResults, "Badge")
        return ascii, res, analysis.CreatedAt.Time, analysis.ID, derefString(analysis.PostureHash), true
}

func (h *BadgeHandler) Badge(c *gin.Context) {
        domain, results, scanTime, scanID, postureHash, ok := h.resolveAnalysis(c)
        if !ok {
                return
        }
        if results == nil {
                c.Data(http.StatusOK, contentTypeSVG, BadgeSVG(labelDNSTool, "no data", colorGrey))
                return
        }

        riskLabel, riskColor := ExtractPostureRisk(results)
        riskHex := RiskColorToHex(riskColor)
        score := ExtractPostureScore(results)
        exposure := ExtractExposure(results)
        style := c.DefaultQuery("style", "flat")

        if IsGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskHex = hexYellow
                score = -1
        }

        compactValue := riskLabel
        if score >= 0 {
                compactValue = fmt.Sprintf("%s (%d/100)", riskLabel, score)
        }
        if IsGatewayDerivedResult(results) {
                compactValue = "Gateway Derived — attribution limited"
        }
        if exposure.Status == "exposed" && exposure.FindingCount > 0 {
                compactValue += fmt.Sprintf(" · %d secret%s exposed", exposure.FindingCount, PluralS(exposure.FindingCount))
                riskHex = hexRed
        }

        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")

        switch style {
        case "covert":
                c.Data(http.StatusOK, contentTypeSVG, BadgeSVGCovert(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        case "detailed":
                c.Data(http.StatusOK, contentTypeSVG, BadgeSVGDetailed(domain, results, scanTime, scanID, postureHash, h.Config.BaseURL))
        default:
                c.Data(http.StatusOK, contentTypeSVG, BadgeSVG(domain, compactValue, riskHex))
        }
}

func (h *BadgeHandler) BadgeEmbed(c *gin.Context) {
        data := h.templateDataFn(c, h.Config, "")
        data["BaseURL"] = h.Config.BaseURL
        c.HTML(http.StatusOK, "badge_embed.html", data)
}

func UnmarshalResults(fullResults []byte, caller string) map[string]any {
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

func ExtractPostureRisk(results map[string]any) (string, string) {
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

func RiskColorToHex(color string) string {
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

func NormalizeRiskColor(label, color string) string {
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

func ReportRiskColor(color string) string {
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

func ScotopicRiskColor(color string) string {
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

func BadgeSVG(label, value, color string) []byte {
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

func ShieldsErrorJSON(msg string, isError bool) gin.H {
        resp := gin.H{
                strSchemaversion: 1,
                mapKeyLabel:      labelDNSTool,
                mapKeyMessage:    msg,
                mapKeyColor:      mapKeyLightgrey,
        }
        if isError {
                resp["isError"] = true
        }
        return resp
}

func (h *BadgeHandler) BadgeShieldsIO(c *gin.Context) {
        domainQ := strings.TrimSpace(c.Query(mapKeyDomain))
        idQ := strings.TrimSpace(c.Query("id"))

        if domainQ == "" && idQ == "" {
                c.JSON(http.StatusOK, ShieldsErrorJSON("missing domain or id", true))
                return
        }

        results, errResp := h.loadShieldsResults(c.Request.Context(), idQ, domainQ)
        if errResp != nil {
                c.JSON(http.StatusOK, errResp)
                return
        }

        riskLabel, riskColorRaw := ExtractPostureRisk(results)
        if IsGatewayDerivedResult(results) {
                riskLabel = labelGatewayDerived
                riskColorRaw = "warning"
        }
        shieldsColor := RiskColorToShields(riskColorRaw)

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

func (h *BadgeHandler) loadShieldsResults(ctx context.Context, idQ, domainQ string) (map[string]any, gin.H) {
        if idQ != "" {
                scanID, err := strconv.ParseInt(idQ, 10, 32)
                if err != nil {
                        return nil, ShieldsErrorJSON("invalid scan id", true)
                }
                analysis, err := h.store().GetAnalysisByID(ctx, int32(scanID))
                if err != nil || analysis.Private {
                        return nil, ShieldsErrorJSON("scan not found", false)
                }
                return UnmarshalResults(analysis.FullResults, "BadgeShieldsIO"), nil
        }
        ascii, err := dnsclient.DomainToASCII(domainQ)
        if err != nil || !dnsclient.ValidateDomain(ascii) {
                return nil, ShieldsErrorJSON("invalid domain", true)
        }
        analysis, err := h.store().GetRecentAnalysisByDomain(ctx, ascii)
        if err != nil || analysis.Private {
                return nil, ShieldsErrorJSON("not scanned", false)
        }
        return UnmarshalResults(analysis.FullResults, "BadgeShieldsIO"), nil
}

func RiskColorToShields(color string) string {
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

func CovertRiskLabel(riskLabel string) string {
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

func CovertTagline(riskLabel string) string {
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

func RiskBorderColor(riskColorName string) string {
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

func CountMissing(nodes []ProtocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.Status == "missing" || n.Status == "error" {
                        count++
                }
        }
        return count
}

func CountVulnerable(nodes []ProtocolNode) int {
        count := 0
        for _, n := range nodes {
                if n.Status != "success" && n.Status != "warning" && n.Status != "info" {
                        count++
                }
        }
        return count
}

