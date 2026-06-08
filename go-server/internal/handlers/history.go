// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/json"
        "net/http"
        "strconv"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/icsae"

        "github.com/gin-gonic/gin"
)

const (
        templateHistory = "history.html"

        mapKeyHistory = "history"
)

type HistoryHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewHistoryHandler(database *db.Database, cfg *config.Config) *HistoryHandler {
        return &HistoryHandler{DB: database, Config: cfg}
}

type historyAnalysisItem struct {
        ID               int32
        Domain           string
        AsciiDomain      string
        SpfStatus        string
        DmarcStatus      string
        DkimStatus       string
        AnalysisDuration float64
        CreatedDate      string
        CreatedTime      string
        ToolVersion      string
        RequestSource    string
        RiskLevel        string
        RiskColor        string
        FixCount         int
        FixColor         string
}

// normalizeRiskColor whitelists the posture color read from persisted
// full_results JSON to a known Bootstrap contextual token before it is
// interpolated into a bg-* class. Stored JSON can drift across versions, so we
// never trust the producer: any unrecognized value falls back to "secondary".
func normalizeRiskColor(color string) string {
        switch color {
        case "success", "info", "warning", "danger":
                return color
        default:
                return "secondary"
        }
}

// postureSliceLen returns the length of a JSON array stored under key in the
// already-decoded posture map, tolerating absent or wrong-typed values.
func postureSliceLen(posture map[string]interface{}, key string) int {
        if arr, ok := posture[key].([]interface{}); ok {
                return len(arr)
        }
        return 0
}

// icsaeFixSummary derives the reality-matched "to Fix" count from a persisted
// ICSAE evaluation. The headline count is RealFixCount: failed controls that
// carry a real, RFC-grounded operational-security consequence for THIS operator.
// Controls absent by deliberate enterprise choice (with strong compensating
// posture), impossible on the operator's mail platform, that we could not verify
// (e.g. DKIM selectors), or optional hardening are sorted into honest context
// buckets and excluded from the headline — so the count stays trustworthy in
// both directions. See icsae.ClassifyFixes. The boolean is false when the scan
// predates ICSAE wiring, so callers can fall back to posture-derived counts.
func icsaeFixSummary(fr map[string]interface{}) (int, string, bool) {
        fc, ok := icsae.ClassifyFromResults(fr)
        if !ok {
                return 0, "", false
        }
        return fc.RealFixCount, fc.Color, true
}

func buildHistoryItem(a dbq.DomainAnalysis) historyAnalysisItem {
        spfStatus := ""
        if a.SpfStatus != nil {
                spfStatus = *a.SpfStatus
        }
        dmarcStatus := ""
        if a.DmarcStatus != nil {
                dmarcStatus = *a.DmarcStatus
        }
        dkimStatus := ""
        if a.DkimStatus != nil {
                dkimStatus = *a.DkimStatus
        }
        dur := 0.0
        if a.AnalysisDuration != nil {
                dur = *a.AnalysisDuration
        }
        createdDate, createdTime := "", ""
        if a.CreatedAt.Valid {
                createdDate = a.CreatedAt.Time.UTC().Format("2 Jan 2006")
                createdTime = a.CreatedAt.Time.UTC().Format("15:04 UTC")
        }
        toolVersion := ""
        requestSource := ""
        riskLevel := ""
        riskColor := ""
        fixCount := 0
        fixColor := ""
        if len(a.FullResults) > 0 {
                var fr map[string]interface{}
                if json.Unmarshal(a.FullResults, &fr) == nil {
                        if tv, ok := fr["_tool_version"].(string); ok {
                                toolVersion = tv
                        }
                        if rs, ok := fr["_request_source"].(string); ok {
                                requestSource = rs
                        }
                        if posture, ok := fr["posture"].(map[string]interface{}); ok {
                                if st, ok := posture["state"].(string); ok {
                                        riskLevel = st
                                }
                                if cl, ok := posture["color"].(string); ok {
                                        riskColor = normalizeRiskColor(cl)
                                }
                        }
                        // Catalog-backed "to Fix" count: the reality-matched RealFixCount from
                        // icsae.ClassifyFixes (failed controls that carry a real, RFC-grounded
                        // consequence for THIS operator; deliberate posture, platform limits,
                        // could-not-verify and hygiene are bucketed out). Falls back to
                        // posture-derived issues for scans recorded before ICSAE was wired in.
                        if c, col, ok := icsaeFixSummary(fr); ok {
                                fixCount = c
                                fixColor = col
                        } else if posture, ok := fr["posture"].(map[string]interface{}); ok {
                                critical := postureSliceLen(posture, "critical_issues")
                                recommendations := postureSliceLen(posture, "recommendations")
                                fixCount = critical + recommendations
                                if critical > 0 {
                                        fixColor = "danger"
                                } else if recommendations > 0 {
                                        fixColor = "warning"
                                }
                        }
                }
        }
        return historyAnalysisItem{
                ID:               a.ID,
                Domain:           a.Domain,
                AsciiDomain:      a.AsciiDomain,
                SpfStatus:        spfStatus,
                DmarcStatus:      dmarcStatus,
                DkimStatus:       dkimStatus,
                AnalysisDuration: dur,
                CreatedDate:      createdDate,
                CreatedTime:      createdTime,
                ToolVersion:      toolVersion,
                RequestSource:    requestSource,
                RiskLevel:        riskLevel,
                RiskColor:        riskColor,
                FixCount:         fixCount,
                FixColor:         fixColor,
        }
}

func (h *HistoryHandler) History(c *gin.Context) {
        page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
        if err != nil {
                page = 1
        }
        if page < 1 {
                page = 1
        }
        searchDomain := c.Query("domain")
        perPage := 20

        ctx := c.Request.Context()

        total, err := h.countAnalyses(ctx, searchDomain)
        if err != nil {
                errData := NewTemplateData(c, h.Config, mapKeyHistory)
                errData["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to count analyses"}}
                c.HTML(http.StatusInternalServerError, templateHistory, errData)
                return
        }

        pagination := NewPagination(page, perPage, total)

        items, err := h.fetchAnalyses(ctx, searchDomain, &pagination)
        if err != nil {
                errData := NewTemplateData(c, h.Config, mapKeyHistory)
                errData["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to fetch analyses"}}
                c.HTML(http.StatusInternalServerError, templateHistory, errData)
                return
        }

        pd := BuildPagination(page, pagination.TotalPages, total)

        data := NewTemplateData(c, h.Config, mapKeyHistory)
        data["Analyses"] = items
        data["Pagination"] = pd
        data["SearchDomain"] = searchDomain
        data["SearchAction"] = "/history"
        data["SearchPlaceholder"] = "Search by domain name..."
        data["SearchAriaLabel"] = "Search history by domain name"
        data["PaginationLabel"] = "Analysis history pagination"
        data["PaginationBase"] = "/history"
        c.HTML(http.StatusOK, templateHistory, data)
}

func (h *HistoryHandler) countAnalyses(ctx context.Context, searchDomain string) (int64, error) {
        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                return h.DB.Queries.CountSearchSuccessfulAnalyses(ctx, searchPattern)
        }
        return h.DB.Queries.CountSuccessfulAnalyses(ctx)
}

func (h *HistoryHandler) fetchAnalyses(ctx context.Context, searchDomain string, pagination *PaginationInfo) ([]historyAnalysisItem, error) {
        var analyses []dbq.DomainAnalysis
        var err error

        if searchDomain != "" {
                searchPattern := "%" + searchDomain + "%"
                analyses, err = h.DB.Queries.SearchSuccessfulAnalyses(ctx, dbq.SearchSuccessfulAnalysesParams{
                        Domain: searchPattern,
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
        } else {
                analyses, err = h.DB.Queries.ListSuccessfulAnalyses(ctx, dbq.ListSuccessfulAnalysesParams{
                        Limit:  pagination.Limit(),
                        Offset: pagination.Offset(),
                })
        }
        if err != nil {
                return nil, err
        }

        items := make([]historyAnalysisItem, 0, len(analyses))
        for _, a := range analyses {
                items = append(items, buildHistoryItem(a))
        }
        return items, nil
}
