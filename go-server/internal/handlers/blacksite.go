// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "fmt"
        "log/slog"
        "net/http"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

type BlackSiteHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewBlackSiteHandler(database *db.Database, cfg *config.Config) *BlackSiteHandler {
        return &BlackSiteHandler{DB: database, Config: cfg}
}

type findingView struct {
        PublicID       string
        Kind           string
        Domain         string
        Title          string
        SymptomMD      string
        HypothesisMD   string
        RootCauseMD    string
        Severity       int
        SeverityLabel  string
        Priority       int
        PriorityLabel  string
        Status         string
        StatusDisplay  string
        StatusCSS      string
        EvidenceGrade  string
        Confidence     string
        BlastRadius    string
        Visibility     string
        SourceTeam     string
        LegacyBsiID    string
        FingerprintSHA string
}

type eventView struct {
        PublicID  string
        Title     string
        Severity  int
        Actor     string
        EventType string
        ToStatus  string
        CommitSHA string
        NoteMD    string
        CreatedAt string
}

var severityLabels = map[int]string{
        0: "S0 — Red Notice",
        1: "S1 — Critical Path",
        2: "S2 — Major",
        3: "S3 — Contained",
        4: "S4 — Minor",
}

var priorityLabels = map[int]string{
        0: "P0",
        1: "P1",
        2: "P2",
        3: "P3",
}

var statusDisplay = map[string]string{
        "DETAINED":             "Detained",
        "VERIFIED":             "Verified",
        "UNDER_INTERROGATION":  "Under Interrogation",
        "CONTAINED":            "Contained",
        "RENDERED":             "Rendered",
        "REGRESSED":            "Regressed",
        "EXTRADITED":           "Extradited",
        "DISMISSED":            "Dismissed",
}

var statusCSS = map[string]string{
        "DETAINED":             "detained",
        "VERIFIED":             "verified",
        "UNDER_INTERROGATION":  "interrogation",
        "CONTAINED":            "contained",
        "RENDERED":             "rendered",
        "REGRESSED":            "regressed",
        "EXTRADITED":           "extradited",
        "DISMISSED":            "dismissed",
}

func (h *BlackSiteHandler) BlackSite(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        ctx := c.Request.Context()

        findings, err := h.DB.Queries.ListFindings(ctx)
        if err != nil {
                slog.Warn("black-site: failed to list findings", "error", err)
        }

        sevCounts, err := h.DB.Queries.CountFindingsBySeverity(ctx)
        if err != nil {
                slog.Warn("black-site: failed to count by severity", "error", err)
        }

        kindCounts, err := h.DB.Queries.CountFindingsByKind(ctx)
        if err != nil {
                slog.Warn("black-site: failed to count by kind", "error", err)
        }

        statusCounts, err := h.DB.Queries.CountFindingsByStatus(ctx)
        if err != nil {
                slog.Warn("black-site: failed to count by status", "error", err)
        }

        totalRow, err := h.DB.Queries.CountFindingsTotal(ctx)
        if err != nil {
                slog.Warn("black-site: failed to count total", "error", err)
        }

        eventsRaw, err := h.DB.Queries.ListFindingEvents(ctx)
        if err != nil {
                slog.Warn("black-site: failed to list events", "error", err)
        }

        s0 := []findingView{}
        s1 := []findingView{}
        s2 := []findingView{}
        s3 := []findingView{}
        s4 := []findingView{}

        for _, f := range findings {
                sev := int(f.Severity)
                conf := "—"
                if f.Confidence.Valid {
                        fl, fErr := f.Confidence.Float64Value()
                        if fErr == nil && fl.Valid {
                                conf = fmt.Sprintf("%.0f%%", fl.Float64*100)
                        }
                }
                fpShort := f.FingerprintSha256
                if len(fpShort) > 8 {
                        fpShort = fpShort[:8]
                }

                fv := findingView{
                        PublicID:       f.PublicID,
                        Kind:           f.Kind,
                        Domain:         f.Domain,
                        Title:          f.Title,
                        SymptomMD:      f.SymptomMd,
                        HypothesisMD:   stringOrEmpty(f.HypothesisMd),
                        RootCauseMD:    stringOrEmpty(f.RootCauseMd),
                        Severity:       sev,
                        SeverityLabel:  severityLabels[sev],
                        Priority:       int(f.Priority),
                        PriorityLabel:  priorityLabels[int(f.Priority)],
                        Status:         f.Status,
                        StatusDisplay:  statusDisplay[f.Status],
                        StatusCSS:      statusCSS[f.Status],
                        EvidenceGrade:  f.EvidenceGrade,
                        Confidence:     conf,
                        BlastRadius:    f.BlastRadius,
                        Visibility:     f.Visibility,
                        SourceTeam:     f.SourceTeam,
                        LegacyBsiID:    stringOrEmpty(f.LegacyBsiID),
                        FingerprintSHA: fpShort,
                }
                switch sev {
                case 0:
                        s0 = append(s0, fv)
                case 1:
                        s1 = append(s1, fv)
                case 2:
                        s2 = append(s2, fv)
                case 3:
                        s3 = append(s3, fv)
                case 4:
                        s4 = append(s4, fv)
                }
        }

        sevMap := map[int16]int64{}
        for _, sc := range sevCounts {
                sevMap[sc.Severity] = sc.Count
        }

        kindMap := map[string]int64{}
        for _, kc := range kindCounts {
                kindMap[kc.Kind] = kc.Count
        }

        statusMap := map[string]int64{}
        for _, sc := range statusCounts {
                statusMap[sc.Status] = sc.Count
        }

        events := []eventView{}
        for _, e := range eventsRaw {
                ev := eventView{
                        PublicID:  e.PublicID,
                        Title:     e.Title,
                        Severity:  int(e.Severity),
                        Actor:     e.Actor,
                        EventType: e.EventType,
                        CommitSHA: stringOrEmpty(e.CommitSha),
                        NoteMD:    stringOrEmpty(e.NoteMd),
                }
                if e.ToStatus != nil {
                        ev.ToStatus = *e.ToStatus
                }
                if e.CreatedAt.Valid {
                        ev.CreatedAt = e.CreatedAt.Time.Format("2006-01-02")
                }
                events = append(events, ev)
        }

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "ActivePage":      "black-site",

                "S0Findings": s0,
                "S1Findings": s1,
                "S2Findings": s2,
                "S3Findings": s3,
                "S4Findings": s4,

                "S0Count":     sevMap[0],
                "S1Count":     sevMap[1],
                "S2Count":     sevMap[2],
                "S3Count":     sevMap[3],
                "S4Count":     sevMap[4],
                "TotalCount":  totalRow,

                "DefectCount":         kindMap["defect"],
                "WeaknessCount":       kindMap["weakness"],
                "ComplianceGapCount":  kindMap["compliance_gap"],
                "ClaimIntegrityCount": kindMap["claim_integrity"],
                "DesignDebtCount":     kindMap["design_debt"],
                "IncidentCount":       kindMap["incident"],

                "DetainedCount":  statusMap["DETAINED"],
                "RenderedCount":  statusMap["RENDERED"],

                "Events":    events,
                "HasEvents": len(events) > 0,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "black_site.html", data)
}

func stringOrEmpty(s *string) string {
        if s == nil {
                return ""
        }
        return *s
}
