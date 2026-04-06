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
        "dnstool/go-server/internal/dbq"

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
        "DETAINED":            "Detained",
        "VERIFIED":            "Verified",
        "UNDER_INTERROGATION": "Under Interrogation",
        "CONTAINED":           "Contained",
        "RENDERED":            "Rendered",
        "REGRESSED":           "Regressed",
        "EXTRADITED":          "Extradited",
        "DISMISSED":           "Dismissed",
}

var statusCSS = map[string]string{
        "DETAINED":            "detained",
        "VERIFIED":            "verified",
        "UNDER_INTERROGATION": "interrogation",
        "CONTAINED":           "contained",
        "RENDERED":            "rendered",
        "REGRESSED":           "regressed",
        "EXTRADITED":          "extradited",
        "DISMISSED":           "dismissed",
}

func (h *BlackSiteHandler) BlackSite(c *gin.Context) {
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

        sevBuckets := bucketBySeverity(findings)
        sevMap := buildSeverityMap(sevCounts)
        kindMap := buildKindMap(kindCounts)
        stMap := buildStatusMap(statusCounts)
        allEvents := buildEventViews(eventsRaw)

        recentCut := 25
        if recentCut > len(allEvents) {
                recentCut = len(allEvents)
        }
        recentEvents := allEvents[:recentCut]
        archiveEvents := allEvents[recentCut:]

        data := NewTemplateData(c, h.Config, "black-site")
        data["S0Findings"] = sevBuckets[0]
        data["S1Findings"] = sevBuckets[1]
        data["S2Findings"] = sevBuckets[2]
        data["S3Findings"] = sevBuckets[3]
        data["S4Findings"] = sevBuckets[4]
        data["S0Count"] = sevMap[0]
        data["S1Count"] = sevMap[1]
        data["S2Count"] = sevMap[2]
        data["S3Count"] = sevMap[3]
        data["S4Count"] = sevMap[4]
        data["TotalCount"] = totalRow
        data["DefectCount"] = kindMap["defect"]
        data["WeaknessCount"] = kindMap["weakness"]
        data["ComplianceGapCount"] = kindMap["compliance_gap"]
        data["ClaimIntegrityCount"] = kindMap["claim_integrity"]
        data["DesignDebtCount"] = kindMap["design_debt"]
        data["IncidentCount"] = kindMap["incident"]
        data["DetainedCount"] = stMap["DETAINED"]
        data["RenderedCount"] = stMap["RENDERED"]
        data["RecentEvents"] = recentEvents
        data["ArchiveEvents"] = archiveEvents
        data["ArchiveEventCount"] = len(archiveEvents)
        data["TotalEventCount"] = len(allEvents)
        data["HasEvents"] = len(allEvents) > 0
        c.HTML(http.StatusOK, "black_site.html", data)
}

func toFindingView(f dbq.Finding) findingView {
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
        return findingView{
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
}

func bucketBySeverity(findings []dbq.Finding) map[int][]findingView {
        buckets := map[int][]findingView{0: {}, 1: {}, 2: {}, 3: {}, 4: {}}
        for _, f := range findings {
                fv := toFindingView(f)
                buckets[fv.Severity] = append(buckets[fv.Severity], fv)
        }
        return buckets
}

func buildSeverityMap(counts []dbq.CountFindingsBySeverityRow) map[int16]int64 {
        m := map[int16]int64{}
        for _, sc := range counts {
                m[sc.Severity] = sc.Count
        }
        return m
}

func buildKindMap(counts []dbq.CountFindingsByKindRow) map[string]int64 {
        m := map[string]int64{}
        for _, kc := range counts {
                m[kc.Kind] = kc.Count
        }
        return m
}

func buildStatusMap(counts []dbq.CountFindingsByStatusRow) map[string]int64 {
        m := map[string]int64{}
        for _, sc := range counts {
                m[sc.Status] = sc.Count
        }
        return m
}

func buildEventViews(eventsRaw []dbq.ListFindingEventsRow) []eventView {
        events := make([]eventView, 0, len(eventsRaw))
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
        return events
}

func stringOrEmpty(s *string) string {
        if s == nil {
                return ""
        }
        return *s
}
