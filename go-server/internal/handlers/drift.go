package handlers

import (
        "encoding/json"
        "net/http"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

const templateDrift = "drift.html"

type DriftHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewDriftHandler(database *db.Database, cfg *config.Config) *DriftHandler {
        return &DriftHandler{DB: database, Config: cfg}
}

type driftTimelineEvent struct {
        ID               int32
        Domain           string
        AnalysisID       int32
        PrevAnalysisID   int32
        CurrentHash      string
        PreviousHash     string
        CurrentHashShort string
        PrevHashShort    string
        Severity         string
        CreatedAt        string
        Fields           []analyzer.PostureDiffField
}

type postureHashEntry struct {
        ID               int32
        PostureHash      string
        PostureHashShort string
        CreatedAt        string
        HashChanged      bool
}

func shortHash(s string) string {
        if len(s) > 16 {
                return s[:16]
        }
        return s
}

func (h *DriftHandler) Timeline(c *gin.Context) {
        nonce := c.MustGet("csp_nonce")
        csrfToken := c.MustGet("csrf_token")

        domain := c.Query("domain")
        if domain == "" {
                data := gin.H{
                        "AppVersion":      h.Config.AppVersion,
                        "MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
                        "CspNonce":        nonce,
                        "CsrfToken":       csrfToken,
                        "ActivePage":      "",
                        "FlashMessages":   []FlashMessage{{Category: "danger", Message: "Domain parameter is required. Use ?domain=example.com"}},
                }
                mergeAuthData(c, h.Config, data)
                c.HTML(http.StatusBadRequest, templateDrift, data)
                return
        }

        ctx := c.Request.Context()

        driftEvents, err := h.DB.Queries.ListDriftEventsByDomain(ctx, dbq.ListDriftEventsByDomainParams{
                Domain: domain,
                Limit:  50,
        })
        if err != nil {
                data := gin.H{
                        "AppVersion":      h.Config.AppVersion,
                        "MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
                        "CspNonce":        nonce,
                        "CsrfToken":       csrfToken,
                        "ActivePage":      "",
                        "Domain":          domain,
                        "FlashMessages":   []FlashMessage{{Category: "danger", Message: "Failed to load drift events"}},
                }
                mergeAuthData(c, h.Config, data)
                c.HTML(http.StatusInternalServerError, templateDrift, data)
                return
        }

        analyses, err := h.DB.Queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
                Domain: domain,
                Limit:  50,
        })
        if err != nil {
                data := gin.H{
                        "AppVersion":      h.Config.AppVersion,
                        "MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
                        "CspNonce":        nonce,
                        "CsrfToken":       csrfToken,
                        "ActivePage":      "",
                        "Domain":          domain,
                        "FlashMessages":   []FlashMessage{{Category: "danger", Message: "Failed to load analysis history"}},
                }
                mergeAuthData(c, h.Config, data)
                c.HTML(http.StatusInternalServerError, templateDrift, data)
                return
        }

        timeline := make([]driftTimelineEvent, 0, len(driftEvents))
        for _, ev := range driftEvents {
                te := driftTimelineEvent{
                        ID:               ev.ID,
                        Domain:           ev.Domain,
                        AnalysisID:       ev.AnalysisID,
                        PrevAnalysisID:   ev.PrevAnalysisID,
                        CurrentHash:      ev.CurrentHash,
                        PreviousHash:     ev.PreviousHash,
                        CurrentHashShort: shortHash(ev.CurrentHash),
                        PrevHashShort:    shortHash(ev.PreviousHash),
                        Severity:         ev.Severity,
                }
                if ev.CreatedAt.Valid {
                        te.CreatedAt = ev.CreatedAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                if len(ev.DiffSummary) > 0 {
                        var fields []analyzer.PostureDiffField
                        if json.Unmarshal(ev.DiffSummary, &fields) == nil {
                                te.Fields = fields
                        }
                }
                timeline = append(timeline, te)
        }

        hashHistory := make([]postureHashEntry, 0, len(analyses))
        prevHash := ""
        for i := len(analyses) - 1; i >= 0; i-- {
                a := analyses[i]
                ph := ""
                if a.PostureHash != nil {
                        ph = *a.PostureHash
                }
                entry := postureHashEntry{
                        ID:               a.ID,
                        PostureHash:      ph,
                        PostureHashShort: shortHash(ph),
                }
                if a.CreatedAt.Valid {
                        entry.CreatedAt = a.CreatedAt.Time.Format("2 Jan 2006 15:04 UTC")
                }
                if ph != "" && prevHash != "" && ph != prevHash {
                        entry.HashChanged = true
                }
                prevHash = ph
                hashHistory = append(hashHistory, entry)
        }
        for i, j := 0, len(hashHistory)-1; i < j; i, j = i+1, j-1 {
                hashHistory[i], hashHistory[j] = hashHistory[j], hashHistory[i]
        }

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":        h.Config.BetaPages,
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "ActivePage":      "",
                "Domain":          domain,
                "DriftEvents":     timeline,
                "HashHistory":     hashHistory,
                "HasDrift":        len(timeline) > 0,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, templateDrift, data)
}
