package handlers

import (
        "fmt"
        "net/http"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

type TelemetryHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewTelemetryHandler(database *db.Database, cfg *config.Config) *TelemetryHandler {
        return &TelemetryHandler{DB: database, Config: cfg}
}

func (h *TelemetryHandler) Dashboard(c *gin.Context) {
        ctx := c.Request.Context()

        summaries, err := h.DB.Queries.GetRecentTelemetrySummaries(ctx, 20)
        if err != nil {
                summaries = nil
        }

        slowest, err := h.DB.Queries.GetSlowestPhases(ctx, 30)
        if err != nil {
                slowest = nil
        }

        trends, err := h.DB.Queries.GetTelemetryTrends(ctx)
        if err != nil {
                trends = nil
        }

        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        data := gin.H{
                "Title":            "Scan Telemetry",
                "CspNonce":         nonce,
                "CsrfToken":        csrfToken,
                "Summaries":        summaries,
                "Slowest":          slowest,
                "Trends":           trends,
                "PhaseGroupLabels": analyzer.PhaseGroupLabels,
                "PhaseGroupOrder":  analyzer.PhaseGroupOrder,
        }

        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin_telemetry.html", data)
}

func (h *TelemetryHandler) VerifyHash(c *gin.Context) {
        analysisIDStr := c.Param("id")
        var analysisID int32
        if _, err := fmt.Sscanf(analysisIDStr, "%d", &analysisID); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid analysis ID"})
                return
        }

        ctx := c.Request.Context()

        storedHash, err := h.DB.Queries.GetTelemetryHash(ctx, analysisID)
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "telemetry hash not found"})
                return
        }

        timings, err := h.DB.Queries.GetTelemetryByAnalysis(ctx, analysisID)
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load telemetry"})
                return
        }

        var phaseTimings []analyzer.PhaseTiming
        for _, t := range timings {
                pt := analyzer.PhaseTiming{
                        PhaseGroup:  t.PhaseGroup,
                        PhaseTask:   t.PhaseTask,
                        StartedAtMs: int(t.StartedAtMs),
                        DurationMs:  int(t.DurationMs),
                }
                if t.RecordCount != nil {
                        pt.RecordCount = int(*t.RecordCount)
                }
                if t.Error != nil {
                        pt.Error = *t.Error
                }
                phaseTimings = append(phaseTimings, pt)
        }

        recomputedHash := analyzer.ComputeTelemetryHash(phaseTimings)

        c.JSON(http.StatusOK, gin.H{
                "analysis_id":     analysisID,
                "stored_hash":     storedHash.Sha3512,
                "recomputed_hash": recomputedHash,
                "verified":        storedHash.Sha3512 == recomputedHash,
                "phase_count":     storedHash.PhaseCount,
                "total_duration_ms": storedHash.TotalDurationMs,
        })
}
