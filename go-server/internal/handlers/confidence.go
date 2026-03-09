// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
)

type ConfidenceHandler struct {
        Config *config.Config
        DB     *db.Database
}

func NewConfidenceHandler(cfg *config.Config, database *db.Database) *ConfidenceHandler {
        return &ConfidenceHandler{Config: cfg, DB: database}
}

func (h *ConfidenceHandler) Confidence(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "ActivePage":      "confidence",
        }

        isDev := h.Config.IsDevEnvironment
        data["IsDev"] = isDev

        if h.DB != nil {
                if metrics := icae.LoadReportMetrics(c.Request.Context(), h.DB.Queries); metrics != nil {
                        metrics.HashAudit = icae.AuditHashIntegrity(c.Request.Context(), h.DB.Queries, 100)
                        if metrics.HashAudit != nil {
                                if totalHashed, err := h.DB.Queries.CountHashedAnalyses(c.Request.Context()); err == nil {
                                        metrics.HashAudit.TotalHashedInDB = int(totalHashed)
                                }
                        }
                        ce := icae.NewCalibrationEngine()
                        calResult := icae.RunDegradedCalibration(ce)
                        metrics.Calibration = &calResult
                        data["ICAEMetrics"] = metrics
                }
        }

        if h.DB != nil {
                if runtimeMetrics := icuae.LoadRuntimeMetrics(c.Request.Context(), h.DB.Queries); runtimeMetrics != nil {
                        data["ICuAERuntimeMetrics"] = runtimeMetrics
                }
        }

        mergeAuthData(c, h.Config, data)
        data["ICuAEInventory"] = icuae.GetTestInventory()
        c.HTML(http.StatusOK, "confidence.html", data)
}
