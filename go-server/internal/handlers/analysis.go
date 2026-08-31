// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"
	"dnstool/go-server/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	templateIndex            = "index.html"
	headerContentDisposition = "Content-Disposition"

	mapKeyAuthenticated  = "authenticated"
	mapKeyCovert         = "covert"
	mapKeyCritical       = "critical"
	mapKeyCurrencyReport = "currency_report"
	mapKeyDanger         = "danger"
	mapKeyDkimAnalysis   = "dkim_analysis"
	mapKeyDmarcAnalysis  = "dmarc_analysis"
	mapKeyDomain         = "domain"
	mapKeyMessage        = "message"
	mapKeySpfAnalysis    = "spf_analysis"
	mapKeyStandard       = "standard"
	mapKeyStatus         = "status"
	mapKeyWarning        = "warning"
	strAnalysisNotFound  = "Analysis not found"
	strUtc               = "2006-01-02 15:04:05 UTC"
	// Sonar S1192: deduplicate string literals (added 2026-04-16)
	errMsgInvalidAnalysisID    = "Invalid analysis ID"
	errMsgFailedToParseResults = "Failed to parse results"
)

type AnalysisHandler struct {
	DB              *db.Database
	Config          *config.Config
	Analyzer        *analyzer.Analyzer
	DNSHistoryCache *analyzer.DNSHistoryCache
	Calibration     *icae.CalibrationEngine
	DimCharts       *icuae.DimensionCharts
	ProgressStore   *ProgressStore
	analysisStore   AnalysisStore
	statsExec       StatsExecer
	// ScanCharger charges the per-key scan tokens for batch requests
	// (the route middleware charges only the 1 request token; the batch
	// handler charges the rest so total charge == scan count). Nil means
	// enqueue-only contract-test mode, mirroring nil Analyzer.
	ScanCharger middleware.ScanKeyRateLimiter
}

func (h *AnalysisHandler) store() AnalysisStore {
	if h.analysisStore != nil {
		return h.analysisStore
	}
	if h.DB != nil {
		return h.DB.Queries
	}
	return nil
}

func (h *AnalysisHandler) execer() StatsExecer {
	if h.statsExec != nil {
		return h.statsExec
	}
	if h.DB != nil {
		return h.DB.Pool
	}
	return nil
}

func (h *AnalysisHandler) rawQueries() *dbq.Queries {
	if h.DB != nil {
		return h.DB.Queries
	}
	return nil
}

func NewAnalysisHandler(database *db.Database, cfg *config.Config, a *analyzer.Analyzer, historyCache *analyzer.DNSHistoryCache) *AnalysisHandler {
	return &AnalysisHandler{
		DB:              database,
		Config:          cfg,
		Analyzer:        a,
		DNSHistoryCache: historyCache,
		Calibration:     icae.NewCalibrationEngine(),
		DimCharts:       icuae.NewDimensionCharts(),
		ProgressStore:   NewProgressStore(),
	}
}

func (h *AnalysisHandler) Close() {
	if h.ProgressStore != nil {
		h.ProgressStore.Close()
	}
}

func (h *AnalysisHandler) checkPrivateAccess(c *gin.Context, analysisID int32, private bool) bool {
	if !private {
		return true
	}
	auth, exists := c.Get(mapKeyAuthenticated)
	if !exists || auth != true {
		return false
	}
	uid, ok := c.Get(mapKeyUserId)
	if !ok {
		return false
	}
	userID, ok := uid.(int32)
	if !ok {
		return false
	}
	isOwner, err := h.store().CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
		AnalysisID: analysisID,
		UserID:     userID,
	})
	return err == nil && isOwner
}

func derefString(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}
