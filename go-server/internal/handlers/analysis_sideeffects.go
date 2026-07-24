// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"
	"dnstool/go-server/internal/wayback"

	"github.com/gin-gonic/gin"
)

func (h *AnalysisHandler) storeTelemetry(ctx context.Context, analysisID int32, results map[string]any, ephemeral bool) {
	if ephemeral || analysisID == 0 {
		return
	}
	telRaw, ok := results["_scan_telemetry"]
	if !ok {
		return
	}
	if _, valid := telRaw.(analyzer.ScanTelemetry); !valid {
		return
	}
	delete(results, "_scan_telemetry")
	h.storeTelemetryFromRaw(ctx, analysisID, telRaw, ephemeral)
}

func (h *AnalysisHandler) storeTelemetryFromRaw(_ context.Context, analysisID int32, telRaw any, ephemeral bool) {
	if ephemeral || analysisID == 0 || telRaw == nil {
		return
	}
	tel, ok := telRaw.(analyzer.ScanTelemetry)
	if !ok {
		return
	}

	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, t := range tel.Timings {
			var errPtr *string
			if t.Error != "" {
				errPtr = &t.Error
			}
			rc := int32(t.RecordCount)
			if err := h.store().InsertPhaseTelemetry(bgCtx, dbq.InsertPhaseTelemetryParams{
				AnalysisID:  analysisID,
				PhaseGroup:  t.PhaseGroup,
				PhaseTask:   t.PhaseTask,
				StartedAtMs: int32(t.StartedAtMs),
				DurationMs:  int32(t.DurationMs),
				RecordCount: &rc,
				Error:       errPtr,
			}); err != nil {
				slog.Warn("Failed to store phase telemetry", "analysis_id", analysisID, "task", t.PhaseTask, "error", err)
			}
		}
		if err := h.store().InsertTelemetryHash(bgCtx, dbq.InsertTelemetryHashParams{
			AnalysisID:      analysisID,
			TotalDurationMs: int32(tel.TotalDurationMs),
			PhaseCount:      int32(len(tel.Timings)),
			Sha3512:         tel.SHA3Hash,
		}); err != nil {
			slog.Warn("Failed to store telemetry hash", "analysis_id", analysisID, "error", err)
		}
	}()
}

func (h *AnalysisHandler) recordCurrencyIfEligible(ephemeral, domainExists bool, asciiDomain string, results map[string]any) {
	if ephemeral || !domainExists {
		return
	}
	cr, ok := results[mapKeyCurrencyReport]
	if !ok {
		return
	}
	if report, valid := cr.(icuae.CurrencyReport); valid {
		if q := h.rawQueries(); q != nil {
			go icuae.RecordScanResult(context.Background(), q, asciiDomain, report, h.Config.AppVersion)
		}
	}
}

func (h *AnalysisHandler) detectHistoricalDrift(ctx context.Context, currentHash, domain string, analysisID int32, results map[string]any) driftInfo {
	if currentHash == "" {
		return driftInfo{}
	}
	prevRow, prevErr := h.store().GetPreviousAnalysisForDriftBefore(ctx, dbq.GetPreviousAnalysisForDriftBeforeParams{
		Domain: domain,
		ID:     analysisID,
	})
	if prevErr != nil {
		return driftInfo{}
	}
	return computeDriftFromPrev(currentHash, prevAnalysisSnapshot{
		Hash:           prevRow.PostureHash,
		ID:             prevRow.ID,
		CreatedAtValid: prevRow.CreatedAt.Valid,
		CreatedAt:      prevRow.CreatedAt.Time,
		FullResults:    prevRow.FullResults,
	}, results)
}

func (h *AnalysisHandler) detectDrift(ctx context.Context, devNull, domainExists bool, asciiDomain, postureHash string, results map[string]any) driftInfo {
	drift := driftInfo{}
	s := h.store()
	if !devNull && domainExists && s != nil {
		prevRow, prevErr := s.GetPreviousAnalysisForDrift(ctx, asciiDomain)
		if prevErr == nil {
			drift = computeDriftFromPrev(postureHash, prevAnalysisSnapshot{
				Hash:           prevRow.PostureHash,
				ID:             prevRow.ID,
				CreatedAtValid: prevRow.CreatedAt.Valid,
				CreatedAt:      prevRow.CreatedAt.Time,
				FullResults:    prevRow.FullResults,
			}, results)
			if drift.Detected {
				slog.Info("Posture drift detected", mapKeyDomain, asciiDomain, "prev_hash", drift.PrevHash[:8], "new_hash", postureHash[:8], "changed_fields", len(drift.Fields))
			}
		}
	}
	return drift
}

type sideEffectsParams struct {
	asciiDomain      string
	analysisID       int32
	isAuthenticated  bool
	userID           int32
	ephemeral        bool
	domainExists     bool
	drift            driftInfo
	postureHash      string
	analysisSuccess  bool
	analysisDuration float64
	isPrivate        bool
	isScanFlagged    bool
	results          map[string]any
}

func (h *AnalysisHandler) handlePostAnalysisSideEffects(ctx context.Context, c *gin.Context, p sideEffectsParams) {
	if p.analysisID > 0 {
		h.recordUserAnalysisAsync(p)
		if p.drift.Detected && !p.isPrivate {
			go h.persistDriftEvent(p.asciiDomain, p.analysisID, p.drift, p.postureHash)
		}
		if shouldArchiveToWayback(p.analysisID, p.analysisSuccess, p.ephemeral, p.isPrivate, p.isScanFlagged) {
			go h.archiveToWayback(p.analysisID, p.asciiDomain)
		}
		if p.analysisSuccess {
			go h.persistConfidenceScores(p.analysisID, p.asciiDomain, p.results)
		}
	}

	if shouldRunICAE(p.ephemeral, p.domainExists) {
		if q := h.rawQueries(); q != nil {
			icae.EvaluateAndRecord(c.Request.Context(), q, h.Config.AppVersion)
		}
		recordAnalyticsCollector(c, p.asciiDomain)
	}

	go h.recordDailyStats(p.analysisSuccess, p.analysisDuration)
}

func (h *AnalysisHandler) handlePostAnalysisSideEffectsAsync(ctx context.Context, p sideEffectsParams) {
	if p.analysisID > 0 {
		h.recordUserAnalysisAsync(p)
		if p.drift.Detected && !p.isPrivate {
			go h.persistDriftEvent(p.asciiDomain, p.analysisID, p.drift, p.postureHash)
		}
		if shouldArchiveToWayback(p.analysisID, p.analysisSuccess, p.ephemeral, p.isPrivate, p.isScanFlagged) {
			go h.archiveToWayback(p.analysisID, p.asciiDomain)
		}
		if p.analysisSuccess {
			go h.persistConfidenceScores(p.analysisID, p.asciiDomain, p.results)
		}
	}

	if shouldRunICAE(p.ephemeral, p.domainExists) {
		if q := h.rawQueries(); q != nil {
			icae.EvaluateAndRecord(ctx, q, h.Config.AppVersion)
		}
	}

	go h.recordDailyStats(p.analysisSuccess, p.analysisDuration)
}

func (h *AnalysisHandler) archiveToWayback(analysisID int32, domain string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	analysisURL := fmt.Sprintf("%s/analysis/%d/view/E", h.Config.BaseURL, analysisID)
	result := wayback.Archive(ctx, analysisURL)
	if result.Err != nil {
		slog.Warn("Wayback Machine archival failed", "analysis_id", analysisID, "domain", domain, mapKeyError, result.Err)
		return
	}
	err := h.store().UpdateWaybackURL(context.Background(), dbq.UpdateWaybackURLParams{
		ID:         analysisID,
		WaybackUrl: &result.URL,
	})
	if err != nil {
		slog.Error("Failed to store Wayback URL", "analysis_id", analysisID, "wayback_url", result.URL, mapKeyError, err)
	}
}

func (h *AnalysisHandler) recordUserAnalysisAsync(p sideEffectsParams) {
	if !shouldRecordUserAssociation(p.isAuthenticated, p.userID) {
		return
	}
	go func() {
		err := h.store().InsertUserAnalysis(context.Background(), dbq.InsertUserAnalysisParams{
			UserID:     p.userID,
			AnalysisID: p.analysisID,
		})
		if err != nil {
			slog.Error("Failed to record user analysis association", mapKeyUserId, p.userID, "analysis_id", p.analysisID, mapKeyError, err)
		}
	}()
}

func (h *AnalysisHandler) recordDailyStats(success bool, duration float64) {
	exec := h.execer()
	if exec == nil {
		return
	}
	ctx := context.Background()
	today := time.Now().UTC().Truncate(24 * time.Hour)

	successInt := 0
	failedInt := 0
	if success {
		successInt = 1
	} else {
		failedInt = 1
	}

	_, err := exec.Exec(ctx,
		`INSERT INTO analysis_stats (date, total_analyses, successful_analyses, failed_analyses, unique_domains, avg_analysis_time, created_at, updated_at)
                 VALUES ($1, 1, $2, $3, 0, $4, NOW(), NOW())
                 ON CONFLICT (date) DO UPDATE SET
                     total_analyses = COALESCE(analysis_stats.total_analyses, 0) + 1,
                     successful_analyses = COALESCE(analysis_stats.successful_analyses, 0) + $2,
                     failed_analyses = COALESCE(analysis_stats.failed_analyses, 0) + $3,
                     avg_analysis_time = CASE
                         WHEN COALESCE(analysis_stats.total_analyses, 0) = 0 THEN $4
                         ELSE (COALESCE(analysis_stats.avg_analysis_time, 0) * COALESCE(analysis_stats.total_analyses, 0) + $4) / (COALESCE(analysis_stats.total_analyses, 0) + 1)
                     END,
                     updated_at = NOW()`,
		today, successInt, failedInt, duration)
	if err != nil {
		slog.Error("Failed to record daily stats", mapKeyError, err)
	}
}

func recordAnalyticsCollector(c *gin.Context, domain string) {
	ac, exists := c.Get("analytics_collector")
	if !exists {
		return
	}
	if collector, ok := ac.(interface{ RecordAnalysis(string) }); ok {
		collector.RecordAnalysis(domain)
	}
}

type driftInfo struct {
	Detected bool
	PrevHash string
	PrevTime string
	PrevID   int32
	Fields   []analyzer.PostureDiffField
}

type prevAnalysisSnapshot struct {
	Hash           *string
	ID             int32
	CreatedAtValid bool
	CreatedAt      time.Time
	FullResults    json.RawMessage
}

func computeDriftFromPrev(currentHash string, prev prevAnalysisSnapshot, currentResults map[string]any) driftInfo {
	if prev.Hash == nil || *prev.Hash == "" || *prev.Hash == currentHash {
		return driftInfo{}
	}
	di := driftInfo{
		Detected: true,
		PrevHash: *prev.Hash,
		PrevID:   prev.ID,
	}
	if prev.CreatedAtValid {
		di.PrevTime = prev.CreatedAt.Format("2 Jan 2006 15:04 UTC")
	}
	if prev.FullResults != nil {
		var prevResults map[string]any
		if json.Unmarshal(prev.FullResults, &prevResults) == nil {
			di.Fields = analyzer.ComputePostureDiff(prevResults, currentResults)
			// The canonical hash differed, but the field-level diff is
			// empty. This happens when the only thing that moved was a
			// tri-state field suppressed by ComputePostureDiff (DANE /
			// DNSSEC indeterminate from a transient lookup failure). A
			// hash flip with no explicable field change is not real
			// drift — suppress it so transient failures stop flapping.
			if len(di.Fields) == 0 {
				return driftInfo{}
			}
		}
	}
	return di
}

func (h *AnalysisHandler) persistDriftEvent(domain string, analysisID int32, drift driftInfo, currentHash string) {
	diffJSON, err := json.Marshal(drift.Fields)
	if err != nil {
		slog.Error("Failed to marshal drift diff", mapKeyDomain, domain, mapKeyError, err)
		return
	}

	severity := computeDriftSeverity(drift.Fields)

	driftRow, insertErr := h.store().InsertDriftEvent(context.Background(), dbq.InsertDriftEventParams{
		Domain:         domain,
		AnalysisID:     analysisID,
		PrevAnalysisID: drift.PrevID,
		CurrentHash:    currentHash,
		PreviousHash:   drift.PrevHash,
		DiffSummary:    diffJSON,
		Severity:       severity,
	})
	if insertErr != nil {
		slog.Error("Failed to persist drift event", mapKeyDomain, domain, mapKeyError, insertErr)
		return
	}
	slog.Info("Drift event persisted", mapKeyDomain, domain, "severity", severity, "changed_fields", len(drift.Fields))

	h.queueDriftNotifications(domain, driftRow.ID)
}

func (h *AnalysisHandler) queueDriftNotifications(domain string, driftEventID int32) {
	ctx := context.Background()
	endpoints, err := h.store().ListEndpointsForWatchedDomain(ctx, domain)
	if err != nil {
		slog.Error("Failed to list endpoints for watched domain", mapKeyDomain, domain, mapKeyError, err)
		return
	}
	if len(endpoints) == 0 {
		return
	}
	for _, ep := range endpoints {
		_, qErr := h.store().InsertDriftNotification(ctx, dbq.InsertDriftNotificationParams{
			DriftEventID: driftEventID,
			EndpointID:   ep.EndpointID,
			Status:       "pending",
		})
		if qErr != nil {
			slog.Error("Failed to queue drift notification",
				mapKeyDomain, domain,
				"endpoint_id", ep.EndpointID,
				"endpoint_type", ep.EndpointType,
				mapKeyError, qErr,
			)
			continue
		}
		slog.Info("Drift notification queued",
			mapKeyDomain, domain,
			"endpoint_id", ep.EndpointID,
			"endpoint_type", ep.EndpointType,
		)
	}
}

func shouldArchiveToWayback(analysisID int32, analysisSuccess, ephemeral, isPrivate, isScanFlagged bool) bool {
	return analysisID > 0 && analysisSuccess && !ephemeral && !isPrivate && !isScanFlagged
}

func computeDriftSeverity(fields []analyzer.PostureDiffField) string {
	severity := "info"
	for _, f := range fields {
		if f.Severity == mapKeyCritical {
			return mapKeyCritical
		}
		if f.Severity == mapKeyWarning {
			severity = mapKeyWarning
		}
	}
	return severity
}

func shouldRunICAE(ephemeral, domainExists bool) bool {
	return !ephemeral && domainExists
}

func shouldRecordUserAssociation(isAuthenticated bool, userID int32) bool {
	return isAuthenticated && userID > 0
}
