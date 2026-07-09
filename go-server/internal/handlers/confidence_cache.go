// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icae"
)

// The /confidence page audit bundle is expensive to compute (SHA-3 re-derivation
// over the 100-entry audit window + calibration). Its inputs only change when the
// evidence ledger changes, so the bundle is cached keyed on the ledger head:
// identical inputs yield an identical audit, and a recompute is triggered the
// moment the ledger head moves. A modest max age bounds any input that could
// drift without moving the head (e.g. maturity passes) and forces periodic
// re-verification regardless of traffic.
const confidenceCacheMaxAge = 2 * time.Minute

type confidenceBundle struct {
	key          string
	computedAt   time.Time
	metrics      *icae.ReportMetrics
	recentHashes []AuditLogEntry
}

var confidenceCache struct {
	mu     sync.Mutex
	bundle *confidenceBundle
}

// resetConfidenceCache clears the cached bundle (test hook).
func resetConfidenceCache() {
	confidenceCache.mu.Lock()
	confidenceCache.bundle = nil
	confidenceCache.mu.Unlock()
}

// confidenceBundleFresh reports whether a cached bundle may be served for the
// given ledger-head key at time now.
func confidenceBundleFresh(b *confidenceBundle, key string, now time.Time) bool {
	return b != nil &&
		b.metrics != nil &&
		b.key == key &&
		now.Sub(b.computedAt) < confidenceCacheMaxAge
}

// ledgerHeadKey cheaply identifies the current state of the evidence ledger:
// newest hashed analysis (id + posture hash) plus the total hashed count.
// Returns ok=false when the probe fails — callers then fall back to a live,
// uncached compute (fail open to fresh data, never to stale data).
func (h *ConfidenceHandler) ledgerHeadKey(ctx context.Context) (string, bool) {
	if h.DB == nil || h.DB.Queries == nil {
		return "", false
	}
	total, err := h.DB.Queries.CountHashedAnalyses(ctx)
	if err != nil {
		return "", false
	}
	head, err := h.DB.Queries.ListHashedAnalyses(ctx, dbq.ListHashedAnalysesParams{Limit: 1, Offset: 0})
	if err != nil {
		return "", false
	}
	if len(head) == 0 {
		return fmt.Sprintf("empty|%d", total), true
	}
	posture := ""
	if head[0].PostureHash != nil {
		posture = *head[0].PostureHash
	}
	return fmt.Sprintf("%d|%s|%d", head[0].ID, posture, total), true
}

// computeConfidenceBundle performs the full live audit: report metrics, hash
// integrity re-derivation over the audit window, and calibration. This is the
// single place the bundle is built; the cache stores its output verbatim and
// nothing may mutate the returned metrics afterwards.
func (h *ConfidenceHandler) computeConfidenceBundle(ctx context.Context) (*icae.ReportMetrics, []AuditLogEntry) {
	metrics := icae.LoadReportMetrics(ctx, h.DB.Queries)
	if metrics == nil {
		return nil, nil
	}
	metrics.HashAudit = icae.AuditHashIntegrity(ctx, h.DB.Queries, 100)
	var recent []AuditLogEntry
	if metrics.HashAudit != nil {
		if totalHashed, err := h.DB.Queries.CountHashedAnalyses(ctx); err == nil {
			metrics.HashAudit.TotalHashedInDB = int(totalHashed)
		}
		if rows, err := h.DB.Queries.ListHashedAnalyses(ctx, dbq.ListHashedAnalysesParams{Limit: 3, Offset: 0}); err == nil {
			recent = convertAuditRows(rows)
		}
	}
	ce := icae.NewCalibrationEngine()
	ce.ApplyEvidence(metrics, icae.DefaultEvidenceCap)
	calResult := icae.RunDegradedCalibration(ce)
	metrics.Calibration = &calResult
	return metrics, recent
}

// confidenceBundleFor returns the audit bundle, serving the cached copy while
// the ledger head is unchanged and recomputing under a single-flight lock the
// moment it moves. The lock intentionally serializes recomputes: concurrent
// viewers wait for one compute instead of amplifying it.
func (h *ConfidenceHandler) confidenceBundleFor(ctx context.Context) (metrics *icae.ReportMetrics, recent []AuditLogEntry, computedAt time.Time, fromCache bool) {
	key, ok := h.ledgerHeadKey(ctx)
	if !ok {
		m, r := h.computeConfidenceBundle(ctx)
		return m, r, time.Now().UTC(), false
	}

	confidenceCache.mu.Lock()
	defer confidenceCache.mu.Unlock()

	now := time.Now().UTC()
	if b := confidenceCache.bundle; confidenceBundleFresh(b, key, now) {
		return b.metrics, b.recentHashes, b.computedAt, true
	}

	m, r := h.computeConfidenceBundle(ctx)
	if m != nil {
		confidenceCache.bundle = &confidenceBundle{
			key:          key,
			computedAt:   now,
			metrics:      m,
			recentHashes: r,
		}
	}
	return m, r, now, false
}
