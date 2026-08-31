// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/middleware"
	"dnstool/go-server/internal/scanner"
)

// BatchScans — API-key-gated batch enqueue over the EXISTING scan path
// (design docs/DESIGN-batch-scans-api-keys-20260831.md). The endpoint is a
// QUEUE, not a new scanner: every domain runs through Analyzer.AnalyzeDomain
// exactly as a single POST /analyze would, with the same persistence, seals,
// receipts, and daily stats. No new scan logic — single producer.
//
// Provenance: every batch row is stamped after the scan via
// StampBatchProvenance so corpus statistics can include/exclude batch
// traffic explicitly (the map-on-read class of rule; no backfill).

const (
	maxBatchDomains  = 500 // DoS guard; larger sets split into batches
	batchConcurrency = 4   // parallel scans inside one batch — bounded, not unbounded
)

type batchScanRequest struct {
	Domains        []string `json:"domains" binding:"required"`
	Label          string   `json:"label"`
	Selectors      []string `json:"selectors"`
	ExposureChecks bool     `json:"exposure_checks"`
	DevNull        bool     `json:"devnull"`
}

type batchDomainResult struct {
	Domain string `json:"domain"`
	Queued bool   `json:"queued"`
	Error  string `json:"error,omitempty"`
}

type batchScanResponse struct {
	BatchID    string              `json:"batch_id"`
	Label      string              `json:"label,omitempty"`
	Total      int                 `json:"total"`
	Queued     int                 `json:"queued"`
	Failed     int                 `json:"failed"`
	PerDomain  []batchDomainResult `json:"per_domain"`
	KeyLabel   string              `json:"key_label"`
	BatchStamp string              `json:"_batch_stamp"`
}

// AnalyzeBatch is the POST /api/batch handler. Auth happens at the
// middleware layer (ScanAPIKeyAuth); rate limiting is split — the route
// middleware charges the 1 request token, this handler charges the
// remaining scan tokens post-validation (total == scan count).
func (h *AnalysisHandler) AnalyzeBatch(c *gin.Context) {
	keyID := c.GetInt32("scan_key_id")
	keyLabel := c.GetString("scan_key_label")

	var req batchScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if len(req.Domains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domains list is empty"})
		return
	}
	if len(req.Domains) > maxBatchDomains {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("batch too large: %d domains (max %d); split into multiple batches",
				len(req.Domains), maxBatchDomains),
		})
		return
	}

	batchID := newBatchID()
	resp := batchScanResponse{
		BatchID:    batchID,
		Label:      req.Label,
		Total:      len(req.Domains),
		KeyLabel:   keyLabel,
		BatchStamp: "v=batch1",
	}

	// Normalize + validate every domain UP FRONT (reject the batch-mixing shape
	// where some domains queue and others fail validation only at scan time).
	valid, perDomain, queued, failed := normalizeBatchDomains(req.Domains)
	resp.PerDomain = perDomain
	resp.Queued = queued
	resp.Failed = failed

	// Per-scan charging (the 30-scans/min per-key invariant, mechanical):
	// the route middleware charged 1 request token before the body was
	// readable; charge the remaining queued-1 here so the batch's total
	// equals its scan count. A batch that cannot EVER fit the window
	// (queued > cap) gets a permanent refusal with the split instruction —
	// never retry advice that cannot come true. Nil charger = enqueue-only
	// contract-test mode, mirroring nil Analyzer.
	if resp.Queued > middleware.KeyScanCapPerMinute {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"batch of %d scans exceeds the per-key rate cap (%d/min): split into batches of at most %d",
				resp.Queued, middleware.KeyScanCapPerMinute, middleware.KeyScanCapPerMinute),
		})
		return
	}
	if h.ScanCharger != nil && resp.Queued > 1 {
		if ok, retry := h.ScanCharger.AllowKey(keyID, resp.Queued-1); !ok {
			if retry < 0 {
				retry = 60
			}
			c.Header("Retry-After", fmt.Sprintf("%d", retry))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "batch rate limit exceeded for this key",
				"retry_after": retry,
			})
			return
		}
	}

	// 202: the batch is ACCEPTED; scans run server-side after the response.
	// Results are ordinary domain_analyses rows readable by every existing
	// read path (/agent/api, history, /analysis/:id).
	c.JSON(http.StatusAccepted, resp)

	// Fire the scans bounded-parallel. The request context is GONE after the
	// 202 — use a fresh background context with the same scan budget a single
	// POST would get. A nil Analyzer means ENQUEUE-ONLY mode (contract tests,
	// and a legitimate dry-run for verifying the queue shape).
	if h.Analyzer != nil {
		go h.runBatchScans(batchID, valid, req, keyID)
	}
}

// normalizeBatchDomains trims, normalizes, and validates every submitted domain
// UP FRONT so the batch never mixes queued and validate-at-scan-time failures.
// Returns the ASCII-ready valid list to scan, the per-domain result rows (both
// queued and rejected), and the queued/failed counts. Extracted from
// AnalyzeBatch to keep that handler under the cyclomatic-complexity ratchet.
func normalizeBatchDomains(domains []string) (valid []string, perDomain []batchDomainResult, queued, failed int) {
	valid = make([]string, 0, len(domains))
	perDomain = make([]batchDomainResult, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		normalized, _, _ := dnsclient.NormalizeDomainInput(d)
		if normalized == "" {
			normalized = d
		}
		if !dnsclient.ValidateDomain(normalized) && !analyzer.IsWeb3Input(normalized) {
			perDomain = append(perDomain, batchDomainResult{Domain: d, Error: "invalid domain"})
			failed++
			continue
		}
		ascii, err := dnsclient.DomainToASCII(normalized)
		if err != nil {
			ascii = normalized
		}
		valid = append(valid, ascii)
		perDomain = append(perDomain, batchDomainResult{Domain: ascii, Queued: true})
		queued++
	}
	return valid, perDomain, queued, failed
}

// runBatchScans executes the queued domains through the standard analyzer.
// Failures are recorded per-domain to the log; the batch contract is
// enqueue-and-run, and the ROWS are the results (read paths answer status).
func (h *AnalysisHandler) runBatchScans(batchID string, domains []string, req batchScanRequest, keyID int32) {
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results := h.Analyzer.AnalyzeDomain(scanBatchContext(), domain, req.Selectors, analyzer.AnalysisOptions{
				ExposureChecks: req.ExposureChecks,
			})
			if failed, errMsg := isAnalysisFailure(results); failed {
				batchScanLog("batch %s: domain %s failed: %s", batchID, domain, errMsg)
				return
			}
			h.applyConfidenceEngines(results)
			// Provenance: stamp the batch BEFORE persist so the stored row
			// carries the batch facts (the same discipline as _request_source).
			stampBatchProvenance(results, batchID, req.Label, keyID)
			started := time.Now()
			ctx, cancel := scanContext(context.Background())
			defer cancel()
			h.persistOrLogEphemeral(ctx, persistParams{
				domain:           domain,
				asciiDomain:      domain,
				results:          results,
				analysisDuration: time.Since(started).Seconds(),
				// Batch scans are operator-authorized automation: the source
				// stamp is the batch class, not a crawler class.
				scanClass: scanner.Classification{},
				botClass:  fmt.Sprintf("batch:%s", batchID),
			})
		}(domain)
	}
	wg.Wait()
	if err := h.DB.MarkScanKeyUsed(scanBatchContext(), keyID); err != nil {
		batchScanLog("batch %s: key-use mark failed: %v", batchID, err)
	}
}

// newBatchID returns a unique, sortable batch identifier.
func newBatchID() string {
	return fmt.Sprintf("b_%d_%s", time.Now().Unix(), randomHex(6))
}

// scanBatchContext is the background context for server-side batch runs —
// the HTTP request is gone after 202, so scans run on their own budget.
func scanBatchContext() context.Context {
	return context.Background()
}

// batchScanLog is slog with a stable prefix so batch lines are greppable.
func batchScanLog(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...), "source", "batch_scans")
}

// stampBatchProvenance writes the batch facts into the results map BEFORE
// persist, following the _request_source discipline: corpus statistics can
// include/exclude batch traffic explicitly.
func stampBatchProvenance(results map[string]any, batchID, label string, keyID int32) {
	results["_request_source"] = "batch"
	batch := map[string]any{
		"id":      batchID,
		"key_id":  keyID,
		"channel": "api_batch",
	}
	if label != "" {
		batch["label"] = label
	}
	results["_batch"] = batch
}

// randomHex returns n random bytes hex-encoded (batch-id entropy).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Entropy failure degrades to a time-only id — still unique per call.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
