// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icae

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
)

type HashAuditResult struct {
	TotalAudited    int
	TotalVerified   int
	TotalFailed     int
	TotalMissing    int
	TotalHashedInDB int
	LastVerifiedAt  string
	FailedDomains   []string
	IntegrityPct    int
}

func AuditHashIntegrity(ctx context.Context, queries *dbq.Queries, limit int32) *HashAuditResult {
	if queries == nil {
		return nil
	}

	rows, err := queries.GetRecentHashedAnalyses(ctx, limit)
	if err != nil {
		slog.Warn("ICAE hash audit: failed to query analyses", "error", err)
		return nil
	}

	result := &HashAuditResult{}
	for _, row := range rows {
		auditSingleRow(row, result)
	}

	if result.TotalAudited > 0 {
		result.IntegrityPct = (result.TotalVerified * 100) / result.TotalAudited
	}

	return result
}

func auditSingleRow(row dbq.GetRecentHashedAnalysesRow, result *HashAuditResult) {
	if row.PostureHash == nil || *row.PostureHash == "" {
		result.TotalMissing++
		return
	}

	result.TotalAudited++

	var fullResults map[string]any
	if err := json.Unmarshal(row.FullResults, &fullResults); err != nil {
		slog.Warn("ICAE hash audit: failed to parse full_results",
			"id", row.ID, "domain", row.Domain, "error", err)
		result.TotalFailed++
		result.FailedDomains = append(result.FailedDomains, row.Domain)
		return
	}

	if hashMatches(*row.PostureHash, fullResults) {
		result.TotalVerified++
		if result.LastVerifiedAt == "" && row.CreatedAt.Valid {
			result.LastVerifiedAt = row.CreatedAt.Time.Format(time.DateOnly)
		}
	} else {
		result.TotalFailed++
		result.FailedDomains = append(result.FailedDomains, row.Domain)
		slog.Warn("ICAE hash audit: posture hash mismatch",
			"id", row.ID, "domain", row.Domain,
			"stored", *row.PostureHash,
			"recomputed", analyzer.CanonicalPostureHash(fullResults))
	}
}

// hashMatches verifies a stored hash against every formula that ever
// legitimately produced one: the live formula, the sha3 formula as it stood
// before extractSortedSelectors learned the map shape (dkim_selectors pinned
// to ""), and the sha256-era formula for 64-char rows. Without the pinned
// sha3 fallback, every pre-fix row whose domain publishes selectors would
// read as an integrity failure on the public audit — a failure the audit
// itself measured into existence, not one that happened to the data.
func hashMatches(stored string, fullResults map[string]any) bool {
	if len(stored) == 64 {
		return analyzer.CanonicalPostureHashLegacySHA256(fullResults) == stored
	}
	if analyzer.CanonicalPostureHash(fullResults) == stored {
		return true
	}
	return analyzer.CanonicalPostureHashLegacySelectors(fullResults) == stored
}
