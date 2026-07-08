-- Confidence scores: normalized per-scan, per-protocol confidence statistics.
-- Written post-scan (source='scan') and by the admin backfill job (source='import').
-- NOTE: rows include private/flagged scans — any PUBLIC consumer must join
-- domain_analyses and filter private = FALSE AND scan_flag = FALSE.

-- name: InsertConfidenceScore :execrows
INSERT INTO confidence_scores (
    analysis_id, domain, protocol, score, resolver_count, resolver_agreement,
    evidence_factors, calibrated_score, raw_score, source, scanned_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT (analysis_id, protocol) WHERE analysis_id IS NOT NULL DO NOTHING;

-- name: ListConfidenceBackfillBatch :many
-- NOTE: iterates ALL successful analyses (not just those missing confidence
-- rows) — re-runs rely on InsertConfidenceScore's ON CONFLICT DO NOTHING for
-- idempotency. An anti-join filter was skipped deliberately: full_results is
-- json (not jsonb) and the table is scanned keyset-style once per admin run.
SELECT id, ascii_domain, full_results, created_at
FROM domain_analyses
WHERE id > $1
  AND analysis_success = TRUE
  AND full_results IS NOT NULL
ORDER BY id
LIMIT $2;

-- name: CountConfidenceScores :one
SELECT COUNT(*) FROM confidence_scores;

-- name: CountConfidenceBackfillCandidates :one
SELECT COUNT(*) FROM domain_analyses
WHERE analysis_success = TRUE
  AND full_results IS NOT NULL;
