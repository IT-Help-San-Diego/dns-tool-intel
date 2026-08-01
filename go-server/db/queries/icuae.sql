-- name: ICuAEInsertScanScore :one
INSERT INTO icuae_scan_scores (domain, overall_score, overall_grade, resolver_count, record_count, app_version)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, created_at;

-- name: ICuAEInsertDimensionScore :exec
INSERT INTO icuae_dimension_scores (scan_id, dimension, score, grade, record_types_evaluated, record_types_list)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ICuAEGetAggregateStats :one
SELECT
    COUNT(*)::integer AS total_scans,
    COALESCE(AVG(overall_score), 0)::real AS avg_score,
    COALESCE(STDDEV_POP(overall_score), 0)::real AS stddev_score,
    MAX(created_at) AS last_evaluated_at
FROM icuae_scan_scores;

-- name: ICuAEGetGradeDistribution :many
-- Scope to rows recorded at/after the 018 grade-width adoption, so the
-- published distribution is not a blend of two regimes: pre-018 rows could
-- only ever be 'good'/'stale' (longer grade names failed VARCHAR(5) insert),
-- post-018 rows can carry any grade. The cutoff derives from the migration
-- ledger (newest applied row for version 18), never a hardcoded date. If 018
-- is not yet applied the subquery is NULL and created_at >= NULL matches
-- nothing — correct (render no distribution), stated here so it is not "fixed"
-- into an unfiltered query.
SELECT
    overall_grade AS grade,
    COUNT(*)::integer AS count
FROM icuae_scan_scores
WHERE created_at >= (
    SELECT tstamp FROM goose_db_version
    WHERE version_id = 18 AND is_applied = true
    ORDER BY id DESC LIMIT 1
)
GROUP BY overall_grade
ORDER BY overall_grade ASC;

-- name: ICuAEGetGradeDistributionCutoff :one
-- The cutoff the distribution is scoped to, for the caption. Label and filter
-- must come from ONE source (the ledger), or the caption drifts from the query.
SELECT tstamp FROM goose_db_version
WHERE version_id = 18 AND is_applied = true
ORDER BY id DESC LIMIT 1;

-- name: ICuAEGetDimensionAverages :many
SELECT
    dimension,
    COALESCE(AVG(score), 0)::real AS avg_score,
    COALESCE(STDDEV_POP(score), 0)::real AS stddev_score,
    COUNT(*)::integer AS sample_count
FROM icuae_dimension_scores
GROUP BY dimension
ORDER BY dimension ASC;

-- name: ICuAEGetRecentTrend :many
SELECT
    overall_score,
    created_at
FROM icuae_scan_scores
ORDER BY created_at DESC
LIMIT $1;
