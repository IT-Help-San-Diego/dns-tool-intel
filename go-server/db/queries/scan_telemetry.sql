-- name: InsertPhaseTelemetry :exec
INSERT INTO scan_phase_telemetry (analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count, error)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: InsertTelemetryHash :exec
INSERT INTO scan_telemetry_hash (analysis_id, total_duration_ms, phase_count, sha3_512)
VALUES ($1, $2, $3, $4);

-- name: GetTelemetryByAnalysis :many
SELECT id, analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count, error, created_at
FROM scan_phase_telemetry
WHERE analysis_id = $1
ORDER BY started_at_ms, phase_task;

-- name: GetTelemetryHash :one
SELECT analysis_id, total_duration_ms, phase_count, sha3_512, created_at
FROM scan_telemetry_hash
WHERE analysis_id = $1;

-- name: GetTelemetryTrends :many
SELECT spt.phase_group,
       DATE(spt.created_at) AS trend_date,
       AVG(spt.duration_ms)::INT AS avg_duration_ms,
       COUNT(*) AS sample_count
FROM scan_phase_telemetry spt
WHERE spt.created_at >= NOW() - INTERVAL '7 days'
GROUP BY spt.phase_group, DATE(spt.created_at)
ORDER BY trend_date, spt.phase_group;

-- name: GetSlowestPhases :many
SELECT phase_group, phase_task, AVG(duration_ms)::INT AS avg_ms,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms)::INT AS p50_ms,
       PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::INT AS p95_ms,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms)::INT AS p99_ms,
       COUNT(*) AS sample_count
FROM scan_phase_telemetry
WHERE created_at >= NOW() - INTERVAL '7 days'
GROUP BY phase_group, phase_task
ORDER BY p95_ms DESC
LIMIT $1;

-- name: GetRecentTelemetrySummaries :many
SELECT sth.analysis_id, da.ascii_domain, sth.total_duration_ms, sth.phase_count, sth.sha3_512, sth.created_at
FROM scan_telemetry_hash sth
JOIN domain_analyses da ON da.id = sth.analysis_id
ORDER BY sth.created_at DESC
LIMIT $1;
