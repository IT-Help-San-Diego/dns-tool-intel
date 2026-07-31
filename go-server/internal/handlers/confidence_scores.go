// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// confidence_scores.go — Writer + backfill for the confidence_scores table.
//
// Every successful persisted scan writes one row per calibrated protocol
// (source='scan'). The admin backfill job replays historical
// domain_analyses.full_results JSON into the same table (source='import').
// Both paths share extractConfidenceRows/insertConfidenceScores so live and
// imported rows are computed identically. Idempotency comes from the partial
// unique index on (analysis_id, protocol).
package handlers

import (
        "context"
        "encoding/json"
        "log/slog"
        "net/http"
        "strconv"
        "sync"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"

        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
)

const (
        confidenceSourceScan   = "scan"
        confidenceSourceImport = "import"
)

// confidenceProtocolDBNames maps code-side protocol keys to the DB CHECK
// constraint spelling (hyphens, not underscores).
var confidenceProtocolDBNames = map[string]string{
        "MTA_STS": "MTA-STS",
        "TLS_RPT": "TLS-RPT",
}

func confidenceProtocolDBName(protocol string) string {
        if mapped, ok := confidenceProtocolDBNames[protocol]; ok {
                return mapped
        }
        return protocol
}

type confidenceScoreRow struct {
        Protocol   string // code-side key (e.g. MTA_STS)
        Calibrated float64
        Raw        float64
        Status     string
}

// asFloat64 tolerates both live Go values (int, float64) and JSON
// round-tripped values (float64, json.Number) for numeric fields.
func asFloat64(v any) (float64, bool) {
        switch n := v.(type) {
        case float64:
                return n, true
        case float32:
                return float64(n), true
        case int:
                return float64(n), true
        case int32:
                return float64(n), true
        case int64:
                return float64(n), true
        case json.Number:
                f, err := n.Float64()
                if err != nil {
                        return 0, false
                }
                return f, true
        }
        return 0, false
}

func clamp01(v float64) float64 {
        if v < 0 {
                return 0
        }
        if v > 1 {
                return 1
        }
        return v
}

// calibratedConfidenceMap normalizes results["calibrated_confidence"] whether
// it is the live map[string]float64 (scan time) or the JSON round-tripped
// map[string]any (backfill). This dual-shape handling is deliberate: the same
// data has two runtime types depending on the code path.
func calibratedConfidenceMap(results map[string]any) map[string]float64 {
        switch m := results["calibrated_confidence"].(type) {
        case map[string]float64:
                return m
        case map[string]any:
                out := make(map[string]float64, len(m))
                for k, v := range m {
                        if f, ok := asFloat64(v); ok {
                                out[k] = f
                        }
                }
                return out
        }
        return nil
}

// extractConfidenceRows builds one row per protocol present in the
// calibrated_confidence map. Protocols absent from the map (older scans,
// engine changes) are skipped — never fabricated.
func extractConfidenceRows(results map[string]any) []confidenceScoreRow {
        calibrated := calibratedConfidenceMap(results)
        if len(calibrated) == 0 {
                return nil
        }
        rows := make([]confidenceScoreRow, 0, len(protocolResultKeys))
        for protocol, resultKey := range protocolResultKeys {
                cc, ok := calibrated[protocol]
                if !ok {
                        continue
                }
                status := ""
                if section, ok := results[resultKey].(map[string]any); ok {
                        status, _ = section[mapKeyStatus].(string) //nolint:errcheck // zero-value fallback is intentional
                }
                rows = append(rows, confidenceScoreRow{
                        Protocol:   protocol,
                        Calibrated: clamp01(cc),
                        Raw:        protocolVerdictSeverity(results, resultKey),
                        Status:     status,
                })
        }
        return rows
}

// aggregateResolverAgreementTolerant mirrors aggregateResolverAgreement but
// accepts JSON round-tripped numerics (float64) as well as live ints.
func aggregateResolverAgreementTolerant(results map[string]any) (int, int) {
        consensus, ok := results["resolver_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        perRecord, ok := consensus["per_record_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        totalAgree := 0
        totalResolvers := 0
        for _, data := range perRecord {
                rd, ok := data.(map[string]any)
                if !ok {
                        continue
                }
                rcF, _ := asFloat64(rd["resolver_count"]) //nolint:errcheck // zero-value fallback is intentional
                rc := int(rcF)
                isConsensus, _ := rd["consensus"].(bool) //nolint:errcheck // zero-value fallback is intentional
                agreeCount := rc
                if !isConsensus {
                        agreeCount = rc - 1
                        if agreeCount < 0 {
                                agreeCount = 0
                        }
                }
                totalAgree += agreeCount
                totalResolvers += rc
        }
        return totalAgree, totalResolvers
}

func numericFromFloat(v float64) (pgtype.Numeric, error) {
        var n pgtype.Numeric
        err := n.Scan(strconv.FormatFloat(v, 'f', 4, 64))
        return n, err
}

func buildConfidenceScoreParams(analysisID int32, domain string, row confidenceScoreRow, agree, total int, scannedAt time.Time, source, appVersion string) (dbq.InsertConfidenceScoreParams, error) {
        score, err := numericFromFloat(row.Calibrated)
        if err != nil {
                return dbq.InsertConfidenceScoreParams{}, err
        }
        calibratedScore, err := numericFromFloat(row.Calibrated)
        if err != nil {
                return dbq.InsertConfidenceScoreParams{}, err
        }
        rawScore, err := numericFromFloat(clamp01(row.Raw))
        if err != nil {
                return dbq.InsertConfidenceScoreParams{}, err
        }

        var resolverCount *int16
        var resolverAgreement pgtype.Numeric // zero value = NULL
        if total > 0 {
                rc := int16(total) //nolint:gosec // resolver counts are single digits
                resolverCount = &rc
                resolverAgreement, err = numericFromFloat(clamp01(float64(agree) / float64(total)))
                if err != nil {
                        return dbq.InsertConfidenceScoreParams{}, err
                }
        }

        // resolver_scope is tagged "aggregate" because agreement is measured
        // across ALL records in the scan, not per protocol — consumers must not
        // read it as protocol-specific.
        factors := map[string]any{
                "status":         row.Status,
                "resolver_scope": "aggregate",
        }
        if appVersion != "" {
                factors["app_version"] = appVersion
        }
        factorsJSON, err := json.Marshal(factors)
        if err != nil {
                return dbq.InsertConfidenceScoreParams{}, err
        }

        return dbq.InsertConfidenceScoreParams{
                AnalysisID:        &analysisID,
                Domain:            domain,
                Protocol:          confidenceProtocolDBName(row.Protocol),
                Score:             score,
                ResolverCount:     resolverCount,
                ResolverAgreement: resolverAgreement,
                EvidenceFactors:   factorsJSON,
                CalibratedScore:   calibratedScore,
                RawScore:          rawScore,
                Source:            source,
                ScannedAt:         pgtype.Timestamptz{Time: scannedAt, Valid: true},
        }, nil
}

// insertConfidenceScores writes one confidence_scores row per calibrated
// protocol. Returns (inserted, skipped). Never fails the caller — errors are
// logged and counted as skips.
func insertConfidenceScores(ctx context.Context, q *dbq.Queries, analysisID int32, domain string, results map[string]any, scannedAt time.Time, source, appVersion string) (int, int) {
        rows := extractConfidenceRows(results)
        if len(rows) == 0 {
                return 0, 0
        }
        agree, total := aggregateResolverAgreementTolerant(results)

        inserted := 0
        skipped := 0
        for _, row := range rows {
                params, err := buildConfidenceScoreParams(analysisID, domain, row, agree, total, scannedAt, source, appVersion)
                if err != nil {
                        slog.Warn("Confidence score params failed", mapKeyDomain, domain, "protocol", row.Protocol, mapKeyError, err)
                        skipped++
                        continue
                }
                affected, err := q.InsertConfidenceScore(ctx, params)
                if err != nil {
                        slog.Warn("Confidence score insert failed", mapKeyDomain, domain, "protocol", row.Protocol, mapKeyError, err)
                        skipped++
                        continue
                }
                if affected > 0 {
                        inserted++
                } else {
                        skipped++ // ON CONFLICT DO NOTHING — row already exists
                }
        }
        return inserted, skipped
}

// persistConfidenceScores is the post-scan side effect (source='scan').
// Runs in a goroutine; must never fail the scan.
func (h *AnalysisHandler) persistConfidenceScores(analysisID int32, domain string, results map[string]any) {
        q := h.rawQueries()
        if q == nil || analysisID <= 0 || len(results) == 0 {
                return
        }
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()

        inserted, skipped := insertConfidenceScores(ctx, q, analysisID, domain, results, time.Now(), confidenceSourceScan, h.Config.AppVersion)
        slog.Info("Confidence scores persisted", mapKeyDomain, domain, "analysis_id", analysisID, "inserted", inserted, "skipped", skipped)
}

// --- Admin backfill (POST /ops/confidence-backfill) ---

type confidenceBackfillStatus struct {
        Running    bool   `json:"running"`
        StartedAt  string `json:"started_at,omitempty"`
        FinishedAt string `json:"finished_at,omitempty"`
        Candidates int64  `json:"candidates"`
        Processed  int    `json:"processed"`
        Inserted   int    `json:"inserted"`
        Skipped    int    `json:"skipped"`
        LastID     int32  `json:"last_id"`
        TotalRows  int64  `json:"total_rows_in_table"`
        Error      string `json:"error,omitempty"`
}

type confidenceBackfillState struct {
        mu         sync.Mutex
        running    bool
        startedAt  time.Time
        finishedAt time.Time
        candidates int64
        processed  int
        inserted   int
        skipped    int
        lastID     int32
        errMsg     string
}

func (s *confidenceBackfillState) snapshot() confidenceBackfillStatus {
        s.mu.Lock()
        defer s.mu.Unlock()
        st := confidenceBackfillStatus{
                Running:    s.running,
                Candidates: s.candidates,
                Processed:  s.processed,
                Inserted:   s.inserted,
                Skipped:    s.skipped,
                LastID:     s.lastID,
                Error:      s.errMsg,
        }
        if !s.startedAt.IsZero() {
                st.StartedAt = s.startedAt.UTC().Format(time.RFC3339)
        }
        if !s.finishedAt.IsZero() {
                st.FinishedAt = s.finishedAt.UTC().Format(time.RFC3339)
        }
        return st
}

// ConfidenceBackfillHandler replays historical domain_analyses.full_results
// into confidence_scores. Admin-only; idempotent (ON CONFLICT DO NOTHING).
type ConfidenceBackfillHandler struct {
        DB    *db.Database
        state confidenceBackfillState
}

func NewConfidenceBackfillHandler(database *db.Database) *ConfidenceBackfillHandler {
        return &ConfidenceBackfillHandler{DB: database}
}

// Start launches the backfill in a background goroutine. 409 if already running.
func (h *ConfidenceBackfillHandler) Start(c *gin.Context) {
        if h.DB == nil || h.DB.Queries == nil {
                c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
                return
        }

        h.state.mu.Lock()
        if h.state.running {
                h.state.mu.Unlock()
                c.JSON(http.StatusConflict, h.state.snapshot())
                return
        }
        h.state.running = true
        h.state.startedAt = time.Now()
        h.state.finishedAt = time.Time{}
        h.state.processed = 0
        h.state.inserted = 0
        h.state.skipped = 0
        h.state.lastID = 0
        h.state.errMsg = ""
        h.state.mu.Unlock()

        candidates, err := h.DB.Queries.CountConfidenceBackfillCandidates(c.Request.Context())
        if err != nil {
                slog.Warn("Confidence backfill candidate count failed", "error", err)
                candidates = 0
        }
        h.state.mu.Lock()
        h.state.candidates = candidates
        h.state.mu.Unlock()

        go h.run()

        slog.Info("Confidence backfill started", "candidates", candidates)
        c.JSON(http.StatusAccepted, h.state.snapshot())
}

// Status reports progress plus the current confidence_scores row count.
func (h *ConfidenceBackfillHandler) Status(c *gin.Context) {
        st := h.state.snapshot()
        if h.DB != nil && h.DB.Queries != nil {
                if total, err := h.DB.Queries.CountConfidenceScores(c.Request.Context()); err == nil {
                        st.TotalRows = total
                }
        }
        c.JSON(http.StatusOK, st)
}

const confidenceBackfillBatchSize = 500

func (h *ConfidenceBackfillHandler) run() {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
        defer cancel()

        q := h.DB.Queries
        cursor := int32(0)

        defer func() {
                h.state.mu.Lock()
                h.state.running = false
                h.state.finishedAt = time.Now()
                h.state.mu.Unlock()
                st := h.state.snapshot()
                slog.Info("Confidence backfill finished",
                        "processed", st.Processed, "inserted", st.Inserted,
                        "skipped", st.Skipped, "error", st.Error)
        }()

        for {
                batch, err := q.ListConfidenceBackfillBatch(ctx, dbq.ListConfidenceBackfillBatchParams{
                        ID:    cursor,
                        Limit: confidenceBackfillBatchSize,
                })
                if err != nil {
                        h.state.mu.Lock()
                        h.state.errMsg = err.Error()
                        h.state.mu.Unlock()
                        return
                }
                if len(batch) == 0 {
                        return
                }

                for _, rec := range batch {
                        cursor = rec.ID

                        var results map[string]any
                        if err := json.Unmarshal(rec.FullResults, &results); err != nil {
                                h.state.mu.Lock()
                                h.state.processed++
                                h.state.skipped++
                                h.state.lastID = rec.ID
                                h.state.mu.Unlock()
                                continue
                        }

                        scannedAt := time.Now()
                        if rec.CreatedAt.Valid {
                                scannedAt = rec.CreatedAt.Time
                        }

                        ins, skip := insertConfidenceScores(ctx, q, rec.ID, rec.AsciiDomain, results, scannedAt, confidenceSourceImport, "")

                        h.state.mu.Lock()
                        h.state.processed++
                        h.state.inserted += ins
                        h.state.skipped += skip
                        h.state.lastID = rec.ID
                        h.state.mu.Unlock()
                }
        }
}
