package handlers

import (
        "context"
        "encoding/json"
        "errors"
        "fmt"
        "html/template"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

func telemetryTestDB(t *testing.T) *db.Database {
        t.Helper()
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                t.Skip("DATABASE_URL not set")
        }
        database, err := db.ConnectForTests(dbURL)
        if err != nil {
                t.Fatalf("connect: %v", err)
        }
        t.Cleanup(func() { database.Close() })
        return database
}

func telemetryRouter() *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        r.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        tmpl := template.New("root")
        template.Must(tmpl.New("admin_telemetry.html").Parse(`OK`))
        r.SetHTMLTemplate(tmpl)
        return r
}

func TestTelemetry_Dashboard_Renders(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}
        router := telemetryRouter()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Dashboard: got %d, want 200; body: %s", w.Code, w.Body.String())
        }
}

func TestTelemetry_VerifyHash_BadID(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry/verify/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Fatalf("VerifyHash bad ID: got %d, want 400", w.Code)
        }
        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response not valid JSON: %v", err)
        }
        if body["error"] != "invalid analysis ID" {
                t.Errorf("unexpected error message: %v", body["error"])
        }
}

func TestTelemetry_VerifyHash_NonexistentID(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry/verify/999999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("VerifyHash nonexistent: got %d, want 404", w.Code)
        }
        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response not valid JSON: %v", err)
        }
        if body["error"] != "telemetry hash not found" {
                t.Errorf("unexpected error: %v", body["error"])
        }
}

func TestTelemetry_VerifyHash_NegativeID(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry/verify/-1", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
                t.Fatalf("VerifyHash negative ID: got %d, want 400 or 404", w.Code)
        }
}

var knownPhaseTimings = []analyzer.PhaseTiming{
        {PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 120, RecordCount: 4},
        {PhaseGroup: "dns_records", PhaseTask: "auth", StartedAtMs: 120, DurationMs: 85, RecordCount: 2},
        {PhaseGroup: "security", PhaseTask: "dnssec", StartedAtMs: 205, DurationMs: 340, RecordCount: 6},
        {PhaseGroup: "network", PhaseTask: "connectivity", StartedAtMs: 545, DurationMs: 210, RecordCount: 3},
        {PhaseGroup: "performance", PhaseTask: "latency", StartedAtMs: 755, DurationMs: 745, RecordCount: 8},
}

var knownTotalDurationMs = 1500

func ensureTelemetryHash(t *testing.T, database *db.Database) int32 {
        t.Helper()
        ctx := context.Background()

        realHash := analyzer.ComputeTelemetryHash(knownPhaseTimings)

        var analysisID int32
        err := database.Pool.QueryRow(ctx,
                `INSERT INTO domain_analyses (domain, ascii_domain, full_results, created_at)
                 VALUES ('telemetry-hash-test.example.com', 'telemetry-hash-test.example.com', '{}', NOW()) RETURNING id`).Scan(&analysisID)
        if err != nil {
                t.Skipf("cannot create test analysis for telemetry: %v", err)
        }
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM scan_phase_telemetry WHERE analysis_id = $1`, analysisID)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM scan_telemetry_hash WHERE analysis_id = $1`, analysisID)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM domain_analyses WHERE id = $1`, analysisID)
        })

        for _, pt := range knownPhaseTimings {
                _, err := database.Pool.Exec(ctx,
                        `INSERT INTO scan_phase_telemetry (analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count)
                         VALUES ($1, $2, $3, $4, $5, $6)`,
                        analysisID, pt.PhaseGroup, pt.PhaseTask, pt.StartedAtMs, pt.DurationMs, pt.RecordCount)
                if err != nil {
                        t.Skipf("cannot insert test phase telemetry: %v", err)
                }
        }

        _, err = database.Pool.Exec(ctx,
                `INSERT INTO scan_telemetry_hash (analysis_id, total_duration_ms, phase_count, sha3_512)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (analysis_id) DO NOTHING`,
                analysisID, knownTotalDurationMs, len(knownPhaseTimings), realHash)
        if err != nil {
                t.Skipf("cannot insert test telemetry hash: %v", err)
        }
        return analysisID
}

func TestTelemetry_VerifyHash_CanceledContext_Returns404(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        validID := ensureTelemetryHash(t, database)

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                canceledCtx, cancel := context.WithCancel(c.Request.Context())
                cancel()
                c.Request = c.Request.WithContext(canceledCtx)
                c.Next()
        })

        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/telemetry/verify/%d", validID), nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Fatalf("VerifyHash with canceled context: want 404 (hash query fails first), got %d", w.Code)
        }
        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response is not valid JSON: %v", err)
        }
        if errMsg, ok := body["error"].(string); !ok || errMsg != "telemetry hash not found" {
                t.Fatalf("expected error='telemetry hash not found', got %v", body["error"])
        }
}

func TestTelemetry_VerifyHash_RealSHA3_VerifiedTrue(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        validID := ensureTelemetryHash(t, database)
        expectedHash := analyzer.ComputeTelemetryHash(knownPhaseTimings)

        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/telemetry/verify/%d", validID), nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("VerifyHash: got %d, want 200, body=%s", w.Code, w.Body.String())
        }

        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response not valid JSON: %v", err)
        }

        verified, ok := body["verified"].(bool)
        if !ok {
                t.Fatal("'verified' field missing or not boolean")
        }
        if !verified {
                storedHash, _ := body["stored_hash"].(string)
                recomputedHash, _ := body["recomputed_hash"].(string)
                t.Fatalf("verified should be true for real SHA3 hash: stored=%s recomputed=%s", storedHash, recomputedHash)
        }

        storedHash, _ := body["stored_hash"].(string)
        recomputedHash, _ := body["recomputed_hash"].(string)
        if storedHash != expectedHash {
                t.Fatalf("stored_hash = %q, want computed SHA3 hash %q", storedHash, expectedHash)
        }
        if recomputedHash != expectedHash {
                t.Fatalf("recomputed_hash = %q, want computed SHA3 hash %q", recomputedHash, expectedHash)
        }

        phaseCount, _ := body["phase_count"].(float64)
        if int(phaseCount) != len(knownPhaseTimings) {
                t.Errorf("phase_count = %d, want %d", int(phaseCount), len(knownPhaseTimings))
        }
        totalDuration, _ := body["total_duration_ms"].(float64)
        if int(totalDuration) != knownTotalDurationMs {
                t.Errorf("total_duration_ms = %d, want %d", int(totalDuration), knownTotalDurationMs)
        }
}

func TestTelemetry_VerifyHash_TamperedHash_VerifiedFalse(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        ctx := context.Background()

        var analysisID int32
        err := database.Pool.QueryRow(ctx,
                `INSERT INTO domain_analyses (domain, ascii_domain, full_results, created_at)
                 VALUES ('telemetry-tamper-test.example.com', 'telemetry-tamper-test.example.com', '{}', NOW()) RETURNING id`).Scan(&analysisID)
        if err != nil {
                t.Skipf("cannot create test analysis: %v", err)
        }
        t.Cleanup(func() {
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM scan_phase_telemetry WHERE analysis_id = $1`, analysisID)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM scan_telemetry_hash WHERE analysis_id = $1`, analysisID)
                _, _ = database.Pool.Exec(context.Background(), `DELETE FROM domain_analyses WHERE id = $1`, analysisID)
        })

        for _, pt := range knownPhaseTimings {
                _, err := database.Pool.Exec(ctx,
                        `INSERT INTO scan_phase_telemetry (analysis_id, phase_group, phase_task, started_at_ms, duration_ms, record_count)
                         VALUES ($1, $2, $3, $4, $5, $6)`,
                        analysisID, pt.PhaseGroup, pt.PhaseTask, pt.StartedAtMs, pt.DurationMs, pt.RecordCount)
                if err != nil {
                        t.Skipf("cannot insert phase telemetry: %v", err)
                }
        }

        tamperedHash := "deadbeef" + strings.Repeat("00", 60)
        _, err = database.Pool.Exec(ctx,
                `INSERT INTO scan_telemetry_hash (analysis_id, total_duration_ms, phase_count, sha3_512)
                 VALUES ($1, $2, $3, $4)`,
                analysisID, knownTotalDurationMs, len(knownPhaseTimings), tamperedHash)
        if err != nil {
                t.Skipf("cannot insert tampered hash: %v", err)
        }

        gin.SetMode(gin.TestMode)
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/telemetry/verify/%d", analysisID), nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("VerifyHash tampered: got %d, want 200", w.Code)
        }

        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response not valid JSON: %v", err)
        }

        verified, ok := body["verified"].(bool)
        if !ok {
                t.Fatal("'verified' field missing or not boolean")
        }
        if verified {
                t.Fatal("verified should be false: stored hash was deliberately tampered")
        }

        storedHash, _ := body["stored_hash"].(string)
        if storedHash != tamperedHash {
                t.Fatalf("stored_hash = %q, want tampered hash %q", storedHash, tamperedHash)
        }

        recomputedHash, _ := body["recomputed_hash"].(string)
        realHash := analyzer.ComputeTelemetryHash(knownPhaseTimings)
        if recomputedHash != realHash {
                t.Fatalf("recomputed_hash = %q, want real SHA3 %q", recomputedHash, realHash)
        }
}

func TestTelemetry_VerifyHash_TimingsQueryFails_Returns500(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        validID := ensureTelemetryHash(t, database)

        gin.SetMode(gin.TestMode)
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        handler.TimingsFunc = func(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
                return nil, errors.New("injected DB connection failure")
        }
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/telemetry/verify/%d", validID), nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusInternalServerError {
                t.Fatalf("VerifyHash with failing timings query: want 500, got %d body=%s", w.Code, w.Body.String())
        }
        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response is not valid JSON: %v", err)
        }
        errMsg, ok := body["error"].(string)
        if !ok || errMsg != "failed to load telemetry" {
                t.Fatalf("expected error='failed to load telemetry', got %v", body["error"])
        }
}

func TestTelemetry_VerifyHash_SuccessResponse_ContractVerified(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        validID := ensureTelemetryHash(t, database)
        expectedHash := analyzer.ComputeTelemetryHash(knownPhaseTimings)

        gin.SetMode(gin.TestMode)
        router := gin.New()
        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry/verify/:id", handler.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/telemetry/verify/%d", validID), nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("VerifyHash for valid ID: want 200, got %d body=%s", w.Code, w.Body.String())
        }

        var body map[string]any
        if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
                t.Fatalf("response is not valid JSON: %v", err)
        }

        requiredFields := []string{"analysis_id", "stored_hash", "recomputed_hash", "verified", "phase_count", "total_duration_ms"}
        for _, field := range requiredFields {
                if _, ok := body[field]; !ok {
                        t.Errorf("response missing required field %q", field)
                }
        }

        storedHash, ok := body["stored_hash"].(string)
        if !ok || storedHash == "" {
                t.Fatal("stored_hash must be a non-empty string")
        }
        if storedHash != expectedHash {
                t.Fatalf("stored_hash = %q, want real SHA3 hash %q", storedHash, expectedHash)
        }

        recomputedHash, ok := body["recomputed_hash"].(string)
        if !ok || recomputedHash != expectedHash {
                t.Fatalf("recomputed_hash = %q, want real SHA3 hash %q", recomputedHash, expectedHash)
        }

        analysisIDFloat, ok := body["analysis_id"].(float64)
        if !ok || int32(analysisIDFloat) != validID {
                t.Fatalf("analysis_id = %v, want %d", body["analysis_id"], validID)
        }

        verified, ok := body["verified"].(bool)
        if !ok || !verified {
                t.Fatalf("verified = %v, want true (real SHA3 hash should match)", body["verified"])
        }
}

func TestTelemetry_Dashboard_DBQueryCovers_TrendData(t *testing.T) {
        database := telemetryTestDB(t)
        cfg := &config.Config{AppVersion: "test", BetaPages: map[string]bool{}, SectionTuning: map[string]string{}}

        gin.SetMode(gin.TestMode)
        router := gin.New()
        router.Use(func(c *gin.Context) {
                c.Set("csp_nonce", "test-nonce")
                c.Set("csrf_token", "test-csrf")
                c.Next()
        })
        tmpl := template.New("root")
        template.Must(tmpl.New("admin_telemetry.html").Parse(
                `Summaries={{len .Summaries}} TrendsJSON={{.TrendsJSON}}`))
        router.SetHTMLTemplate(tmpl)

        handler := NewTelemetryHandler(database, cfg)
        router.GET("/telemetry", handler.Dashboard)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("Dashboard with trend template: got %d, want 200", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Summaries=") {
                t.Errorf("template output missing Summaries: %s", body)
        }
        if !strings.Contains(body, "TrendsJSON=") {
                t.Errorf("template output missing TrendsJSON: %s", body)
        }

        trendsStart := strings.Index(body, "TrendsJSON=")
        if trendsStart == -1 {
                t.Fatal("TrendsJSON not found in output")
        }
        trendsRaw := body[trendsStart+len("TrendsJSON="):]
        trendsRaw = strings.TrimSpace(trendsRaw)
        if trendsRaw != "" {
                var trendsPayload any
                if err := json.Unmarshal([]byte(trendsRaw), &trendsPayload); err != nil {
                        if trendsRaw != "null" && trendsRaw != "[]" {
                                t.Logf("TrendsJSON is not parseable JSON (may contain template escaping): %s", trendsRaw[:min(100, len(trendsRaw))])
                        }
                } else {
                        switch v := trendsPayload.(type) {
                        case []any:
                                t.Logf("TrendsJSON is a valid JSON array with %d entries", len(v))
                        case nil:
                                t.Log("TrendsJSON is null (no trend data)")
                        default:
                                t.Errorf("TrendsJSON should be a JSON array or null, got %T", v)
                        }
                }
        }
}
