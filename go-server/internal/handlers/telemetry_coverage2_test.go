//go:build coverage

package handlers

import (
        "context"
        "encoding/json"
        "html/template"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
)

func telemetryConfig2() *config.Config {
        return &config.Config{
                AppVersion:    "test",
                BetaPages:     map[string]bool{},
                SectionTuning: map[string]string{},
        }
}

func telemetryRouter2() *gin.Engine {
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

func TestTelemetryHandler_VerifyHash_InvalidID_C2(t *testing.T) {
        h := NewTelemetryHandler(nil, telemetryConfig2())
        router := telemetryRouter2()
        router.GET("/telemetry/verify/:id", h.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry/verify/abc", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
        var resp map[string]any
        json.NewDecoder(w.Body).Decode(&resp)
        if resp["error"] != "invalid analysis ID" {
                t.Errorf("expected error message, got %v", resp["error"])
        }
}

func TestTelemetryHandler_VerifyHash_NoDB_C2(t *testing.T) {
        database := adminTestDB(t)
        cfg := telemetryConfig2()
        h := NewTelemetryHandler(database, cfg)
        h.TimingsFunc = func(ctx context.Context, analysisID int32) ([]dbq.ScanPhaseTelemetry, error) {
                return nil, nil
        }
        router := telemetryRouter2()
        router.GET("/telemetry/verify/:id", h.VerifyHash)

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/telemetry/verify/999999", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusNotFound {
                t.Errorf("expected 404 for missing hash, got %d", w.Code)
        }
}

func TestTelemetryHandler_Fields_C2(t *testing.T) {
        h := NewTelemetryHandler(nil, telemetryConfig2())
        if h.DB != nil {
                t.Error("expected nil DB")
        }
        if h.Config == nil {
                t.Error("expected non-nil Config")
        }
        if h.TimingsFunc != nil {
                t.Error("expected nil TimingsFunc by default")
        }
}
