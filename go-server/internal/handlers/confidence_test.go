package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestConfidenceHandler_NilDB(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewConfidenceHandler(cfg, nil)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("confidence.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/confidence", h.Confidence)
	req := httptest.NewRequest(http.MethodGet, "/confidence", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Error("expected rendered template body")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html", w.Header().Get("Content-Type"))
	}
}

func TestConfidenceHandler_AuditQ_NilDBAndStore(t *testing.T) {
	h := &ConfidenceHandler{Config: &config.Config{}}
	if h.auditQ() != nil {
		t.Error("auditQ should return nil when both DB and auditStore are nil")
	}
}

func TestConfidenceHandler_PostNotAllowed(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{}}
	h := NewConfidenceHandler(cfg, nil)

	w := httptest.NewRecorder()
	tmpl := mustParseMinimalTemplate("confidence.html")
	router := gin.New()
	router.SetHTMLTemplate(tmpl)
	router.GET("/confidence", h.Confidence)
	req := httptest.NewRequest(http.MethodPost, "/confidence", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("POST should not return 200")
	}
}
