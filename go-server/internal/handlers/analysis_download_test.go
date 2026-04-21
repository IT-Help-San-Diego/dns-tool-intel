package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
)

func downloadAPIRouter(h *AnalysisHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	tmpl := template.Must(template.New("").Parse(
		`{{define "index.html"}}ok{{end}}` +
			`{{define "results.html"}}ok{{end}}`,
	))
	r.SetHTMLTemplate(tmpl)
	r.GET("/api/analysis/:id", h.APIAnalysis)
	return r
}

// TestAPIAnalysis_DownloadParamRejectsArbitraryValue covers the strict
// whitelist added to silence Qualys WAS QID 150743. Anything other than
// "" or "1" must be rejected with HTTP 400 BEFORE any DB or hash work.
func TestAPIAnalysis_DownloadParamRejectsArbitraryValue(t *testing.T) {
	called := false
	h := newViewModeHandler(&mockAnalysisStore{
		GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
			called = true
			return dbq.DomainAnalysis{}, nil
		},
	})
	r := downloadAPIRouter(h)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/analysis/1?download=evil", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("download=evil: got status %d, want 400", w.Code)
	}
	if called {
		t.Error("download=evil: store should NOT be queried before validation")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body not JSON: %v", err)
	}
	if msg, _ := body["error"].(string); msg == "" {
		t.Error("expected non-empty error message in JSON response")
	}
}

// TestAPIAnalysis_DownloadParamOneSetsAttachment confirms that download=1
// (the only accepted truthy value) returns 200 with an attachment
// Content-Disposition header naming the analyzed domain.
func TestAPIAnalysis_DownloadParamOneSetsAttachment(t *testing.T) {
	results := map[string]any{"analysis_success": true, "_tool_version": "test"}
	resultsJSON, _ := json.Marshal(results)

	h := newViewModeHandler(&mockAnalysisStore{
		GetAnalysisByIDFn: func(ctx context.Context, id int32) (dbq.DomainAnalysis, error) {
			return dbq.DomainAnalysis{
				ID:          id,
				Domain:      "example.com",
				AsciiDomain: "example.com",
				FullResults: resultsJSON,
				CreatedAt:   pgtype.Timestamp{Valid: true},
			}, nil
		},
	})
	r := downloadAPIRouter(h)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/analysis/1?download=1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("download=1: got status %d, want 200", w.Code)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q, want attachment; ...", cd)
	}
	if !strings.Contains(cd, "example.com") {
		t.Errorf("Content-Disposition %q should reference the domain", cd)
	}
}
