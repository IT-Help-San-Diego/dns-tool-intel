//go:build coverage

package handlers

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func zoneConfig() *config.Config {
	return &config.Config{
		AppVersion:    "test",
		BetaPages:     map[string]bool{},
		SectionTuning: map[string]string{},
	}
}

func zoneRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("csp_nonce", "test-nonce")
		c.Set("csrf_token", "test-csrf")
		c.Next()
	})
	tmpl := template.New("root")
	template.Must(tmpl.New("zone.html").Parse(`OK`))
	r.SetHTMLTemplate(tmpl)
	return r
}

func TestZone_UploadForm(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter()
	router.GET("/zone", handler.UploadForm)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/zone", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("UploadForm: got %d, want 200", w.Code)
	}
}

func TestZone_ProcessUpload_NoFile(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter()
	router.POST("/zone", handler.ProcessUpload)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", nil)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=testboundary")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload no file: got %d, want 200 (with flash)", w.Code)
	}
}

func TestZone_ProcessUpload_Unauthenticated(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter()
	router.POST("/zone", handler.ProcessUpload)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload unauthenticated: got %d, want 200", w.Code)
	}
}

func TestZone_RenderZoneFlash(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter()
	router.GET("/test-flash", func(c *gin.Context) {
		handler.renderZoneFlash(c, "danger", "Test error message")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-flash", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("renderZoneFlash: got %d, want 200", w.Code)
	}
}
