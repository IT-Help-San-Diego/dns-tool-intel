//go:build coverage

package handlers

import (
	"bytes"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func zoneConfig2() *config.Config {
	return &config.Config{
		AppVersion:    "test-v2",
		BetaPages:     map[string]bool{},
		SectionTuning: map[string]string{},
	}
}

func zoneRouter2() *gin.Engine {
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

func TestZone_ProcessUpload_WithFile_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter2()
	router.POST("/zone", handler.ProcessUpload)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("zone_file", "test.zone")
	if err != nil {
		t.Fatal(err)
	}
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 2024010101 3600 600 604800 1800
@ IN NS ns1.example.com.
@ IN NS ns2.example.com.
@ IN A 1.2.3.4
www IN A 1.2.3.4
@ IN MX 10 mail.example.com.
`
	part.Write([]byte(zoneContent))
	writer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload with valid zone: got %d, want 200", w.Code)
	}
}

func TestZone_ProcessUpload_EmptyFile_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter2()
	router.POST("/zone", handler.ProcessUpload)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("zone_file", "empty.zone")
	part.Write([]byte(""))
	writer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload with empty zone: got %d, want 200", w.Code)
	}
}

func TestZone_ProcessUpload_OversizedFile_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter2()
	router.POST("/zone", handler.ProcessUpload)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("zone_file", "big.zone")
	bigData := make([]byte, maxZoneFileSizeUnauth+1)
	for i := range bigData {
		bigData[i] = 'x'
	}
	part.Write(bigData)
	writer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload oversized: got %d, want 200 (with error flash)", w.Code)
	}
}

func TestZone_ProcessUpload_Authenticated_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("csp_nonce", "test-nonce")
		c.Set("csrf_token", "test-csrf")
		c.Set("user_id", int32(1))
		c.Next()
	})
	tmpl := template.New("root")
	template.Must(tmpl.New("zone.html").Parse(`OK`))
	router.SetHTMLTemplate(tmpl)
	router.POST("/zone", handler.ProcessUpload)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("zone_file", "test.zone")
	zoneContent := `$ORIGIN test.com.
$TTL 3600
@ IN SOA ns1.test.com. admin.test.com. 2024010101 3600 600 604800 1800
@ IN A 5.6.7.8
`
	part.Write([]byte(zoneContent))
	writer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload authenticated: got %d, want 200", w.Code)
	}
}

func TestZone_NewZoneHandler_Coverage_C2(t *testing.T) {
	h := NewZoneHandler(nil, nil)
	if h == nil {
		t.Fatal("expected handler")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestZone_ProcessUpload_DomainOverride_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter2()
	router.POST("/zone", handler.ProcessUpload)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("zone_file", "noorigin.zone")
	zoneContent := `@ IN A 1.2.3.4
www IN A 1.2.3.4
`
	part.Write([]byte(zoneContent))
	writer.WriteField("domain_override", "override.com")
	writer.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/zone", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ProcessUpload with override: got %d, want 200", w.Code)
	}
}

func TestZone_RenderZoneFlash_Warning_C2(t *testing.T) {
	database := adminTestDB(t)
	cfg := zoneConfig2()
	handler := NewZoneHandler(database, cfg)
	router := zoneRouter2()
	router.GET("/test-flash", func(c *gin.Context) {
		handler.renderZoneFlash(c, "warning", "Test warning message")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-flash", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("renderZoneFlash warning: got %d, want 200", w.Code)
	}
}
