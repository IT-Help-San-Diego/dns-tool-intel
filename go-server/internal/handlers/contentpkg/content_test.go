package contentpkg

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func stubTemplateData(c *gin.Context, cfg *config.Config, activePage string) gin.H {
	return gin.H{
		"AppVersion": cfg.AppVersion,
		"ActivePage": activePage,
	}
}

func mustParseMinimalTemplate(name string) *template.Template {
	return template.Must(template.New(name).Parse("{{define \"" + name + "\"}}ok{{end}}"))
}

func TestAboutHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewAboutHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("about.html"))
	router.GET("/about", h.About)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/about", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("expected rendered template")
	}
}

func TestApproachHandler(t *testing.T) {
	cfg := &config.Config{
		AppVersion:    "26.0.0",
		BetaPages:     map[string]bool{},
		YouTubeVideoIDs: map[string]string{"forgotten-domain": "abc123"},
	}
	h := NewApproachHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("approach.html"))
	router.GET("/approach", h.Approach)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/approach", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestArchitectureHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewArchitectureHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("architecture.html"))
	router.GET("/architecture", h.Architecture)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/architecture", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestColorScienceHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewColorScienceHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("color_science.html"))
	router.GET("/color-science", h.ColorScience)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/color-science", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCommunicationStandardsHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewCommunicationStandardsHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("communication_standards.html"))
	router.GET("/communication-standards", h.CommunicationStandards)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/communication-standards", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestContactHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewContactHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("contact.html"))
	router.GET("/contact", h.Contact)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/contact", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestFAQHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewFAQHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("faq_subdomains.html"))
	router.GET("/faq/subdomains", h.SubdomainDiscovery)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/faq/subdomains", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestManifestoHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewManifestoHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("manifesto.html"))
	router.GET("/manifesto", h.Manifesto)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/manifesto", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestPrivacyHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewPrivacyHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("privacy.html"))
	router.GET("/privacy", h.Privacy)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/privacy", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestReferenceLibraryHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewReferenceLibraryHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("reference_library.html"))
	router.GET("/reference-library", h.ReferenceLibrary)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/reference-library", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestROEHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewROEHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("roe.html"))
	router.GET("/roe", h.ROE)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/roe", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestSecurityPolicyHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "26.0.0", BetaPages: map[string]bool{}}
	h := NewSecurityPolicyHandler(cfg, stubTemplateData)
	w := httptest.NewRecorder()
	router := gin.New()
	router.SetHTMLTemplate(mustParseMinimalTemplate("security_policy.html"))
	router.GET("/security-policy", h.SecurityPolicy)
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/security-policy", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestNilConfig(t *testing.T) {
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h := NewAboutHandler(nil, stubTemplateData)
		if h == nil {
			t.Fatal("expected non-nil handler")
		}
	}()
	if panicked {
		t.Error("NewAboutHandler should not panic with nil config")
	}
}
