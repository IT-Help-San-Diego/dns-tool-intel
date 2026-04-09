package handlers

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func TestShouldServeAsyncWait_GET_NoSync(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)

        if !shouldServeAsyncWait(c, nil, false) {
                t.Error("expected true for plain GET without sync=1")
        }
}

func TestShouldServeAsyncWait_GET_Sync1(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&sync=1", nil)

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false when sync=1 is set")
        }
}

func TestShouldServeAsyncWait_POST(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze?domain=example.com", nil)

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false for POST requests")
        }
}

func TestShouldServeAsyncWait_FetchHeader(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)
        c.Request.Header.Set("X-Requested-With", "fetch")

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false when X-Requested-With: fetch is set")
        }
}

func TestShouldServeAsyncWait_AgentCacheEligible(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false for agent-cache-eligible requests")
        }
}

func TestShouldServeAsyncWait_CustomSelectorsNotAgent(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)

        if !shouldServeAsyncWait(c, []string{"sel1"}, false) {
                t.Error("expected true: custom selectors without src=agent should still serve async wait")
        }
}

func waitPageRouter() *gin.Engine {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        tmpl := template.New("")
        template.Must(tmpl.New("head").Parse(``))
        template.Must(tmpl.New("head_css").Parse(``))
        template.Must(tmpl.New("scan_overlay_content").Parse(`<div class="scan-overlay-domain"></div>`))
        template.Must(tmpl.New("scan_topology").Parse(`<div id="scanTopology"></div>`))
        template.Must(tmpl.New("scripts").Parse(``))
        template.Must(tmpl.New("scan_wait.html").Parse(
                `<!DOCTYPE html><html><head>{{template "head" .}}{{template "head_css" .}}</head>` +
                        `<body><output id="loadingOverlay">{{template "scan_overlay_content" .}}</output>` +
                        `<div data-token="{{.ScanToken}}" data-domain="{{.AsciiDomain}}"></div>` +
                        `{{template "scripts" .}}</body></html>`))
        r.SetHTMLTemplate(tmpl)
        return r
}

func TestRenderWaitingPage_HeadersAndContent(t *testing.T) {
        router := waitPageRouter()
        cfg := &config.Config{AppVersion: "test", BaseURL: "https://test.example"}
        h := &AnalysisHandler{Config: cfg, ProgressStore: NewProgressStore()}
        defer h.ProgressStore.Close()

        router.GET("/analyze", func(c *gin.Context) {
                h.renderWaitingPage(c, "tok-abc123", "example.com", "example.com")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        if cc := w.Header().Get("Cache-Control"); cc != "no-store, private, max-age=0" {
                t.Errorf("expected no-store Cache-Control, got %q", cc)
        }
        if xr := w.Header().Get("X-Robots-Tag"); xr != "noindex, nofollow" {
                t.Errorf("expected noindex X-Robots-Tag, got %q", xr)
        }
        body := w.Body.String()
        if !strings.Contains(body, "tok-abc123") {
                t.Error("response body should contain the scan token")
        }
        if !strings.Contains(body, "example.com") {
                t.Error("response body should contain the domain")
        }
        if !strings.Contains(body, "loadingOverlay") {
                t.Error("response body should contain loadingOverlay element")
        }
}

func TestRenderWaitingPage_Sync1Bypass(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&sync=1", nil)

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("sync=1 should bypass async waiting page")
        }
}

func TestShouldServeAsyncWait_AgentCacheHitPreserved(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("agent cache-eligible requests must not enter async wait path")
        }

        if !isAgentCacheEligible(c, nil, false) {
                t.Error("expected request to be agent-cache-eligible")
        }
}

func TestShouldServeAsyncWait_POSTFormUnchanged(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=example.com"))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("POST form submissions must not enter async wait path")
        }
}

func TestShouldServeAsyncWait_JSONAsyncUnchanged(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader("domain=example.com"))
        c.Request.Header.Set("Accept", "application/json")
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

        if shouldServeAsyncWait(c, nil, false) {
                t.Error("JSON async POST must not enter async wait path")
        }
}
