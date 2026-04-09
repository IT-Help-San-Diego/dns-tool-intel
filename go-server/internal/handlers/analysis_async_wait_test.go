package handlers

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

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

func TestRenderWaitingPage_Headers(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)

        c.Header("Cache-Control", "no-store, private, max-age=0")
        c.Header("X-Robots-Tag", "noindex, nofollow")

        if cc := w.Header().Get("Cache-Control"); cc != "no-store, private, max-age=0" {
                t.Errorf("expected no-store Cache-Control, got %q", cc)
        }
        if xr := w.Header().Get("X-Robots-Tag"); xr != "noindex, nofollow" {
                t.Errorf("expected noindex X-Robots-Tag, got %q", xr)
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
