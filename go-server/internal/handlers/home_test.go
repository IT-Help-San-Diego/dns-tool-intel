package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestApplyWelcomeOrFlash(t *testing.T) {
	t.Run("welcome parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?welcome=Alice", nil)
		data := gin.H{}
		applyWelcomeOrFlash(c, data)
		if data["WelcomeName"] != "Alice" {
			t.Errorf("WelcomeName = %v, want Alice", data["WelcomeName"])
		}
	})

	t.Run("welcome truncated at 100", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		longName := ""
		for i := 0; i < 120; i++ {
			longName += "x"
		}
		c.Request = httptest.NewRequest(http.MethodGet, "/?welcome="+longName, nil)
		data := gin.H{}
		applyWelcomeOrFlash(c, data)
		name, ok := data["WelcomeName"].(string)
		if !ok {
			t.Fatal("expected WelcomeName to be string")
		}
		if len(name) != 100 {
			t.Errorf("expected length 100, got %d", len(name))
		}
	})

	t.Run("no welcome falls through to flash", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=test+message&flash_cat=success", nil)
		data := gin.H{}
		applyWelcomeOrFlash(c, data)
		if _, ok := data["WelcomeName"]; ok {
			t.Error("should not have WelcomeName")
		}
		msgs, ok := data["FlashMessages"].([]FlashMessage)
		if !ok {
			t.Fatal("expected FlashMessages")
		}
		if len(msgs) != 1 || msgs[0].Category != "success" {
			t.Errorf("unexpected flash: %+v", msgs)
		}
	})

	t.Run("no params does nothing", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		data := gin.H{}
		applyWelcomeOrFlash(c, data)
		if _, ok := data["WelcomeName"]; ok {
			t.Error("should not have WelcomeName")
		}
		if _, ok := data["FlashMessages"]; ok {
			t.Error("should not have FlashMessages")
		}
	})
}

func TestApplyFlashFromQuery(t *testing.T) {
	t.Run("no flash param", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		if _, ok := data["FlashMessages"]; ok {
			t.Error("should not have FlashMessages")
		}
	})

	t.Run("flash with default category", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=hello", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		msgs := data["FlashMessages"].([]FlashMessage)
		if msgs[0].Category != "warning" {
			t.Errorf("expected default category 'warning', got %q", msgs[0].Category)
		}
		if msgs[0].Message != "hello" {
			t.Errorf("message = %q, want hello", msgs[0].Message)
		}
	})

	t.Run("flash with success category", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=done&flash_cat=success", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		msgs := data["FlashMessages"].([]FlashMessage)
		if msgs[0].Category != "success" {
			t.Errorf("category = %q, want success", msgs[0].Category)
		}
	})

	t.Run("flash with danger category", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=err&flash_cat=danger", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		msgs := data["FlashMessages"].([]FlashMessage)
		if msgs[0].Category != "danger" {
			t.Errorf("category = %q, want danger", msgs[0].Category)
		}
	})

	t.Run("invalid category defaults to warning", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=test&flash_cat=invalid", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		msgs := data["FlashMessages"].([]FlashMessage)
		if msgs[0].Category != "warning" {
			t.Errorf("category = %q, want warning", msgs[0].Category)
		}
	})

	t.Run("long message truncated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		longMsg := ""
		for i := 0; i < 250; i++ {
			longMsg += "a"
		}
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash="+longMsg, nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		msgs := data["FlashMessages"].([]FlashMessage)
		if len(msgs[0].Message) != 200 {
			t.Errorf("expected message length 200, got %d", len(msgs[0].Message))
		}
	})

	t.Run("with domain prefill", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=msg&domain=example.com", nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		if data["PrefillDomain"] != "example.com" {
			t.Errorf("PrefillDomain = %v, want example.com", data["PrefillDomain"])
		}
	})

	t.Run("long domain truncated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		longDomain := ""
		for i := 0; i < 300; i++ {
			longDomain += "d"
		}
		c.Request = httptest.NewRequest(http.MethodGet, "/?flash=msg&domain="+longDomain, nil)
		data := gin.H{}
		applyFlashFromQuery(c, data)
		d, ok := data["PrefillDomain"].(string)
		if !ok {
			t.Fatal("expected PrefillDomain to be string")
		}
		if len(d) != 253 {
			t.Errorf("expected domain length 253, got %d", len(d))
		}
	})
}

func TestNewHomeHandler(t *testing.T) {
	h := NewHomeHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

// swapMetricsLoaders replaces the metrics loader seams for a test and
// restores them on cleanup.
func swapMetricsLoaders(t *testing.T, icaeFn func(context.Context, icae.MaturityQuerier) *icae.ReportMetrics, icuaeFn func(context.Context, icuae.DBTX) *icuae.RuntimeMetrics) {
	t.Helper()
	origICAE, origICUAE := loadReportMetricsFn, loadRuntimeMetricsFn
	loadReportMetricsFn, loadRuntimeMetricsFn = icaeFn, icuaeFn
	t.Cleanup(func() { loadReportMetricsFn, loadRuntimeMetricsFn = origICAE, origICUAE })
}

func TestCachedMetricsColdLoadThenTTLCache(t *testing.T) {
	calls := 0
	swapMetricsLoaders(t,
		func(context.Context, icae.MaturityQuerier) *icae.ReportMetrics {
			calls++
			return &icae.ReportMetrics{}
		},
		func(context.Context, icuae.DBTX) *icuae.RuntimeMetrics {
			return &icuae.RuntimeMetrics{}
		})

	h := &HomeHandler{DB: &db.Database{}}
	icaeM, icuaeM := h.cachedMetrics()
	if icaeM == nil || icuaeM == nil {
		t.Fatal("cold load returned nil metrics")
	}
	if calls != 1 {
		t.Fatalf("loader calls after cold load = %d, want 1", calls)
	}
	if icaeM2, _ := h.cachedMetrics(); icaeM2 != icaeM {
		t.Fatal("within-TTL call did not return cached pointer")
	}
	if calls != 1 {
		t.Fatalf("loader calls within TTL = %d, want 1 (no synchronous reload)", calls)
	}
}

func TestCachedMetricsServesStaleWhileRevalidating(t *testing.T) {
	fresh := &icae.ReportMetrics{}
	done := make(chan struct{})
	swapMetricsLoaders(t,
		func(context.Context, icae.MaturityQuerier) *icae.ReportMetrics {
			return fresh
		},
		func(context.Context, icuae.DBTX) *icuae.RuntimeMetrics {
			defer close(done)
			return &icuae.RuntimeMetrics{}
		})

	stale := &icae.ReportMetrics{}
	h := &HomeHandler{DB: &db.Database{}}
	h.icaeCache = stale
	h.icuaeCache = &icuae.RuntimeMetrics{}
	h.loaded = true
	h.cacheExpiry = time.Now().Add(-time.Second)

	if got, _ := h.cachedMetrics(); got != stale {
		t.Fatal("expired cache did not serve stale value immediately")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background refresh never ran")
	}
	for i := 0; i < 200; i++ {
		h.mu.Lock()
		updated := h.icaeCache == fresh && !h.refreshing
		h.mu.Unlock()
		if updated {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background refresh never installed fresh metrics / cleared refreshing")
}

func TestRefreshMetricsFailureKeepsStaleAndRetriesSoon(t *testing.T) {
	swapMetricsLoaders(t,
		func(context.Context, icae.MaturityQuerier) *icae.ReportMetrics { return nil },
		func(context.Context, icuae.DBTX) *icuae.RuntimeMetrics { return nil })

	stale := &icae.ReportMetrics{}
	h := &HomeHandler{DB: &db.Database{}}
	h.icaeCache = stale
	h.loaded = true
	h.refreshing = true

	before := time.Now()
	icaeM, _ := h.refreshMetrics(time.Second)
	if icaeM != stale {
		t.Fatal("failed refresh dropped last good metrics")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refreshing {
		t.Fatal("refreshing flag stuck after failed refresh")
	}
	if h.cacheExpiry.After(before.Add(metricsCacheTTL)) {
		t.Fatalf("failure cached for full TTL; expiry = %v, want short retry delay", h.cacheExpiry)
	}
}

func TestRefreshMetricsRecoversFromLoaderPanic(t *testing.T) {
	swapMetricsLoaders(t,
		func(context.Context, icae.MaturityQuerier) *icae.ReportMetrics { panic("loader boom") },
		func(context.Context, icuae.DBTX) *icuae.RuntimeMetrics { return nil })

	h := &HomeHandler{DB: &db.Database{}}
	h.refreshing = true
	h.refreshMetrics(time.Second)

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refreshing {
		t.Fatal("refreshing flag stuck after loader panic — cache can never refresh again")
	}
	if h.cacheExpiry.IsZero() {
		t.Fatal("panic path did not schedule a retry")
	}
}
