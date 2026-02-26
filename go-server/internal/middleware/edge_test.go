package middleware

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
        "time"

        "github.com/gin-gonic/gin"
)

func init() {
        gin.SetMode(gin.TestMode)
}


func TestRecordAnalysisMultiple(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
        }

        ac.RecordAnalysis("Example.COM")
        ac.RecordAnalysis("example.com")
        ac.RecordAnalysis("Other.Net")
        ac.RecordAnalysis("another.org")

        if ac.analysesRun != 4 {
                t.Errorf("expected 4 analyses run, got %d", ac.analysesRun)
        }
        if len(ac.analysisDomains) != 3 {
                t.Errorf("expected 3 unique domains, got %d", len(ac.analysisDomains))
        }
}

func TestAnalyticsMiddlewareSkipsWellKnownPaths(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(ac.Middleware())

        paths := []string{
                "/sitemap.xml", "/sw.js", "/manifest.json", "/llms-full.txt",
        }
        for _, p := range paths {
                router.GET(p, func(c *gin.Context) {
                        c.String(http.StatusOK, "ok")
                })
        }

        for _, p := range paths {
                w := httptest.NewRecorder()
                req := httptest.NewRequest("GET", p, nil)
                router.ServeHTTP(w, req)
        }

        if ac.pageviews != 0 {
                t.Errorf("expected 0 pageviews for static/well-known paths, got %d", ac.pageviews)
        }
}

func TestAnalyticsMiddlewareSkips400Responses(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/error", func(c *gin.Context) {
                c.String(http.StatusNotFound, "not found")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/error", nil)
        router.ServeHTTP(w, req)

        if ac.pageviews != 0 {
                t.Errorf("expected 0 pageviews for 404 response, got %d", ac.pageviews)
        }
}

func TestAnalyticsMiddlewareSetsCollector(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(ac.Middleware())

        var gotCollector bool
        router.GET("/page", func(c *gin.Context) {
                _, gotCollector = c.Get("analytics_collector")
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        router.ServeHTTP(w, req)

        if !gotCollector {
                t.Error("expected analytics_collector to be set in context")
        }
}

func TestAnalyticsMiddlewareDirectReferer(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
        }

        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/page", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        router.ServeHTTP(w, req)

        if len(ac.refCounts) != 0 {
                t.Errorf("expected no refCounts for direct visit, got %d", len(ac.refCounts))
        }
}

func TestCSRFRejectWithDomainInPost(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.POST("/submit", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/submit", strings.NewReader("domain=test.com&csrf_token=bad"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.AddCookie(&http.Cookie{Name: "_csrf", Value: "valid.badsig"})
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 redirect, got %d", w.Code)
        }
        loc := w.Header().Get("Location")
        if !strings.Contains(loc, "domain=test.com") {
                t.Errorf("expected domain in redirect URL, got %q", loc)
        }
}

func TestCSRFHeadRequestSetsToken(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())

        var token string
        router.HEAD("/check", func(c *gin.Context) {
                token = GetCSRFToken(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("HEAD", "/check", nil)
        router.ServeHTTP(w, req)

        if token == "" {
                t.Error("expected csrf_token to be set for HEAD request")
        }
}

func TestCSRFOptionsRequestPassthrough(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.OPTIONS("/preflight", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("OPTIONS", "/preflight", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for OPTIONS, got %d", w.Code)
        }
}

func TestCSRFPutRequestValidation(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.PUT("/update", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("PUT", "/update", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 for PUT without CSRF, got %d", w.Code)
        }
}

func TestCSRFDeleteRequestValidation(t *testing.T) {
        m := NewCSRFMiddleware("test-secret")
        router := gin.New()
        router.Use(m.Handler())
        router.DELETE("/remove", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("DELETE", "/remove", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("expected 303 for DELETE without CSRF, got %d", w.Code)
        }
}

func TestCSRFExemptPaths(t *testing.T) {
        tests := []struct {
                path    string
                exempt  bool
        }{
                {"/api/analyze", true},
                {"/api/v1/report", true},
                {"/go/health", true},
                {"/robots.txt", true},
                {"/sitemap.xml", true},
                {"/manifest.json", true},
                {"/sw.js", true},
                {"/", false},
                {"/submit", false},
                {"/about", false},
        }
        for _, tt := range tests {
                got := isCSRFExempt(tt.path)
                if got != tt.exempt {
                        t.Errorf("isCSRFExempt(%q) = %v, want %v", tt.path, got, tt.exempt)
                }
        }
}

func TestRateLimitDifferentIPs(t *testing.T) {
        limiter := NewInMemoryRateLimiter()

        r1 := limiter.CheckAndRecord("1.2.3.4", "example.com")
        r2 := limiter.CheckAndRecord("5.6.7.8", "example.com")

        if !r1.Allowed || !r2.Allowed {
                t.Error("different IPs should be allowed for same domain")
        }
}

func TestRateLimitAntiRepeatWaitSeconds(t *testing.T) {
        limiter := NewInMemoryRateLimiter()

        limiter.CheckAndRecord("10.0.0.1", "test.com")
        result := limiter.CheckAndRecord("10.0.0.1", "test.com")

        if result.Allowed {
                t.Fatal("repeat should be blocked")
        }
        if result.WaitSeconds < 1 {
                t.Errorf("WaitSeconds should be >= 1, got %d", result.WaitSeconds)
        }
}

func TestAuthRateLimitNonAuthPath(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AuthRateLimit(limiter))
        router.GET("/other", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/other", nil)
        router.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for non-auth path, got %d", w.Code)
        }
}

func TestAnalyzeRateLimitRateLimitReasonMessage(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(RequestContext())
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        for i := 0; i < RateLimitMaxRequests; i++ {
                w := httptest.NewRecorder()
                body := strings.NewReader("domain=domain" + strings.Repeat("z", i) + ".com")
                req := httptest.NewRequest("POST", "/", body)
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                router.ServeHTTP(w, req)
        }

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/", strings.NewReader("domain=overflow.com"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "application/json")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusTooManyRequests {
                t.Fatalf("expected 429 for JSON rate limit, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Rate limit reached") {
                t.Errorf("expected rate limit message in body, got %q", body)
        }
}

func TestNewAnalyticsCollectorBaseHost(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
        }
        ac.rotateSalt()

        if ac.dailySalt == "" {
                t.Error("expected salt to be set")
        }
        if ac.saltDate == "" {
                t.Error("expected saltDate to be set")
        }
}

func TestNormalizePath_RootWithQuery(t *testing.T) {
        got := normalizePath("/?q=1")
        if got != "/" {
                t.Errorf("normalizePath(/?q=1) = %q, want /", got)
        }
}

func TestExtractRefOrigin_InternalSubdomain(t *testing.T) {
        got := extractRefOrigin("https://sub.example.com/page", "example.com")
        if got != "" {
                t.Errorf("expected empty for internal subdomain, got %q", got)
        }
}

func TestSecurityHeadersAllPresent(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(SecurityHeaders())
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        headers := []string{
                "Referrer-Policy",
                "Permissions-Policy",
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Resource-Policy",
                "X-Permitted-Cross-Domain-Policies",
        }
        for _, h := range headers {
                if w.Header().Get(h) == "" {
                        t.Errorf("expected %s header to be set", h)
                }
        }
}

func TestRecoveryHandlesPanic(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        tmpl := template.Must(template.New("index.html").Parse(`{{.ActivePage}}`))
        router.SetHTMLTemplate(tmpl)
        router.Use(Recovery("test-version"))
        router.GET("/panic", func(c *gin.Context) {
                panic("test panic")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/panic", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusInternalServerError {
                t.Fatalf("expected 500, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "home") {
                t.Errorf("expected body to contain 'home' from template, got %q", w.Body.String())
        }
}

func TestRecoveryNoPanic(t *testing.T) {
        router := gin.New()
        router.Use(RequestContext())
        router.Use(Recovery("v1"))
        router.GET("/ok", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/ok", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestAnalyzeRateLimitAllowsGET(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.GET("/analyze", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/analyze", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
}

func TestAnalyzeRateLimitEmptyDomainEdge(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/analyze", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain="))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for empty domain, got %d", w.Code)
        }
}

func TestAnalyzeRateLimitBlocksRepeatJSON(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/analyze", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        body := "domain=example.com"
        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("first request expected 200, got %d", w.Code)
        }

        w = httptest.NewRecorder()
        req = httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "application/json")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusTooManyRequests {
                t.Fatalf("repeat request expected 429, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "anti_repeat") {
                t.Errorf("expected anti_repeat reason in JSON body")
        }
}

func TestAnalyzeRateLimitBlocksRepeatHTML(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/analyze", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        body := "domain=example.com"
        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        w = httptest.NewRecorder()
        req = httptest.NewRequest("POST", "/analyze", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusSeeOther {
                t.Fatalf("repeat HTML request expected 303, got %d", w.Code)
        }

        cookies := w.Result().Cookies()
        var foundFlash bool
        for _, c := range cookies {
                if c.Name == "flash_message" {
                        foundFlash = true
                }
        }
        if !foundFlash {
                t.Error("expected flash_message cookie to be set")
        }
}

func TestAnalyzeRateLimitOverflowJSON(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AnalyzeRateLimit(limiter))
        router.POST("/analyze", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        for i := 0; i < RateLimitMaxRequests; i++ {
                body := strings.NewReader("domain=domain" + strings.Repeat("x", i) + ".com")
                w := httptest.NewRecorder()
                req := httptest.NewRequest("POST", "/analyze", body)
                req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                router.ServeHTTP(w, req)
        }

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/analyze", strings.NewReader("domain=overflow.com"))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "application/json")
        router.ServeHTTP(w, req)

        if w.Code != http.StatusTooManyRequests {
                t.Fatalf("overflow request expected 429, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "rate_limit") {
                t.Errorf("expected rate_limit reason in JSON body")
        }
}

func TestAuthRateLimitCallback(t *testing.T) {
        limiter := NewInMemoryRateLimiter()
        router := gin.New()
        router.Use(AuthRateLimit(limiter))
        router.POST("/auth/callback", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/auth/callback", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }

        w = httptest.NewRecorder()
        req = httptest.NewRequest("POST", "/auth/callback", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusFound {
                t.Fatalf("repeat callback expected 302, got %d", w.Code)
        }
}

func TestCheckAndRecordWaitSecondsMinOne(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        now := float64(time.Now().Unix())
        limiter.requests["10.0.0.1"] = []requestEntry{
                {timestamp: now, domain: "test.com"},
        }

        result := limiter.CheckAndRecord("10.0.0.1", "test.com")
        if result.Allowed {
                t.Fatal("expected not allowed")
        }
        if result.WaitSeconds < 1 {
                t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
        }
}

func TestFlushZeroPageviews(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                pageviews:       0,
        }
        ac.Flush()
        if ac.pageviews != 0 {
                t.Errorf("expected pageviews to remain 0")
        }
}

func TestPruneOldRemovesExpired(t *testing.T) {
        now := float64(time.Now().Unix())
        entries := []requestEntry{
                {timestamp: now - RateLimitWindow - 10, domain: "old.com"},
                {timestamp: now - RateLimitWindow - 1, domain: "old2.com"},
                {timestamp: now - 5, domain: "recent.com"},
                {timestamp: now, domain: "current.com"},
        }
        result := pruneOld(entries, now)
        if len(result) != 2 {
                t.Errorf("expected 2 entries after prune, got %d", len(result))
        }
        if result[0].domain != "recent.com" {
                t.Errorf("expected recent.com first, got %s", result[0].domain)
        }
}

func TestCheckAndRecordRateLimitWaitSecondsMinOne(t *testing.T) {
        limiter := &InMemoryRateLimiter{
                requests: make(map[string][]requestEntry),
        }

        now := float64(time.Now().Unix())
        entries := make([]requestEntry, RateLimitMaxRequests)
        for i := 0; i < RateLimitMaxRequests; i++ {
                entries[i] = requestEntry{
                        timestamp: now - float64(RateLimitMaxRequests-i),
                        domain:    "d" + strings.Repeat("x", i) + ".com",
                }
        }
        limiter.requests["10.0.0.2"] = entries

        result := limiter.CheckAndRecord("10.0.0.2", "new.com")
        if result.Allowed {
                t.Fatal("expected not allowed due to rate limit")
        }
        if result.Reason != "rate_limit" {
                t.Errorf("expected rate_limit reason, got %s", result.Reason)
        }
        if result.WaitSeconds < 1 {
                t.Errorf("waitSeconds should be >= 1, got %d", result.WaitSeconds)
        }
}

func TestAnalyticsMiddlewareTracksReferer(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
                baseHost:        "mysite.com",
        }
        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/about", func(c *gin.Context) {
                c.String(http.StatusOK, "about page")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/about", nil)
        req.Header.Set("Referer", "https://google.com/search?q=test")
        router.ServeHTTP(w, req)

        if ac.pageviews != 1 {
                t.Errorf("expected 1 pageview, got %d", ac.pageviews)
        }
        if ac.refCounts["google.com"] != 1 {
                t.Errorf("expected google.com referer count of 1, got %d", ac.refCounts["google.com"])
        }
}

func TestAnalyticsMiddlewareSkipsSelfReferer(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailySalt:       "test-salt",
                saltDate:        time.Now().UTC().Format("2006-01-02"),
                baseHost:        "mysite.com",
        }
        router := gin.New()
        router.Use(ac.Middleware())
        router.GET("/page", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/page", nil)
        req.Header.Set("Referer", "https://mysite.com/other")
        router.ServeHTTP(w, req)

        if len(ac.refCounts) != 0 {
                t.Errorf("expected no ref counts for self-referrer, got %v", ac.refCounts)
        }
}

func TestNormalizePathEdgeCases(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"/about", "/about"},
                {"/about?foo=bar", "/about"},
                {"/about/", "/about"},
                {"/about/?x=1", "/about/"},
                {"/", "/"},
                {"///", ""},
        }
        for _, tt := range tests {
                got := normalizePath(tt.input)
                if got != tt.want {
                        t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}
