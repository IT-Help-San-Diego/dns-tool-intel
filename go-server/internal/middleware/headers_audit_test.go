package middleware

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "github.com/gin-gonic/gin"
)

// TestProdHeadersAudit_v26_47_0 asserts the response-header set the v26.47.0
// production build is supposed to emit, both for the homepage and for a
// /static/* asset. It is the in-process companion to the live-URL verification
// performed in .local/audits/2026-04-21-task80-prod-headers-and-qualys.md and
// guards against silent regression of the Reporting-Endpoints / Report-To /
// CSP report-to wiring and the X-Frame-Options on /static/*.
func TestProdHeadersAudit_v26_47_0(t *testing.T) {
        gin.SetMode(gin.TestMode)
        t.Setenv("REPLIT_DEV_BANNER", "")

        cases := []struct {
                path string
                want func(t *testing.T, h http.Header)
        }{
                {
                        path: "/",
                        want: func(t *testing.T, h http.Header) {
                                csp := h.Get("Content-Security-Policy")
                                if strings.Contains(csp, "replit.com") {
                                        t.Errorf("prod CSP for / must not allowlist replit.com: %s", csp)
                                }
                                if !strings.Contains(csp, "report-to csp") {
                                        t.Errorf("prod CSP for / missing 'report-to csp': %s", csp)
                                }
                                if !strings.Contains(csp, "report-uri /api/csp-report") {
                                        t.Errorf("prod CSP for / missing 'report-uri /api/csp-report': %s", csp)
                                }
                                if got := h.Get("Reporting-Endpoints"); got != `csp="/api/csp-report"` {
                                        t.Errorf(`prod / Reporting-Endpoints expected csp="/api/csp-report", got %q`, got)
                                }
                                if h.Get("Report-To") == "" {
                                        t.Errorf("prod / missing Report-To header")
                                }
                                if got := h.Get("Strict-Transport-Security"); got != "" {
                                        t.Errorf("prod / must NOT emit app-side HSTS (edge handles it); got %q", got)
                                }
                                if got := h.Get("X-Frame-Options"); got != "DENY" {
                                        t.Errorf("prod / X-Frame-Options expected DENY, got %q", got)
                                }
                        },
                },
                {
                        path: "/static/css/style.css",
                        want: func(t *testing.T, h http.Header) {
                                if got := h.Get("X-Frame-Options"); got != "DENY" {
                                        t.Errorf("/static/* must include X-Frame-Options: DENY, got %q", got)
                                }
                                if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
                                        t.Errorf("/static/* must include X-Content-Type-Options: nosniff, got %q", got)
                                }
                                csp := h.Get("Content-Security-Policy")
                                if !strings.Contains(csp, "default-src 'none'") {
                                        t.Errorf("/static/* CSP must lock down default-src 'none', got %q", csp)
                                }
                        },
                },
        }

        for _, tc := range cases {
                t.Run(tc.path, func(t *testing.T) {
                        r := gin.New()
                        r.Use(SecurityHeaders(false))
                        r.GET(tc.path, func(c *gin.Context) { c.String(http.StatusOK, "ok") })

                        req := httptest.NewRequest(http.MethodGet, tc.path, nil)
                        req.Header.Set("X-Forwarded-Proto", "https")
                        w := httptest.NewRecorder()
                        r.ServeHTTP(w, req)

                        tc.want(t, w.Header())

                        // Also dump the full header set via t.Log for offline audit
                        // reconciliation against the live curl capture in
                        // .local/audits/2026-04-21-task80-prod-headers-and-qualys.md.
                        for _, k := range sortedKeys(w.Header()) {
                                for _, v := range w.Header().Values(k) {
                                        t.Logf("%s: %s", k, v)
                                }
                        }
                })
        }
}

func sortedKeys(h http.Header) []string {
        keys := make([]string, 0, len(h))
        for k := range h {
                keys = append(keys, k)
        }
        for i := 1; i < len(keys); i++ {
                for j := i; j > 0 && strings.ToLower(keys[j]) < strings.ToLower(keys[j-1]); j-- {
                        keys[j], keys[j-1] = keys[j-1], keys[j]
                }
        }
        return keys
}

