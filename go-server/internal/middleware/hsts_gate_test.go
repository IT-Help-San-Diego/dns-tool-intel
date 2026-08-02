// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
//
// HSTS single-authority contract: the app emits Strict-Transport-Security
// everywhere EXCEPT behind Replit's edge, which injects the identical header
// itself. Both directions matter — absence off-Replit is the security
// regression, presence on-Replit is the duplicate-header scanner flag that
// kept the app-side line commented out for months.
package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/middleware"

	"github.com/gin-gonic/gin"
)

const wantHSTSValue = "max-age=63072000; includeSubDomains; preload"

func hstsFor(t *testing.T, path string) http.Header {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SecurityHeaders(false))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/static/css/x.css", func(c *gin.Context) { c.String(http.StatusOK, "x") })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w.Header()
}

func TestHSTS_EmittedOffReplit_IncludingStatic(t *testing.T) {
	t.Setenv("REPLIT_DEPLOYMENT", "")
	for _, path := range []string{"/", "/static/css/x.css"} {
		if got := hstsFor(t, path).Get("Strict-Transport-Security"); got != wantHSTSValue {
			t.Errorf("%s: HSTS must be %q off Replit (static too — hotlinked assets may be a client's only origin contact), got %q", path, wantHSTSValue, got)
		}
	}
}

func TestHSTS_SuppressedBehindReplitEdge(t *testing.T) {
	t.Setenv("REPLIT_DEPLOYMENT", "1")
	for _, path := range []string{"/", "/static/css/x.css"} {
		if got := hstsFor(t, path).Get("Strict-Transport-Security"); got != "" {
			t.Errorf("%s: behind Replit's edge the app must yield HSTS emission (edge injects it; two sources = duplicate-header scanner flag), got %q", path, got)
		}
	}
}

func TestSetEarlyHeaders_CoversEarlyListenerResponses(t *testing.T) {
	t.Setenv("REPLIT_DEPLOYMENT", "")
	h := make(http.Header)
	middleware.SetEarlyHeaders(h)
	if got := h.Get("Strict-Transport-Security"); got != wantHSTSValue {
		t.Errorf("early-listener responses need HSTS parity (a first-time visitor during a DB outage must still get the pin), got %q", got)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("early-listener HTML needs sniffing/framing protection, got nosniff=%q xfo=%q",
			h.Get("X-Content-Type-Options"), h.Get("X-Frame-Options"))
	}
}
