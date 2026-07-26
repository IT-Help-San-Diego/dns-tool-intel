// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCookieSecure pins the loopback exemption that lets a local
// `docker compose up` complete the CSRF double-submit handshake, and — more
// importantly — pins the cases that MUST stay Secure so the exemption can never
// silently downgrade a deployed cookie.
func TestCookieSecure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		host       string
		tls        bool
		fwdProto   string
		wantSecure bool
	}{
		// The bug this fixes: a Secure cookie over plain http:// is discarded
		// by the browser, so POST /analyze arrives with no _csrf cookie.
		{"plain http localhost with port", "localhost:5055", false, "", false},
		{"plain http localhost no port", "localhost", false, "", false},
		{"plain http 127.0.0.1", "127.0.0.1:5055", false, "", false},
		{"plain http IPv6 loopback", "[::1]:5055", false, "", false},

		// Production and everything resembling it must remain Secure.
		{"canonical host behind TLS-terminating proxy", "dnstool.it-help.tech", false, "https", true},
		{"canonical host direct TLS", "dnstool.it-help.tech", true, "", true},
		{"canonical host plaintext (still Secure)", "dnstool.it-help.tech", false, "", true},
		{"loopback but TLS terminated upstream", "localhost:5055", false, "https", true},
		{"loopback but direct TLS", "localhost:5055", true, "", true},
		{"LAN address is not loopback", "192.168.1.10:5055", false, "", true},
		{"hostname merely containing localhost", "notlocalhost.example.com", false, "", true},
		{"subdomain of localhost is not loopback", "evil.localhost", false, "", true},
		{"empty host", "", false, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.Host = tc.host
			if tc.tls {
				c.Request.TLS = &tls.ConnectionState{}
			}
			if tc.fwdProto != "" {
				c.Request.Header.Set("X-Forwarded-Proto", tc.fwdProto)
			}
			if got := CookieSecure(c); got != tc.wantSecure {
				t.Errorf("CookieSecure() = %v, want %v (host=%q tls=%v xfp=%q)",
					got, tc.wantSecure, tc.host, tc.tls, tc.fwdProto)
			}
		})
	}
}

// TestCSRFCookieUsableOverPlainLocalhost is the end-to-end guard: a GET to a
// loopback host must emit a _csrf cookie the browser will actually keep.
func TestCSRFCookieUsableOverPlainLocalhost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := NewCSRFMiddleware("test-secret-not-a-real-one")

	router := gin.New()
	router.Use(m.Handler())
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:5055"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var csrf *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == csrfCookieName {
			csrf = ck
		}
	}
	if csrf == nil {
		t.Fatalf("no %s cookie was set", csrfCookieName)
	}
	if csrf.Secure {
		t.Errorf("%s cookie has Secure set over plain http://localhost — a browser will discard it, breaking the CSRF handshake", csrfCookieName)
	}
	if !csrf.HttpOnly {
		t.Errorf("%s cookie must remain HttpOnly", csrfCookieName)
	}
}

// TestCSRFCookieStaysSecureInProduction is the counterpart: the same handler
// must still emit a Secure cookie for canonical HTTPS traffic.
func TestCSRFCookieStaysSecureInProduction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := NewCSRFMiddleware("test-secret-not-a-real-one")

	router := gin.New()
	router.Use(m.Handler())
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "dnstool.it-help.tech"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	for _, ck := range w.Result().Cookies() {
		if ck.Name == csrfCookieName && !ck.Secure {
			t.Fatalf("%s cookie lost Secure for canonical HTTPS traffic", csrfCookieName)
		}
	}
}
