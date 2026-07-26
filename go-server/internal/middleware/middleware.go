// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
        "context"
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "os"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
)

type contextKey string

const (
        CSPNonceKey contextKey = "csp_nonce"
        TraceIDKey  contextKey = "trace_id"

        ginKeyCSPNonce     = "csp_nonce"
        ginKeyTraceID      = "trace_id"
        ginKeyRequestStart = "request_start"
        ginKeyCSRFToken    = "csrf_token"
        ginKeyDevMode      = "dns.dev_mode"
)

func generateNonce() string {
        b := make([]byte, 16)
        if _, err := rand.Read(b); err != nil {
                slog.Error("rand.Read failed", "error", err)
        }
        return base64.URLEncoding.EncodeToString(b)
}

func RequestContext() gin.HandlerFunc {
        return func(c *gin.Context) {
                nonce := generateNonce()
                traceID := uuid.New().String()[:8]
                start := time.Now()

                c.Set(ginKeyCSPNonce, nonce)
                c.Set(ginKeyTraceID, traceID)
                c.Set(ginKeyRequestStart, start)

                ctx := context.WithValue(c.Request.Context(), CSPNonceKey, nonce)
                ctx = context.WithValue(ctx, TraceIDKey, traceID)
                c.Request = c.Request.WithContext(ctx)

                c.Next()

                duration := time.Since(start)
                slog.Info("Request completed",
                        ginKeyTraceID, traceID,
                        "method", c.Request.Method,
                        "path", c.Request.URL.Path,
                        "status", c.Writer.Status(),
                        "duration_ms", fmt.Sprintf("%.1f", float64(duration.Microseconds())/1000.0),
                )
        }
}

// CookieSecure reports whether the Secure attribute should be set on cookies
// for this request.
//
// Secure is the correct default and is returned for every request that is not
// provably a plaintext loopback request. A browser silently DISCARDS a
// Secure cookie delivered over plain http://, which breaks the CSRF
// double-submit check on a local `docker compose up` — the POST arrives with no
// _csrf cookie and is rejected, surfacing in the UI as a generic
// "Network error". See REPRODUCTION.md (2026-07-26).
//
// The exemption is deliberately narrow: BOTH conditions must hold.
//   1. The request did not arrive over TLS, directly or via a terminating
//      proxy (same test as the CSP upgrade-insecure-requests directive below).
//   2. The Host is a loopback address.
//
// Production traffic fails both tests — it terminates TLS at the edge and
// carries X-Forwarded-Proto: https with the canonical public Host — so this
// cannot silently downgrade a deployed cookie. It is not gated on a dev-mode
// env var, because the container case that needs it has no such variable set.
func CookieSecure(c *gin.Context) bool {
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		return true
	}
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return false
	}
	return true
}

func CookieSameSite(c *gin.Context) http.SameSite {
        if v, exists := c.Get(ginKeyDevMode); exists {
                if dev, ok := v.(bool); ok && dev {
                        return http.SameSiteLaxMode
                }
        }
        return http.SameSiteStrictMode
}

func SecurityHeaders(isDev ...bool) gin.HandlerFunc {
        devMode := len(isDev) > 0 && isDev[0]
        return func(c *gin.Context) {
                c.Set(ginKeyDevMode, devMode)
                const cspHeader = "Content-Security-Policy"
                if strings.HasPrefix(c.Request.URL.Path, "/static/") {
                        c.Header("X-Content-Type-Options", "nosniff")
                        c.Header("X-Frame-Options", "DENY")
                        if strings.HasSuffix(c.Request.URL.Path, ".svg") {
                                c.Header(cspHeader, "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                        } else {
                                c.Header(cspHeader, "default-src 'none'; style-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                        }
                        c.Next()
                        return
                }

                nonceStr := extractNonceStr(c)
                setCommonSecurityHeaders(c, devMode)
                c.Header(cspHeader, buildCSP(c, nonceStr, devMode))
                c.Next()
        }
}

func extractNonceStr(c *gin.Context) string {
        nonce, exists := c.Get(ginKeyCSPNonce)
        if !exists {
                return ""
        }
        if s, ok := nonce.(string); ok {
                return s
        }
        return ""
}

func setCommonSecurityHeaders(c *gin.Context, devMode bool) {
        c.Header("Cache-Control", "no-cache")
        c.Header("X-Content-Type-Options", "nosniff")
        if !devMode {
                if c.Request.URL.Path == "/signature" || strings.HasPrefix(c.Request.URL.Path, "/docs/") {
                        c.Header("X-Frame-Options", "SAMEORIGIN")
                } else {
                        c.Header("X-Frame-Options", "DENY")
                }
        }
        if !devMode {
                // HSTS is intentionally NOT emitted here. The Replit edge proxy
                // already injects `Strict-Transport-Security: max-age=63072000;
                // includeSubDomains; preload` on every TLS response. Emitting it
                // twice causes Mozilla Observatory and some scanners to flag a
                // duplicate header; deferring entirely to the edge keeps a single
                // authoritative source. If the deployment ever moves off the
                // Replit edge, restore the line below.
                // c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

                // CSP / NEL violation reporting endpoint group. The legacy Report-To
                // header is required for Reporting API v0 (Chrome <94), and the
                // modern Reporting-Endpoints header for v1 (Chrome ≥94, Firefox).
                c.Header("Reporting-Endpoints", `csp="/api/csp-report"`)
                c.Header("Report-To", `{"group":"csp","max_age":10886400,"endpoints":[{"url":"/api/csp-report"}],"include_subdomains":true}`)
        }
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=(), screen-wake-lock=(), xr-spatial-tracking=(), interest-cohort=(), browsing-topics=(), tools=(self)")
        if devMode {
                c.Header("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
                c.Header("Cross-Origin-Resource-Policy", "cross-origin")
        } else {
                c.Header("Cross-Origin-Opener-Policy", "same-origin")
                c.Header("Cross-Origin-Resource-Policy", "same-origin")
        }
        c.Header("X-Permitted-Cross-Domain-Policies", "none")
}

func buildCSP(c *gin.Context, nonceStr string, devMode bool) string {
        replitWidget := replitWidgetCSP()

        connectSrc := "connect-src 'self'; "
        if devMode {
                connectSrc = "connect-src 'self' https://replit.com https://*.replit.com https://*.replit.dev; "
        } else if replitWidget {
                connectSrc = "connect-src 'self' https://replit.com https://*.replit.com; "
        }

        frameAncestors := "frame-ancestors 'none'; "
        if devMode {
                frameAncestors = "frame-ancestors https://replit.com https://*.replit.com https://*.replit.dev https://*.replit.app https://*.picard.replit.dev; "
        } else if strings.HasPrefix(c.Request.URL.Path, "/docs/") {
                frameAncestors = "frame-ancestors 'self'; "
        }

        frameSrc := "frame-src 'none'; "
        if c.Request.URL.Path == "/signature" {
                frameSrc = "frame-src 'self'; "
        } else if c.Request.URL.Path == "/video/forgotten-domain" {
                frameSrc = "frame-src https://www.youtube-nocookie.com; "
        } else if replitWidget {
                frameSrc = "frame-src https://replit.com https://*.replit.com; "
        }

        scriptSrc := fmt.Sprintf("script-src 'self' 'nonce-%s'; ", nonceStr)
        if replitWidget && !devMode {
                scriptSrc = fmt.Sprintf("script-src 'self' 'nonce-%s' https://replit.com https://*.replit.com; ", nonceStr)
        }

        upgradeDirective := ""
        if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
                upgradeDirective = "upgrade-insecure-requests; "
        }
        reportDirective := ""
        if !devMode {
                reportDirective = "report-to csp; report-uri /api/csp-report;"
        }

        styleSrc := fmt.Sprintf("style-src 'self' 'nonce-%s'; ", nonceStr)
        if strings.HasPrefix(c.Request.URL.Path, "/agent/") {
                styleSrc = "style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; "
        }

        return fmt.Sprintf(
                "default-src 'none'; "+
                        "%s"+
                        "%s"+
                        "font-src 'self'; "+
                        "img-src 'self' data: blob:; "+
                        "%s"+
                        "%s"+
                        "base-uri 'none'; "+
                        "form-action 'self'; "+
                        "manifest-src 'self'; "+
                        "object-src 'none'; "+
                        "%s"+
                        "media-src 'self'; "+
                        "worker-src 'self'; "+
                        "%s%s",
                scriptSrc, styleSrc, connectSrc, frameAncestors, frameSrc, upgradeDirective, reportDirective,
        )
}

// replitWidgetCSP gates the Replit dev-banner allowlist
// (https://replit.com / https://*.replit.com) in script-src, connect-src, and
// frame-src. Historically this was tied to REPLIT_DEPLOYMENT, but that env
// var is set in BOTH dev and the published deployment, leaking the wildcard
// into production where no Replit script actually loads in the rendered HTML.
// Now gated explicitly: only when REPLIT_DEV_BANNER=1 (set in the dev
// workflow, NOT in the published deployment) does the allowlist appear.
func replitWidgetCSP() bool {
        return os.Getenv("REPLIT_DEV_BANNER") == "1"
}

func Recovery(appVersion string, opts ...map[string]any) gin.HandlerFunc {
        var extraData map[string]any
        if len(opts) > 0 {
                extraData = opts[0]
        }
        return func(c *gin.Context) {
                defer func() {
                        if err := recover(); err != nil {
                                traceID, _ := c.Get(ginKeyTraceID) //nolint:errcheck // value used for logging only
                                slog.Error("Panic recovered",
                                        ginKeyTraceID, traceID,
                                        "error", fmt.Sprintf("%v", err),
                                        "path", c.Request.URL.Path,
                                )
                                nonce, _ := c.Get(ginKeyCSPNonce)      //nolint:errcheck // value used for template rendering
                                csrfToken, _ := c.Get(ginKeyCSRFToken) //nolint:errcheck // value used for template rendering
                                type flashMsg struct {
                                        Category string
                                        Message  string
                                }
                                data := gin.H{
                                        "AppVersion":    appVersion,
                                        "CspNonce":      nonce,
                                        "CsrfToken":     csrfToken,
                                        "ActivePage":    "home",
                                        "FlashMessages": []flashMsg{{Category: "danger", Message: "An internal error occurred. Please try again."}},
                                }
                                for k, v := range extraData {
                                        data[k] = v
                                }
                                c.HTML(http.StatusInternalServerError, "index.html", data)
                                c.Abort()
                        }
                }()
                c.Next()
        }
}

func CanonicalHostRedirect(canonicalURL string) gin.HandlerFunc {
        parsed, err := url.Parse(canonicalURL)
        if err != nil || parsed.Host == "" {
                slog.Warn("CanonicalHostRedirect: invalid canonical URL, middleware disabled", "url", canonicalURL)
                return func(c *gin.Context) { c.Next() }
        }
        canonicalHost := parsed.Host
        canonicalScheme := parsed.Scheme
        if canonicalScheme == "" {
                canonicalScheme = "https"
        }

        return func(c *gin.Context) {
                host := c.Request.Host
                if idx := strings.LastIndex(host, ":"); idx > 0 {
                        host = host[:idx]
                }

                if host == canonicalHost {
                        c.Next()
                        return
                }

                if strings.HasSuffix(host, ".replit.app") || strings.HasSuffix(host, ".replit.dev") {
                        target := canonicalScheme + "://" + canonicalHost + c.Request.URL.RequestURI()
                        c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
                        c.Redirect(http.StatusMovedPermanently, target)
                        c.Abort()
                        return
                }

                c.Next()
        }
}
