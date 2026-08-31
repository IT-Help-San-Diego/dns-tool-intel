// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"dnstool/go-server/internal/logging"

	"github.com/gin-gonic/gin"
)

const (
	RateLimitWindow      = 60
	RateLimitMaxRequests = 8
	AntiRepeatWindow     = 15

	mapKeyReason      = "reason"
	mapKeyWaitSeconds = "wait_seconds"
)

type RateLimitResult struct {
	Allowed     bool
	Reason      string
	WaitSeconds int
}

type RateLimiter interface {
	CheckAndRecord(ip, domain string) RateLimitResult
}

type requestEntry struct {
	timestamp float64
	domain    string
}

type InMemoryRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]requestEntry
}

func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]requestEntry),
	}

	go limiter.cleanupLoop()

	return limiter
}

func (l *InMemoryRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := float64(time.Now().Unix())
		for ip, entries := range l.requests {
			l.requests[ip] = pruneOld(entries, now)
			if len(l.requests[ip]) == 0 {
				delete(l.requests, ip)
			}
		}
		l.mu.Unlock()
	}
}

func pruneOld(entries []requestEntry, now float64) []requestEntry {
	cutoff := now - RateLimitWindow
	result := entries[:0]
	for _, e := range entries {
		if e.timestamp >= cutoff {
			result = append(result, e)
		}
	}
	return result
}

func (l *InMemoryRateLimiter) CheckAndRecord(ip, domain string) RateLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := float64(time.Now().Unix())
	domain = strings.ToLower(domain)

	l.requests[ip] = pruneOld(l.requests[ip], now)
	entries := l.requests[ip]

	if len(entries) >= RateLimitMaxRequests {
		oldest := entries[0].timestamp
		waitSeconds := int(oldest+RateLimitWindow-now) + 1
		if waitSeconds < 1 {
			waitSeconds = 1
		}
		return RateLimitResult{
			Allowed:     false,
			Reason:      "rate_limit",
			WaitSeconds: waitSeconds,
		}
	}

	antiRepeatCutoff := now - AntiRepeatWindow
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].timestamp < antiRepeatCutoff {
			break
		}
		if entries[i].domain == domain {
			waitSeconds := int(entries[i].timestamp+AntiRepeatWindow-now) + 1
			if waitSeconds < 1 {
				waitSeconds = 1
			}
			return RateLimitResult{
				Allowed:     false,
				Reason:      "anti_repeat",
				WaitSeconds: waitSeconds,
			}
		}
	}

	l.requests[ip] = append(entries, requestEntry{
		timestamp: now,
		domain:    domain,
	})

	return RateLimitResult{
		Allowed: true,
		Reason:  "ok",
	}
}

func AuthRateLimit(limiter *InMemoryRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		pathKey := "_auth_login"
		if strings.HasSuffix(c.Request.URL.Path, "/callback") {
			pathKey = "_auth_callback"
		}

		result := limiter.CheckAndRecord(clientIP, pathKey)

		if !result.Allowed {
			traceID, _ := c.Get(ginKeyTraceID)
			tid := fmt.Sprintf("%v", traceID)
			slog.LogAttrs(c.Request.Context(), slog.LevelWarn, "Auth rate limit triggered",
				append(logging.SecurityEvent(logging.EventRateLimitHit, tid, clientIP),
					slog.String("path", c.Request.URL.Path),
					slog.String(mapKeyReason, result.Reason),
					slog.Int(mapKeyWaitSeconds, result.WaitSeconds),
				)...,
			)
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.Next()
	}
}

func AnalyzeRateLimit(limiter RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != "POST" {
			c.Next()
			return
		}

		domain := strings.TrimSpace(c.PostForm("domain"))
		if domain == "" {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		result := limiter.CheckAndRecord(clientIP, domain)

		if !result.Allowed {
			logRateLimitTriggered(c, clientIP, domain, result)
			respondRateLimited(c, result)
			c.Abort()
			return
		}

		c.Next()
	}
}

func extractAgentDomain(c *gin.Context) string {
	for _, key := range []string{"q", "domain", "query", "search", "searchTerms"} {
		if v := strings.TrimSpace(c.Query(key)); v != "" {
			return v
		}
	}
	return ""
}

func respondAgentRateLimited(c *gin.Context, result RateLimitResult) {
	msg := rateLimitMessage(result)
	if strings.Contains(c.GetHeader("Accept"), "application/json") || strings.HasSuffix(c.Request.URL.Path, "/api") {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":           msg,
			mapKeyReason:      result.Reason,
			mapKeyWaitSeconds: result.WaitSeconds,
		})
	} else {
		c.Data(http.StatusTooManyRequests, "text/html; charset=utf-8",
			[]byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>DNS Tool Agent — Rate Limited</title></head><body><h1>Rate Limited</h1><p>%s</p></body></html>`, msg)))
	}
}

func AgentRateLimit(limiter RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}
		domain := extractAgentDomain(c)
		if domain == "" {
			c.Next()
			return
		}
		clientIP := c.ClientIP()
		result := limiter.CheckAndRecord(clientIP, strings.ToLower(domain))
		if !result.Allowed {
			logRateLimitTriggered(c, clientIP, domain, result)
			respondAgentRateLimited(c, result)
			c.Abort()
			return
		}
		c.Next()
	}
}

func logRateLimitTriggered(c *gin.Context, clientIP, domain string, result RateLimitResult) {
	traceID, _ := c.Get(ginKeyTraceID) //nolint:errcheck // value used for logging only
	tid := fmt.Sprintf("%v", traceID)
	slog.LogAttrs(c.Request.Context(), slog.LevelWarn, "Rate limit triggered",
		append(logging.SecurityEvent(logging.EventRateLimitHit, tid, clientIP),
			slog.String(logging.AttrDomain, domain),
			slog.String(mapKeyReason, result.Reason),
			slog.Int(mapKeyWaitSeconds, result.WaitSeconds),
		)...,
	)
}

func rateLimitMessage(result RateLimitResult) string {
	switch result.Reason {
	case "rate_limit":
		return fmt.Sprintf("Rate limit reached. Please wait %d seconds before trying again.", result.WaitSeconds)
	case "anti_repeat":
		return fmt.Sprintf("This domain was recently analyzed. Please wait %d seconds before re-analyzing.", result.WaitSeconds)
	default:
		return fmt.Sprintf("Please wait %d seconds before trying again.", result.WaitSeconds)
	}
}

func respondRateLimited(c *gin.Context, result RateLimitResult) {
	msg := rateLimitMessage(result)
	if c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":           msg,
			mapKeyReason:      result.Reason,
			mapKeyWaitSeconds: result.WaitSeconds,
		})
		return
	}
	setFlashCookies(c, msg)
	c.Redirect(http.StatusSeeOther, safeRefererPath(c))
}

func setFlashCookies(c *gin.Context, msg string) {
	ss := CookieSameSite(c)
	secure := CookieSecure(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "flash_message",
		Value:    msg,
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
		Secure:   secure,
		SameSite: ss,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "flash_category",
		Value:    "warning",
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
		Secure:   secure,
		SameSite: ss,
	})
}

func safeRefererPath(c *gin.Context) string {
	ref := c.Request.Referer()
	if ref == "" {
		return "/"
	}
	u, err := url.Parse(ref)
	if err != nil || u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") {
		return "/"
	}
	return u.Path
}

// KeyScanCapPerMinute is the per-key scan budget: the invariant is SCANS
// per minute, not requests — a leaked key must not be able to hammer the
// fleet through big batches. Handlers that pre-validate batch sizes
// reference this same constant so the refusal boundary cannot drift from
// the bucket that enforces it.
const KeyScanCapPerMinute = 30

// AllowKey is the batch-endpoint keyed bucket: a per-KEY sliding window,
// separate from the per-IP domain limiter (authorized automation is keyed,
// not IP-shaped). Key namespace "scankey:<id>" never collides with IPs.
//
// Charging model: the route middleware charges 1 token per request; the
// batch handler charges the remaining scan tokens after validation — a
// batch's total charge equals its scan count. Generous for a battery
// (8-14 domains), tight enough that a leaked key cannot hammer the fleet.
//
// A single call asking for more than the whole cap can NEVER succeed;
// it returns (false, -1) so the caller refuses permanently ("split the
// batch") instead of issuing retry advice that would never come true.
func (l *InMemoryRateLimiter) AllowKey(keyID int32, scans int) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	const window = time.Minute
	if scans <= 0 {
		return true, 0
	}
	if scans > KeyScanCapPerMinute {
		return false, -1
	}
	now := time.Now()
	key := fmt.Sprintf("scankey:%d", keyID)
	entries := l.requests[key]
	keep := entries[:0]
	for _, e := range entries {
		if now.Unix()-int64(e.timestamp) < int64(window/time.Second) {
			keep = append(keep, e)
		}
	}
	if len(keep)+scans > KeyScanCapPerMinute {
		l.requests[key] = keep
		// scans <= cap here, so overflow implies len(keep) >= 1 and the
		// keep[0] read is safe: retry when the oldest entry leaves the
		// window. (Without the scans > cap guard above, an oversize call
		// on an EMPTY window would index keep[0] out of range.)
		age := now.Unix() - int64(keep[0].timestamp)
		retry := int(int64(window/time.Second)-age) + 1
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}
	for i := 0; i < scans; i++ {
		keep = append(keep, requestEntry{timestamp: float64(now.Unix())})
	}
	l.requests[key] = keep
	return true, 0
}
