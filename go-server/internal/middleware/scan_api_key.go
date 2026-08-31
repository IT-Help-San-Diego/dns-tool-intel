// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ScanAPIKeyAuth gates the batch-scan endpoint: operator-issued keys only
// (design docs/DESIGN-batch-scans-api-keys-20260831.md). The lookup is a
// sha256-compare against scan_api_keys.key_hash — the probe fleet's
// X-Probe-Key pattern, not a bearer session.
//
// On success the handler can read the key row via the context keys
// ("scan_key_id", "scan_key_label"). On failure: 401 with the reason.
//
// Timing: the raw key is sha256'd BEFORE the lookup, so the only equality
// over attacker-influenced bytes runs on the fixed-length hash via the DB
// index — a timing channel on the raw key does not exist. (An earlier
// draft carried a ConstantTimeCompare of the hash WITH ITSELF here — a
// no-op that read as a gate in two reviews; deliberately removed.)
type ScanKeyLookup interface {
	// LookupScanKey returns (id, label, ok) for a NON-REVOKED key whose
	// sha256(key) matches. Implementations must be read-only.
	LookupScanKey(keyHash string) (id int32, label string, ok bool)
}

func ScanAPIKeyAuth(lookup ScanKeyLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := ""
		if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			raw = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if raw == "" {
			raw = c.GetHeader("X-Scan-Key")
		}
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "API key required (Authorization: Bearer <key> or X-Scan-Key)",
			})
			return
		}
		sum := sha256.Sum256([]byte(raw))
		hash := hex.EncodeToString(sum[:])
		id, label, ok := lookup.LookupScanKey(hash)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unknown or revoked API key",
			})
			return
		}
		c.Set("scan_key_id", id)
		c.Set("scan_key_label", label)
		c.Next()
	}
}

// ScanKeyRateLimit is the batch endpoint's keyed bucket — per-KEY, not
// per-IP (the whole point of authorized automation). It charges ONE
// request token here (bounding request floods, unparseable bodies
// included); the batch handler charges the remaining scan tokens after
// validation, so a batch's total charge equals its scan count and the
// per-key scans/min invariant holds mechanically. 429 + Retry-After on
// breach (honest and retryable, the automation-no-blocker rule).
type ScanKeyRateLimiter interface {
	AllowKey(keyID int32, scans int) (ok bool, retryAfterSeconds int)
}

func ScanKeyRateLimit(limiter ScanKeyRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		keyID := c.GetInt32("scan_key_id")
		if ok, retry := limiter.AllowKey(keyID, 1); !ok {
			c.Header("Retry-After", fmt.Sprintf("%d", retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "batch rate limit exceeded for this key",
				"retry_after": retry,
			})
			return
		}
		c.Next()
	}
}
