// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CtxScannerSource is the gin context key under which ScannerWatch publishes
// the attributed scanner source ("CISA Cyber Hygiene", "Forged Localhost
// Referer") for downstream handlers.
const CtxScannerSource = "scanner_source"

const (
	// scannerWatchMaxIPs bounds the in-memory registry. A full CyHy sweep
	// comes from a handful of IPs; commodity botnets can rotate thousands.
	// Past the cap new IPs are counted in aggregate (OverflowDropped) so
	// memory stays flat under a rotation attack.
	scannerWatchMaxIPs = 2048

	// scannerLogInterval throttles per-IP structured logging so a full
	// sweep produces one log line per source IP per interval instead of
	// one per probed URL.
	scannerLogInterval = time.Hour

	// scannerPathMaxLen truncates stored LastPath values so the registry's
	// memory ceiling stays bounded even against absurdly long probe URLs.
	scannerPathMaxLen = 256
)

// ScannerHit is one attributed scanner IP with its observed activity window.
type ScannerHit struct {
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastPath  string    `json:"last_path"`
}

type scannerHitState struct {
	ScannerHit
	lastLogged time.Time
}

// ScannerWatch attributes EVERY request whose client IP falls inside a known
// security-scanner range (currently the CISA Cyber Hygiene CIDR list, via the
// injected matcher) or whose Referer is a forged localhost origin — the
// signature of header-injection probe campaigns.
//
// It exists because scanner.Classify only runs inside the scan-submission
// flow (/analyze), so a CyHy sweep of the general HTTP surface was never
// attributed: the detector was structurally blind to the very scans it was
// built to recognize. This middleware closes that gap at the router level.
type ScannerWatch struct {
	matcher func(string) string
	now     func() time.Time

	mu       sync.Mutex
	hits     map[string]*scannerHitState
	overflow int
}

// NewScannerWatch builds a watch around an IP-range matcher (e.g.
// scanner.MatchCISA). The matcher returns a source label for a matched IP or
// "" for no match. A nil matcher disables range matching but keeps
// forged-Referer detection active.
func NewScannerWatch(matcher func(string) string) *ScannerWatch {
	return &ScannerWatch{
		matcher: matcher,
		now:     time.Now,
		hits:    make(map[string]*scannerHitState),
	}
}

// Middleware tags and records scanner-attributed requests. It never blocks
// them: CISA sweeps are welcome traffic, and probes are already neutralized
// by input validation — the goal here is attribution, not filtering.
func (sw *ScannerWatch) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		source := ""
		if sw.matcher != nil {
			source = sw.matcher(ip)
		}
		if source == "" {
			source = forgedLocalhostReferer(c.Request.Referer())
		}

		if source != "" {
			c.Set(CtxScannerSource, source)
			sw.record(ip, source, c.Request.URL.Path)
		}

		c.Next()
	}
}

// forgedLocalhostReferer flags Referer headers claiming a localhost origin.
// No legitimate browser sends a localhost Referer to a public site; the
// pattern is a header-injection probe signature (e.g. localhost/', localhost/(,
// localhost/1e309). Only the host is inspected — payload heuristics on the
// path would risk false positives.
func forgedLocalhostReferer(referer string) string {
	if referer == "" {
		return ""
	}
	switch refererHost(referer) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return "Forged Localhost Referer"
	}
	return ""
}

// refererHost extracts the lowercased host (port stripped) from a Referer
// value. Schemeless forms parse as relative paths ("localhost/'"), opaque
// URLs ("localhost:5000/x" reads scheme "localhost"), or outright errors
// ("127.0.0.1:80/x"), so anything that does not yield a host from a plain
// http(s)/schemeless parse is re-parsed with an http:// prefix to expose the
// claimed host.
func refererHost(referer string) string {
	if u, err := url.Parse(referer); err == nil {
		if h := u.Hostname(); h != "" && (u.Scheme == "" || u.Scheme == "http" || u.Scheme == "https") {
			return strings.ToLower(h)
		}
	}
	if u, err := url.Parse("http://" + referer); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func (sw *ScannerWatch) record(ip, source, path string) {
	nowTS := sw.now()
	if len(path) > scannerPathMaxLen {
		path = path[:scannerPathMaxLen]
	}

	sw.mu.Lock()
	state, ok := sw.hits[ip]
	if !ok {
		if len(sw.hits) >= scannerWatchMaxIPs {
			sw.overflow++
			sw.mu.Unlock()
			return
		}
		state = &scannerHitState{ScannerHit: ScannerHit{
			IP:        ip,
			Source:    source,
			FirstSeen: nowTS,
		}}
		sw.hits[ip] = state
	}
	state.Count++
	state.LastSeen = nowTS
	state.LastPath = path
	shouldLog := nowTS.Sub(state.lastLogged) >= scannerLogInterval
	if shouldLog {
		state.lastLogged = nowTS
	}
	count := state.Count
	sw.mu.Unlock()

	if shouldLog {
		slog.Info("Scanner activity detected",
			"source", source,
			"ip", ip,
			"path", path,
			"requests_so_far", count,
		)
	}
}

// Snapshot returns all tracked scanner hits sorted by request count
// (descending), plus the number of requests from untracked IPs that were
// dropped after the registry cap was reached (counted per request, not per
// distinct IP).
func (sw *ScannerWatch) Snapshot() ([]ScannerHit, int) {
	sw.mu.Lock()
	out := make([]ScannerHit, 0, len(sw.hits))
	for _, state := range sw.hits {
		out = append(out, state.ScannerHit)
	}
	dropped := sw.overflow
	sw.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	return out, dropped
}

// Handler serves the admin-only JSON view of scanner activity since the last
// server start (registry is in-memory; structured logs hold the durable
// record via the DB sink).
func (sw *ScannerWatch) Handler(c *gin.Context) {
	hits, dropped := sw.Snapshot()
	c.JSON(200, gin.H{
		"tracked_ips":      len(hits),
		"overflow_dropped": dropped,
		"since":            "server start (in-memory; structured logs are the durable record)",
		"hits":             hits,
	})
}
