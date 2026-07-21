// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newScannerWatchRouter(sw *ScannerWatch) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sw.Middleware())
	r.GET("/probe", func(c *gin.Context) {
		src, _ := c.Get(CtxScannerSource)
		if src == nil {
			c.String(http.StatusOK, "clean")
			return
		}
		c.String(http.StatusOK, src.(string))
	})
	return r
}

func TestScannerWatch_MatcherHitTagsAndRecords(t *testing.T) {
	sw := NewScannerWatch(func(ip string) string {
		if ip == "192.0.2.10" {
			return "CISA Cyber Hygiene"
		}
		return ""
	})
	r := newScannerWatchRouter(sw)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/probe", nil)
		req.RemoteAddr = "192.0.2.10:4444"
		r.ServeHTTP(w, req)
		if w.Body.String() != "CISA Cyber Hygiene" {
			t.Fatalf("expected context tag, got %q", w.Body.String())
		}
	}

	hits, dropped := sw.Snapshot()
	if dropped != 0 {
		t.Errorf("expected no overflow, got %d", dropped)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 tracked IP, got %d", len(hits))
	}
	h := hits[0]
	if h.IP != "192.0.2.10" || h.Source != "CISA Cyber Hygiene" || h.Count != 3 {
		t.Errorf("unexpected hit: %+v", h)
	}
	if h.LastPath != "/probe" {
		t.Errorf("expected last path /probe, got %q", h.LastPath)
	}
	if h.FirstSeen.IsZero() || h.LastSeen.Before(h.FirstSeen) {
		t.Errorf("bad seen window: first=%v last=%v", h.FirstSeen, h.LastSeen)
	}
}

func TestScannerWatch_CleanTrafficUntouched(t *testing.T) {
	sw := NewScannerWatch(func(string) string { return "" })
	r := newScannerWatchRouter(sw)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("Referer", "https://www.google.com/")
	r.ServeHTTP(w, req)

	if w.Body.String() != "clean" {
		t.Errorf("clean traffic should not be tagged, got %q", w.Body.String())
	}
	hits, _ := sw.Snapshot()
	if len(hits) != 0 {
		t.Errorf("expected empty registry, got %d hits", len(hits))
	}
}

func TestScannerWatch_ForgedLocalhostReferer(t *testing.T) {
	tests := []struct {
		name    string
		referer string
		want    bool
	}{
		{"schemeless quote probe", "localhost/'", true},
		{"schemeless paren probe", "localhost/(", true},
		{"schemeless float probe", "localhost/1e309", true},
		{"http localhost", "http://localhost/x", true},
		{"loopback v4", "http://127.0.0.1/", true},
		{"unspecified v4", "http://0.0.0.0/", true},
		{"schemeless with port", "localhost:5000/x", true},
		{"loopback v4 with port", "127.0.0.1:80/x", true},
		{"uppercase localhost", "LOCALHOST/'", true},
		{"http localhost with port", "http://localhost:8080/x", true},
		{"real referrer", "https://www.google.com/", false},
		{"empty", "", false},
		{"localhost as subdomain", "https://localhost.example.com/", false},
		{"relative path only", "/somewhere", false},
		{"javascript scheme", "javascript:alert(1)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := forgedLocalhostReferer(tt.referer)
			if tt.want && got != "Forged Localhost Referer" {
				t.Errorf("forgedLocalhostReferer(%q) = %q, want tagged", tt.referer, got)
			}
			if !tt.want && got != "" {
				t.Errorf("forgedLocalhostReferer(%q) = %q, want empty", tt.referer, got)
			}
		})
	}
}

func TestScannerWatch_RefererProbeRecorded(t *testing.T) {
	sw := NewScannerWatch(nil)
	r := newScannerWatchRouter(sw)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/probe", nil)
	req.RemoteAddr = "198.51.100.7:9999"
	req.Header.Set("Referer", "localhost/1e309")
	r.ServeHTTP(w, req)

	if w.Body.String() != "Forged Localhost Referer" {
		t.Fatalf("expected forged-referer tag, got %q", w.Body.String())
	}
	hits, _ := sw.Snapshot()
	if len(hits) != 1 || hits[0].Source != "Forged Localhost Referer" {
		t.Fatalf("expected recorded referer probe, got %+v", hits)
	}
}

func TestScannerWatch_OverflowCap(t *testing.T) {
	sw := NewScannerWatch(nil)
	for i := 0; i < scannerWatchMaxIPs+50; i++ {
		sw.record(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "CISA Cyber Hygiene", "/x")
	}
	hits, dropped := sw.Snapshot()
	if len(hits) != scannerWatchMaxIPs {
		t.Errorf("expected registry capped at %d, got %d", scannerWatchMaxIPs, len(hits))
	}
	if dropped != 50 {
		t.Errorf("expected 50 dropped, got %d", dropped)
	}
}

func TestScannerWatch_SnapshotSortedByCount(t *testing.T) {
	sw := NewScannerWatch(nil)
	sw.record("10.0.0.1", "CISA Cyber Hygiene", "/a")
	sw.record("10.0.0.2", "CISA Cyber Hygiene", "/b")
	sw.record("10.0.0.2", "CISA Cyber Hygiene", "/c")

	hits, _ := sw.Snapshot()
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	if hits[0].IP != "10.0.0.2" || hits[0].Count != 2 {
		t.Errorf("expected 10.0.0.2 (count 2) first, got %+v", hits[0])
	}
}

func TestScannerWatch_LogThrottle(t *testing.T) {
	sw := NewScannerWatch(nil)
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	current := base
	sw.now = func() time.Time { return current }

	sw.record("10.0.0.9", "CISA Cyber Hygiene", "/a")
	first := sw.hits["10.0.0.9"].lastLogged
	if !first.Equal(base) {
		t.Fatalf("first hit should log immediately, lastLogged=%v", first)
	}

	current = base.Add(5 * time.Minute)
	sw.record("10.0.0.9", "CISA Cyber Hygiene", "/b")
	if !sw.hits["10.0.0.9"].lastLogged.Equal(base) {
		t.Error("second hit within interval should not re-log")
	}

	current = base.Add(scannerLogInterval + time.Minute)
	sw.record("10.0.0.9", "CISA Cyber Hygiene", "/c")
	if !sw.hits["10.0.0.9"].lastLogged.Equal(current) {
		t.Error("hit after interval should re-log")
	}
}

func TestScannerWatch_HandlerJSON(t *testing.T) {
	sw := NewScannerWatch(nil)
	sw.record("10.0.0.3", "CISA Cyber Hygiene", "/scan")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ops/scanners", sw.Handler)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/scanners", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"tracked_ips":1`, `"10.0.0.3"`, `"CISA Cyber Hygiene"`, `"/scan"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %s: %s", want, body)
		}
	}
}
