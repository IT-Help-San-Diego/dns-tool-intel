// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dbq"

	"github.com/gin-gonic/gin"
)

func TestComputeDriftFromPrev_NilHash(t *testing.T) {
	d := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: nil, ID: 1}, nil)
	if d.Detected {
		t.Error("expected no drift when prev hash is nil")
	}
}

func TestComputeDriftFromPrev_EmptyHash(t *testing.T) {
	empty := ""
	d := computeDriftFromPrev("abc", prevAnalysisSnapshot{Hash: &empty, ID: 1}, nil)
	if d.Detected {
		t.Error("expected no drift when prev hash is empty")
	}
}

func TestComputeDriftFromPrev_SameHash(t *testing.T) {
	h := "abc123"
	d := computeDriftFromPrev("abc123", prevAnalysisSnapshot{Hash: &h, ID: 1}, nil)
	if d.Detected {
		t.Error("expected no drift when hashes match")
	}
}

func TestComputeDriftFromPrev_DriftDetected(t *testing.T) {
	prev := "oldhash1234567890"
	now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
		Hash:           &prev,
		ID:             42,
		CreatedAtValid: true,
		CreatedAt:      now,
	}, map[string]any{"spf": "pass"})
	if !d.Detected {
		t.Fatal("expected drift to be detected")
	}
	if d.PrevHash != prev {
		t.Errorf("PrevHash = %q, want %q", d.PrevHash, prev)
	}
	if d.PrevID != 42 {
		t.Errorf("PrevID = %d, want 42", d.PrevID)
	}
	if d.PrevTime == "" {
		t.Error("PrevTime should be set when CreatedAtValid is true")
	}
}

func TestComputeDriftFromPrev_WithFullResults(t *testing.T) {
	prev := "oldhash"
	prevResults := map[string]any{"spf": "pass"}
	prevJSON, _ := json.Marshal(prevResults)
	d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
		Hash:        &prev,
		ID:          10,
		FullResults: json.RawMessage(prevJSON),
	}, map[string]any{"spf": "fail"})
	if !d.Detected {
		t.Fatal("expected drift")
	}
}

func TestComputeDriftFromPrev_NoCreatedAt(t *testing.T) {
	prev := "oldhash"
	d := computeDriftFromPrev("newhash", prevAnalysisSnapshot{
		Hash:           &prev,
		ID:             5,
		CreatedAtValid: false,
	}, nil)
	if !d.Detected {
		t.Fatal("expected drift")
	}
	if d.PrevTime != "" {
		t.Error("PrevTime should be empty when CreatedAtValid is false")
	}
}

func TestShortHash(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"abcdef", "abcdef"},
		{"1234567890abcdef", "1234567890abcdef"},
		{"1234567890abcdef0", "1234567890abcdef"},
		{"1234567890abcdef0123456789", "1234567890abcdef"},
	}
	for _, tc := range tests {
		got := shortHash(tc.in)
		if got != tc.want {
			t.Errorf("shortHash(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestConvertDriftEvents_Empty(t *testing.T) {
	result := convertDriftEvents(nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestConvertDriftEvents_WithData(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	fields := []analyzer.PostureDiffField{{Field: "spf", Severity: "warning"}}
	diffJSON, _ := json.Marshal(fields)
	events := []dbq.DriftEvent{
		{
			ID:             1,
			Domain:         "example.com",
			AnalysisID:     100,
			PrevAnalysisID: 99,
			CurrentHash:    "aaaa1111222233334444555566667777",
			PreviousHash:   "bbbb1111222233334444555566667777",
			Severity:       "warning",
			CreatedAt:      dbq.NullTime{Time: now, Valid: true},
			DiffSummary:    diffJSON,
		},
	}
	result := convertDriftEvents(events)
	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	ev := result[0]
	if ev.Domain != "example.com" {
		t.Errorf("domain = %q", ev.Domain)
	}
	if ev.CurrentHashShort != "aaaa111122223333" {
		t.Errorf("short hash = %q", ev.CurrentHashShort)
	}
	if ev.CreatedAt == "" {
		t.Error("CreatedAt should be formatted")
	}
	if len(ev.Fields) != 1 {
		t.Errorf("Fields = %d, want 1", len(ev.Fields))
	}
}

func TestConvertDriftEvents_InvalidDiffJSON(t *testing.T) {
	events := []dbq.DriftEvent{
		{
			ID:          2,
			Domain:      "test.com",
			CurrentHash: "aabbccdd",
			DiffSummary: []byte(`not valid json`),
		},
	}
	result := convertDriftEvents(events)
	if len(result) != 1 {
		t.Fatal("expected 1 event")
	}
	if result[0].Fields != nil {
		t.Error("Fields should be nil for invalid JSON")
	}
}

func TestBuildHashHistory_Empty(t *testing.T) {
	result := buildHashHistory(nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestBuildHashHistory_WithData(t *testing.T) {
	h1 := "hash_a_1234567890abcdef"
	h2 := "hash_b_1234567890abcdef"
	now := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	analyses := []dbq.DomainAnalysis{
		{ID: 3, PostureHash: &h2, CreatedAt: dbq.NullTime{Time: now.Add(1 * time.Hour), Valid: true}},
		{ID: 2, PostureHash: &h1, CreatedAt: dbq.NullTime{Time: now, Valid: true}},
		{ID: 1, PostureHash: &h1, CreatedAt: dbq.NullTime{Time: now.Add(-1 * time.Hour), Valid: true}},
	}
	result := buildHashHistory(analyses)
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	if result[0].HashChanged {
		t.Error("first entry should not have HashChanged")
	}
	foundChanged := false
	for _, e := range result {
		if e.HashChanged {
			foundChanged = true
		}
	}
	if !foundChanged {
		t.Error("expected at least one HashChanged entry")
	}
}

func TestBuildHashHistory_NilHash(t *testing.T) {
	analyses := []dbq.DomainAnalysis{
		{ID: 1, PostureHash: nil},
	}
	result := buildHashHistory(analyses)
	if len(result) != 1 {
		t.Fatal("expected 1")
	}
	if result[0].PostureHash != "" {
		t.Error("expected empty PostureHash for nil")
	}
}

func TestLogEphemeralReason_DevNull(t *testing.T) {
	logEphemeralReason("example.com", true, true)
}

func TestLogEphemeralReason_NonExistent(t *testing.T) {
	logEphemeralReason("example.com", false, false)
}

func TestLogEphemeralReason_Ephemeral(t *testing.T) {
	logEphemeralReason("example.com", false, true)
}

func TestRedactDignityAmendments(t *testing.T) {
	event := &IntegrityEvent{
		Amendments: []Amendment{
			{Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "sensitive-data"},
			{Ground: "OTHER_GROUND", OriginalValue: "keep-this"},
		},
	}
	redactDignityAmendments(event)
	if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
		t.Errorf("dignity amendment not redacted: %q", event.Amendments[0].OriginalValue)
	}
	if event.Amendments[1].OriginalValue != "keep-this" {
		t.Error("non-dignity amendment should not be redacted")
	}
}

func TestRedactDignityAmendments_AlreadyRedacted(t *testing.T) {
	event := &IntegrityEvent{
		Amendments: []Amendment{
			{Ground: "DIGNITY_OF_EXPRESSION", OriginalValue: "[REDACTED — DIGNITY_OF_EXPRESSION]"},
		},
	}
	redactDignityAmendments(event)
	if event.Amendments[0].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
		t.Error("should remain redacted")
	}
}

func TestRedactDignityAmendments_NoAmendments(t *testing.T) {
	event := &IntegrityEvent{}
	redactDignityAmendments(event)
}

func TestHashEvent(t *testing.T) {
	event := &IntegrityEvent{
		EventType:   "test",
		Description: "test event",
	}
	hashEvent(event)
	if event.EventHash == "" {
		t.Error("EventHash should be populated")
	}
	if len(event.EventHash) != 128 {
		t.Errorf("SHA3-512 hex length = %d, want 128", len(event.EventHash))
	}
}

func TestHashEvent_Deterministic(t *testing.T) {
	e1 := &IntegrityEvent{EventType: "a", Description: "b"}
	e2 := &IntegrityEvent{EventType: "a", Description: "b"}
	hashEvent(e1)
	hashEvent(e2)
	if e1.EventHash != e2.EventHash {
		t.Error("same input should produce same hash")
	}
}

func TestScanProgressStore_NewToken(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	token, sp := ps.NewToken()
	if token == "" {
		t.Fatal("token should not be empty")
	}
	if sp == nil {
		t.Fatal("scanProgress should not be nil")
	}
}

func TestScanProgressStore_Get(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	token, _ := ps.NewToken()
	sp, ok := ps.Get(token)
	if !ok {
		t.Fatal("should find token")
	}
	if sp == nil {
		t.Fatal("should return scanProgress")
	}
}

func TestScanProgressStore_GetMissing(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, ok := ps.Get("nonexistent-token")
	if ok {
		t.Error("should not find missing token")
	}
}

func TestScanProgressStore_Delete(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	token, _ := ps.NewToken()
	ps.Delete(token)
	_, ok := ps.Get(token)
	if ok {
		t.Error("should not find deleted token")
	}
}

func TestScanProgress_MarkComplete(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	sp.UpdatePhase("dns", "running", 100)
	sp.MarkComplete(42, "/analysis/42")
	j := sp.toJSON()
	if j["status"] != "complete" {
		t.Errorf("status = %v, want complete", j["status"])
	}
	if j["analysis_id"] != int32(42) {
		t.Errorf("analysis_id = %v", j["analysis_id"])
	}
	if j["redirect_url"] != "/analysis/42" {
		t.Errorf("redirect = %v", j["redirect_url"])
	}
}

func TestScanProgress_MarkFailed(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	sp.MarkFailed("test failure")
	j := sp.toJSON()
	if j["status"] != "failed" {
		t.Errorf("status = %v, want failed", j["status"])
	}
	if j["error"] != "test failure" {
		t.Errorf("error = %v", j["error"])
	}
}

func TestScanProgress_MakeProgressCallback(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	cb := sp.MakeProgressCallback()
	if cb == nil {
		t.Fatal("callback should not be nil")
	}
	cb("dns", "running", 50)
	j := sp.toJSON()
	phases, ok := j["phases"].(map[string]any)
	if !ok {
		t.Fatal("phases should be a map")
	}
	if _, exists := phases["dns"]; !exists {
		t.Error("dns phase should exist after callback")
	}
}

func TestScanProgress_UpdatePhase_NewPhase(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	sp.UpdatePhase("spf", "running", 200)
	j := sp.toJSON()
	phases := j["phases"].(map[string]any)
	spf := phases["spf"].(map[string]any)
	if spf["status"] != "running" {
		t.Errorf("status = %v", spf["status"])
	}
}

func TestScanProgress_UpdatePhase_Done(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	sp.UpdatePhase("mx", "running", 100)
	sp.UpdatePhase("mx", "done", 200)
	j := sp.toJSON()
	phases := j["phases"].(map[string]any)
	mx := phases["mx"].(map[string]any)
	if mx["status"] != "done" {
		t.Errorf("status = %v, want done", mx["status"])
	}
}

func TestScanProgress_UpdatePhase_IgnoreAfterDone(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Stop()
	_, sp := ps.NewToken()
	sp.UpdatePhase("a", "done", 100)
	sp.UpdatePhase("a", "running", 200)
	j := sp.toJSON()
	phases := j["phases"].(map[string]any)
	a := phases["a"].(map[string]any)
	if a["status"] != "done" {
		t.Error("should remain done after subsequent update")
	}
}

func TestStoreTelemetry_EphemeralSkipped(t *testing.T) {
	h := &AnalysisHandler{}
	h.storeTelemetry(nil, 0, nil, true)
}

func TestStoreTelemetry_ZeroIDSkipped(t *testing.T) {
	h := &AnalysisHandler{}
	h.storeTelemetry(nil, 0, map[string]any{"spf": "pass"}, false)
}

func TestStoreTelemetry_NoTelemetryKey(t *testing.T) {
	h := &AnalysisHandler{}
	h.storeTelemetry(nil, 42, map[string]any{"spf": "pass"}, false)
}

func TestStoreTelemetry_WrongType(t *testing.T) {
	h := &AnalysisHandler{}
	h.storeTelemetry(nil, 42, map[string]any{"_scan_telemetry": "not-a-struct"}, false)
}

func TestRecordCurrencyIfEligible_Ephemeral(t *testing.T) {
	h := &AnalysisHandler{}
	h.recordCurrencyIfEligible(true, true, "example.com", nil)
}

func TestRecordCurrencyIfEligible_NonExistent(t *testing.T) {
	h := &AnalysisHandler{}
	h.recordCurrencyIfEligible(false, false, "example.com", nil)
}

func TestRecordCurrencyIfEligible_NoCurrencyReport(t *testing.T) {
	h := &AnalysisHandler{}
	h.recordCurrencyIfEligible(false, true, "example.com", map[string]any{})
}

func TestApplyDevNullHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	applyDevNullHeaders(c, true)
	if w.Header().Get("X-Hacker") == "" {
		t.Error("X-Hacker should be set")
	}
	if w.Header().Get("X-Persistence") != "/dev/null" {
		t.Errorf("X-Persistence = %q", w.Header().Get("X-Persistence"))
	}
}

func TestApplyDevNullHeaders_NotDevNull(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	applyDevNullHeaders(c, false)
	if w.Header().Get("X-Hacker") != "" {
		t.Error("X-Hacker should not be set")
	}
}

func TestResolveCovertMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name   string
		covert string
		domain string
		want   string
	}{
		{"normal", "", "example.com", "E"},
		{"covert", "1", "example.com", "C"},
		{"tld", "", "com", "Z"},
		{"covert_tld", "1", "com", "CZ"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			url := "/?covert=" + tc.covert
			c.Request = httptest.NewRequest(http.MethodGet, url, nil)
			got := resolveCovertMode(c, tc.domain)
			if got != tc.want {
				t.Errorf("resolveCovertMode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractAuthInfo_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	isAuth, uid := extractAuthInfo(c)
	if isAuth {
		t.Error("should not be authenticated")
	}
	if uid != 0 {
		t.Errorf("uid = %d", uid)
	}
}

func TestExtractAuthInfo_Authenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set("authenticated", true)
	c.Set("user_id", int32(99))

	isAuth, uid := extractAuthInfo(c)
	if !isAuth {
		t.Error("should be authenticated")
	}
	if uid != 99 {
		t.Errorf("uid = %d, want 99", uid)
	}
}

func TestNewTopologyHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0", BetaPages: map[string]bool{"topology": true}}
	h := NewTopologyHandler(cfg)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
	if h.Config.AppVersion != "1.0" {
		t.Error("config not set")
	}
}

func TestNewVideoHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "2.0"}
	h := NewVideoHandler(cfg)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestNewTelemetryHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "3.0"}
	h := NewTelemetryHandler(nil, cfg)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
	if h.Config.AppVersion != "3.0" {
		t.Error("config not set")
	}
}

func TestNewPipelineHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "4.0"}
	h := NewPipelineHandler(nil, cfg)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestAnimContentType(t *testing.T) {
	if animContentType("gif") != "image/gif" {
		t.Error("gif should return image/gif")
	}
	if animContentType("apng") != "image/png" {
		t.Error("apng should return image/png")
	}
	if animContentType("") != "image/png" {
		t.Error("empty should default to image/png")
	}
}

func TestStoreAnimInCache(t *testing.T) {
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()

	data := []byte("test-animation-data")
	etag := storeAnimInCache("test-key", data)
	if etag == "" {
		t.Fatal("etag should not be empty")
	}

	animCacheMu.RLock()
	entry, ok := animCache["test-key"]
	animCacheMu.RUnlock()
	if !ok {
		t.Fatal("entry should be in cache")
	}
	if string(entry.data) != "test-animation-data" {
		t.Error("data mismatch")
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestEvictLRUAnimEntry(t *testing.T) {
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	now := time.Now()
	animCache["old"] = &animCacheEntry{data: []byte("a"), lastAccess: now.Add(-1 * time.Hour)}
	animCache["new"] = &animCacheEntry{data: []byte("b"), lastAccess: now}
	evictLRUAnimEntry()
	_, oldExists := animCache["old"]
	_, newExists := animCache["new"]
	animCacheMu.Unlock()

	if oldExists {
		t.Error("old entry should have been evicted")
	}
	if !newExists {
		t.Error("new entry should remain")
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestServeAnimFromCache_Miss(t *testing.T) {
	gin.SetMode(gin.TestMode)
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

	served := serveAnimFromCache(c, "missing-key", "apng")
	if served {
		t.Error("should return false for cache miss")
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestServeAnimFromCache_Hit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCache["hit-key"] = &animCacheEntry{
		data:       []byte("cached-data"),
		createdAt:  time.Now(),
		lastAccess: time.Now(),
		etag:       `"abc123"`,
	}
	animCacheMu.Unlock()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

	served := serveAnimFromCache(c, "hit-key", "apng")
	if !served {
		t.Error("should return true for cache hit")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("ETag") != `"abc123"` {
		t.Errorf("ETag = %q", w.Header().Get("ETag"))
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestServeAnimFromCache_NotModified(t *testing.T) {
	gin.SetMode(gin.TestMode)
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCache["etag-key"] = &animCacheEntry{
		data:       []byte("data"),
		createdAt:  time.Now(),
		lastAccess: time.Now(),
		etag:       `"match"`,
	}
	animCacheMu.Unlock()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)
	c.Request.Header.Set("If-None-Match", `"match"`)

	served := serveAnimFromCache(c, "etag-key", "apng")
	if !served {
		t.Error("should return true")
	}
	if w.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304", w.Code)
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestServeAnimFromCache_Expired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCache["expired"] = &animCacheEntry{
		data:       []byte("stale"),
		createdAt:  time.Now().Add(-time.Duration(animCacheMaxAge+10) * time.Second),
		lastAccess: time.Now(),
		etag:       `"old"`,
	}
	animCacheMu.Unlock()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/badge.apng", nil)

	served := serveAnimFromCache(c, "expired", "apng")
	if served {
		t.Error("should return false for expired entry")
	}

	animCacheMu.Lock()
	animCache = make(map[string]*animCacheEntry)
	animCacheMu.Unlock()
}

func TestGetStringFromResults_TopLevel(t *testing.T) {
	results := map[string]any{"spf": "v=spf1 include:example.com"}
	got := getStringFromResults(results, "spf", "")
	if got == nil || *got != "v=spf1 include:example.com" {
		t.Errorf("got %v", got)
	}
}

func TestGetStringFromResults_Nested(t *testing.T) {
	results := map[string]any{
		"dmarc": map[string]any{"policy": "reject"},
	}
	got := getStringFromResults(results, "dmarc", "policy")
	if got == nil || *got != "reject" {
		t.Errorf("got %v", got)
	}
}

func TestGetStringFromResults_Missing(t *testing.T) {
	results := map[string]any{}
	got := getStringFromResults(results, "missing", "")
	if got != nil {
		t.Error("should be nil for missing key")
	}
}

func TestGetStringFromResults_WrongType(t *testing.T) {
	results := map[string]any{"count": 42}
	got := getStringFromResults(results, "count", "")
	if got != nil {
		t.Error("should be nil for non-string value")
	}
}

func TestGetStringFromResults_NestedMissing(t *testing.T) {
	results := map[string]any{
		"dmarc": map[string]any{"policy": "reject"},
	}
	got := getStringFromResults(results, "dmarc", "missing")
	if got != nil {
		t.Error("should be nil for missing nested key")
	}
}

func TestGetStringFromResults_NotMap(t *testing.T) {
	results := map[string]any{"spf": "string_not_map"}
	got := getStringFromResults(results, "spf", "sub")
	if got != nil {
		t.Error("should be nil when section is not a map")
	}
}

func TestDerefString(t *testing.T) {
	s := "hello"
	if derefString(&s) != "hello" {
		t.Error("should return value")
	}
	if derefString(nil) != "" {
		t.Error("should return empty for nil")
	}
}

func TestExtractReportsAndDurations_Empty(t *testing.T) {
	reports, durations := extractReportsAndDurations(nil)
	if len(reports) != 0 || len(durations) != 0 {
		t.Error("should be empty")
	}
}

func TestExtractReportsAndDurations_EmptyResults(t *testing.T) {
	analyses := []dbq.DomainAnalysis{{FullResults: nil}}
	reports, durations := extractReportsAndDurations(analyses)
	if len(reports) != 0 || len(durations) != 0 {
		t.Error("should skip nil FullResults")
	}
}

func TestExtractReportsAndDurations_InvalidJSON(t *testing.T) {
	analyses := []dbq.DomainAnalysis{{FullResults: []byte(`invalid`)}}
	reports, durations := extractReportsAndDurations(analyses)
	if len(reports) != 0 || len(durations) != 0 {
		t.Error("should skip invalid JSON")
	}
}

func TestExtractReportsAndDurations_WithDuration(t *testing.T) {
	dur := 1.5
	analyses := []dbq.DomainAnalysis{
		{
			FullResults:      json.RawMessage(`{}`),
			AnalysisDuration: &dur,
		},
	}
	reports, durations := extractReportsAndDurations(analyses)
	if len(reports) != 0 {
		t.Error("no currency report expected")
	}
	if len(durations) != 1 || durations[0] != 1500 {
		t.Errorf("durations = %v, want [1500]", durations)
	}
}

func TestNewDriftHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewDriftHandler(nil, cfg)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestNewAuditLogHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewAuditLogHandler(cfg, nil)
	if h == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestAnalysisTimestamp_NoUpdate(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	a := dbq.DomainAnalysis{
		CreatedAt: dbq.NullTime{Time: now, Valid: true},
	}
	ts := analysisTimestamp(a)
	if ts == "" {
		t.Error("should format timestamp")
	}
}

func TestAnalysisDuration_Nil(t *testing.T) {
	a := dbq.DomainAnalysis{}
	if analysisDuration(a) != 0.0 {
		t.Error("should return 0 for nil duration")
	}
}

func TestAnalysisDuration_WithValue(t *testing.T) {
	d := 2.5
	a := dbq.DomainAnalysis{AnalysisDuration: &d}
	if analysisDuration(a) != 2.5 {
		t.Errorf("got %f", analysisDuration(a))
	}
}

func TestNewStatsHandler(t *testing.T) {
	cfg := &config.Config{AppVersion: "1.0"}
	h := NewStatsHandler(nil, cfg)
	if h == nil || h.Config.AppVersion != "1.0" {
		t.Error("handler not initialized correctly")
	}
}

func TestRecordUserAnalysisAsync_UnauthenticatedSkips(t *testing.T) {
	h := &AnalysisHandler{}
	h.recordUserAnalysisAsync(sideEffectsParams{isAuthenticated: false, userID: 0})
}

func TestRecordUserAnalysisAsync_ZeroUserIDSkips(t *testing.T) {
	h := &AnalysisHandler{}
	h.recordUserAnalysisAsync(sideEffectsParams{isAuthenticated: true, userID: 0})
}
