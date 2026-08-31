// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The batch endpoint is a QUEUE over the existing scan path. These tests pin
// the CONTRACT: auth (401 without/with-bad key), validation (empty/oversize/
// invalid domains), the 202 shape, and the provenance stamp — the scan itself
// is the single analyzer, tested elsewhere.

type fakeScanKeyLookup struct {
	known map[string]int32 // hash -> id
}

func (f *fakeScanKeyLookup) LookupScanKey(keyHash string) (int32, string, bool) {
	for h, id := range f.known {
		if h == keyHash {
			return id, "test-key", true
		}
	}
	return 0, "", false
}

func newBatchRouter(lookup *fakeScanKeyLookup) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AnalysisHandler{}
	good := r.Group("/api/batch")
	good.Use(func(c *gin.Context) {
		// inline version of the auth middleware against the fake lookup
		raw := ""
		if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			raw = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "key required"})
			return
		}
		// fake: the test passes the PRE-HASHED key as the bearer; the middleware
		// contract hashes — for the unit test we accept the hash directly.
		id, label, ok := lookup.LookupScanKey(raw)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unknown key"})
			return
		}
		c.Set("scan_key_id", id)
		c.Set("scan_key_label", label)
		c.Next()
	})
	good.POST("", h.AnalyzeBatch)
	return r
}

func TestAnalyzeBatch_RejectsMissingKey(t *testing.T) {
	r := newBatchRouter(&fakeScanKeyLookup{})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no key: got %d, want 401", w.Code)
	}
}

func TestAnalyzeBatch_RejectsBadKey(t *testing.T) {
	r := newBatchRouter(&fakeScanKeyLookup{known: map[string]int32{"aa": 1}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bb")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad key: got %d, want 401", w.Code)
	}
}

func TestAnalyzeBatch_RejectsEmptyDomains(t *testing.T) {
	r := newBatchRouter(&fakeScanKeyLookup{known: map[string]int32{"aa": 1}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(`{"domains":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aa")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty: got %d, want 400", w.Code)
	}
}

func TestAnalyzeBatch_RejectsOversize(t *testing.T) {
	r := newBatchRouter(&fakeScanKeyLookup{known: map[string]int32{"aa": 1}})
	domains := make([]string, maxBatchDomains+1)
	for i := range domains {
		domains[i] = "example.com"
	}
	body, _ := json.Marshal(map[string]any{"domains": domains})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aa")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversize: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "split into multiple batches") {
		t.Errorf("oversize error must name the remedy, got: %s", w.Body.String())
	}
}

func TestAnalyzeBatch_ValidatesPerDomain(t *testing.T) {
	r := newBatchRouter(&fakeScanKeyLookup{known: map[string]int32{"aa": 1}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(
		`{"domains":["example.com","!!invalid!!"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aa")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("mixed validity: got %d, want 202 (batch accepted, per-domain errors in body)", w.Code)
	}
	var resp batchScanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 202: %v", err)
	}
	if resp.Queued != 1 || resp.Failed != 1 {
		t.Errorf("queued=%d failed=%d, want 1/1", resp.Queued, resp.Failed)
	}
	if resp.BatchID == "" || resp.KeyLabel != "test-key" {
		t.Errorf("batch id/label missing: %+v", resp)
	}
}

func TestStampBatchProvenance_Shape(t *testing.T) {
	results := map[string]any{}
	stampBatchProvenance(results, "b_123", "decay-day5", 7)
	if results["_request_source"] != "batch" {
		t.Error("_request_source must be batch")
	}
	b, ok := results["_batch"].(map[string]any)
	if !ok {
		t.Fatal("_batch must be a map")
	}
	if b["id"] != "b_123" || b["label"] != "decay-day5" || b["key_id"] != int32(7) {
		t.Errorf("batch facts wrong: %+v", b)
	}
	if b["channel"] != "api_batch" {
		t.Errorf("channel wrong: %v", b["channel"])
	}
}

func TestNewBatchID_UniqueAndShaped(t *testing.T) {
	a, b := newBatchID(), newBatchID()
	if a == b {
		t.Fatal("two batch ids must differ")
	}
	if !strings.HasPrefix(a, "b_") {
		t.Errorf("batch id shape: %s", a)
	}
}
