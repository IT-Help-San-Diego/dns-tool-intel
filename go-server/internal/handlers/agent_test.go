// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

func setupAgentRouter() (*gin.Engine, *AgentHandler) {
        gin.SetMode(gin.TestMode)
        r := gin.New()
        cfg := &config.Config{
                AppVersion: "26.38.39",
                BaseURL:    "https://dnstool.it-help.tech",
        }
        h := NewAgentHandler(cfg, nil)
        return r, h
}

func TestOpenSearchXML(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/opensearch.xml", h.OpenSearchXML)

        req := httptest.NewRequest(http.MethodGet, "/agent/opensearch.xml", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200, got %d", w.Code)
        }
        ct := w.Header().Get("Content-Type")
        if !strings.Contains(ct, "opensearchdescription+xml") {
                t.Fatalf("expected opensearch content type, got %s", ct)
        }
        body := w.Body.String()
        if !strings.Contains(body, "DNS Tool") {
                t.Fatal("missing DNS Tool in OpenSearch XML")
        }
        if !strings.Contains(body, "{searchTerms}") {
                t.Fatal("missing {searchTerms} placeholder")
        }
        if !strings.Contains(body, "dnstool.it-help.tech") {
                t.Fatal("missing base URL in OpenSearch XML")
        }
}

func TestAgentSearchMissingQuery(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, "/agent/search", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Missing query parameter") {
                t.Fatal("expected missing query error message")
        }
}

func TestAgentSearchInvalidDomain(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, "/agent/search?q=not-a-valid-domain!!!", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Invalid domain") {
                t.Fatal("expected invalid domain error message")
        }
}

func TestAgentAPIMissingQuery(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/api", h.AgentAPI)

        req := httptest.NewRequest(http.MethodGet, "/agent/api", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Missing query parameter") {
                t.Fatal("expected missing query error message")
        }
}

func TestAgentAPIInvalidDomain(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/api", h.AgentAPI)

        req := httptest.NewRequest(http.MethodGet, "/agent/api?q=not-a-valid-domain!!!", nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        if w.Code != http.StatusBadRequest {
                t.Fatalf("expected 400, got %d", w.Code)
        }
        if !strings.Contains(w.Body.String(), "Invalid domain") {
                t.Fatal("expected invalid domain error message")
        }
}

func TestBoolToPresence(t *testing.T) {
        if boolToPresence(true) != "present" {
                t.Fatal("expected 'present' for true")
        }
        if boolToPresence(false) != "not found" {
                t.Fatal("expected 'not found' for false")
        }
}

func TestExtractNestedStatus(t *testing.T) {
        parent := gin.H{
                "spf": gin.H{"status": "pass"},
                "bad": "not a map",
        }
        if extractNestedStatus(parent, "spf") != "pass" {
                t.Fatal("expected 'pass'")
        }
        if extractNestedStatus(parent, "bad") != "unknown" {
                t.Fatal("expected 'unknown' for non-map")
        }
        if extractNestedStatus(parent, "missing") != "unknown" {
                t.Fatal("expected 'unknown' for missing key")
        }
}

func TestAgentSearchXSSEscaping(t *testing.T) {
        r, h := setupAgentRouter()
        r.GET("/agent/search", h.AgentSearch)

        req := httptest.NewRequest(http.MethodGet, `/agent/search?q=%3Cscript%3Ealert(1)%3C/script%3E`, nil)
        w := httptest.NewRecorder()
        r.ServeHTTP(w, req)

        body := w.Body.String()
        if strings.Contains(body, "<script>") {
                t.Fatal("XSS: raw <script> tag found in HTML response")
        }
        if !strings.Contains(body, "&lt;script&gt;") {
                t.Fatal("expected HTML-escaped script tag in response")
        }
}

func TestEscHelper(t *testing.T) {
        if esc("<b>test</b>") != "&lt;b&gt;test&lt;/b&gt;" {
                t.Fatal("esc did not escape HTML")
        }
        if esc(`"quoted"`) != "&#34;quoted&#34;" {
                t.Fatal("esc did not escape quotes")
        }
        if esc("normal") != "normal" {
                t.Fatal("esc should not change safe strings")
        }
}

func TestSafeHelpers(t *testing.T) {
        m := map[string]any{
                "str":     "hello",
                "int":     42,
                "int64":   int64(99),
                "float":   3.14,
                "bool":    true,
                "nested":  map[string]any{"key": "val"},
                "invalid": []string{"a"},
        }
        if safeString(m, "str") != "hello" {
                t.Fatal("safeString failed")
        }
        if safeString(m, "missing") != "" {
                t.Fatal("safeString missing should return empty")
        }
        if safeInt(m, "int") != 42 {
                t.Fatal("safeInt failed for int")
        }
        if safeInt(m, "int64") != 99 {
                t.Fatal("safeInt failed for int64")
        }
        if safeInt(m, "float") != 3 {
                t.Fatal("safeInt failed for float64")
        }
        if safeInt(m, "missing") != 0 {
                t.Fatal("safeInt missing should return 0")
        }
        if !safeBool(m, "bool") {
                t.Fatal("safeBool failed")
        }
        if safeBool(m, "missing") {
                t.Fatal("safeBool missing should return false")
        }
        nested := safeMap(m, "nested")
        if nested == nil || nested["key"] != "val" {
                t.Fatal("safeMap failed")
        }
        if safeMap(m, "invalid") != nil {
                t.Fatal("safeMap should return nil for non-map")
        }
}
