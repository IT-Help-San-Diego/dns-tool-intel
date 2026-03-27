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

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 help page, got %d", w.Code)
        }
        body := w.Body.String()
        if !strings.Contains(body, "Agent Search") {
                t.Fatal("expected help page with Agent Search heading")
        }
        if !strings.Contains(body, "/agent/search?q=") {
                t.Fatal("expected example links on help page")
        }
}

func TestCleanAgentQuery(t *testing.T) {
        tests := []struct {
                input, expect string
        }{
                {`_"it-help.tech"_`, "it-help.tech"},
                {`_"apple.com"_`, "apple.com"},
                {`_Test_`, "test"},
                {"example.com", "example.com"},
                {"  EXAMPLE.COM  ", "example.com"},
                {`"example.com"`, "example.com"},
                {`'example.com'`, "example.com"},
                {"__example.com__", "example.com"},
                {`_"_test_"_`, "test"},
        }
        for _, tt := range tests {
                got := cleanAgentQuery(tt.input)
                if got != tt.expect {
                        t.Errorf("cleanAgentQuery(%q) = %q, want %q", tt.input, got, tt.expect)
                }
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

func TestSafeFloat64(t *testing.T) {
        m := map[string]any{
                "f64":   float64(3.14),
                "int":   42,
                "int64": int64(99),
                "str":   "nope",
        }
        if safeFloat64(m, "f64") != 3.14 {
                t.Fatal("safeFloat64 failed for float64")
        }
        if safeFloat64(m, "int") != 42.0 {
                t.Fatal("safeFloat64 failed for int")
        }
        if safeFloat64(m, "int64") != 99.0 {
                t.Fatal("safeFloat64 failed for int64")
        }
        if safeFloat64(m, "str") != 0 {
                t.Fatal("safeFloat64 should return 0 for non-numeric")
        }
        if safeFloat64(m, "missing") != 0 {
                t.Fatal("safeFloat64 missing should return 0")
        }
}

func TestBuildAgentJSONEnrichedLinks(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "low",
                "posture":       map[string]any{"score": float64(85), "grade": "B+", "label": "Good"},
        }
        j := h.buildAgentJSON("example.com", results)

        links, ok := j["links"].(gin.H)
        if !ok {
                t.Fatal("missing links section")
        }
        checks := map[string]string{
                "report":          "https://dnstool.it-help.tech/analyze?domain=example.com",
                "snapshot":        "https://dnstool.it-help.tech/snapshot/example.com",
                "topology":       "https://dnstool.it-help.tech/topology?domain=example.com",
                "wayback_archive": "https://web.archive.org/web/https://dnstool.it-help.tech/analyze?domain=example.com",
                "api_json":        "https://dnstool.it-help.tech/agent/api?q=example.com",
        }
        for key, want := range checks {
                got, ok := links[key].(string)
                if !ok || got != want {
                        t.Errorf("links[%q] = %q, want %q", key, got, want)
                }
        }

        badges, ok := j["badges"].(gin.H)
        if !ok {
                t.Fatal("missing badges section")
        }
        badgeChecks := map[string]string{
                "detailed_svg": "https://dnstool.it-help.tech/badge?domain=example.com&style=detailed",
                "covert_svg":   "https://dnstool.it-help.tech/badge?domain=example.com&style=covert",
                "flat_svg":     "https://dnstool.it-help.tech/badge?domain=example.com",
        }
        for key, want := range badgeChecks {
                got, ok := badges[key].(string)
                if !ok || got != want {
                        t.Errorf("badges[%q] = %q, want %q", key, got, want)
                }
        }

        summary, ok := j["summary"].(gin.H)
        if !ok {
                t.Fatal("missing summary")
        }
        if summary["posture_score"] != 85 {
                t.Errorf("posture_score = %v, want 85", summary["posture_score"])
        }
        if summary["posture_grade"] != "B+" {
                t.Errorf("posture_grade = %v, want B+", summary["posture_grade"])
        }
}

func TestBuildAgentHTMLZoteroMetadata(t *testing.T) {
        _, h := setupAgentRouter()
        results := map[string]any{
                "domain_exists": true,
                "risk_level":    "low",
                "posture":       map[string]any{"score": float64(72), "grade": "C+", "label": "Fair"},
                "spf_analysis":  map[string]any{"has_spf": true, "verdict": "pass"},
                "dmarc_analysis": map[string]any{"has_dmarc": true, "verdict": "present", "policy": "reject"},
                "dkim_analysis":  map[string]any{"has_dkim": true, "verdict": "present"},
        }
        html := h.buildAgentHTML("example.com", results)

        zoteroChecks := []string{
                `name="DC.title"`,
                `name="DC.creator"`,
                `name="DC.publisher"`,
                `name="DC.date"`,
                `name="DC.type" content="Dataset"`,
                `name="citation_title"`,
                `name="citation_author"`,
                `name="citation_doi" content="10.5281/zenodo.18854899"`,
                `class="Z3988"`,
                `ctx_ver=Z39.88-2004`,
                `property="og:title"`,
                `property="og:image"`,
        }
        for _, check := range zoteroChecks {
                if !strings.Contains(html, check) {
                        t.Errorf("missing Zotero/citation metadata: %q", check)
                }
        }

        assetChecks := []string{
                "/snapshot/example.com",
                "/topology?domain=example.com",
                "web.archive.org/web/",
                "style=detailed",
                "style=covert",
                "Observed Records Snapshot",
                "Analysis Pipeline",
                "Internet Archive",
        }
        for _, check := range assetChecks {
                if !strings.Contains(html, check) {
                        t.Errorf("missing enrichment in HTML: %q", check)
                }
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
