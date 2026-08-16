//go:build coverage

package handlers

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"

        "dnstool/go-server/internal/analyzer"

        "github.com/gin-gonic/gin"
)

func TestIsAnalysisFailure_MissingKey_Ext2(t *testing.T) {
        results := map[string]any{}
        failed, msg := isAnalysisFailure(results)
        if failed {
                t.Error("expected not failed when key missing")
        }
        if msg != "" {
                t.Errorf("expected empty msg, got %s", msg)
        }
}

func TestIsAnalysisFailure_SuccessFalseNoError_Ext2(t *testing.T) {
        results := map[string]any{"analysis_success": false}
        failed, _ := isAnalysisFailure(results)
        if failed {
                t.Error("expected not failed when no error key")
        }
}

func TestIsAnalysisFailure_SuccessFalseEmptyError_Ext2(t *testing.T) {
        results := map[string]any{"analysis_success": false, "error": ""}
        failed, msg := isAnalysisFailure(results)
        if !failed {
                t.Error("expected failed=true for success=false with empty error (string assertion succeeds)")
        }
        if msg != "" {
                t.Errorf("expected empty error msg, got %q", msg)
        }
}

func TestComputeDriftSeverity_Empty_Ext2(t *testing.T) {
        if s := computeDriftSeverity([]analyzer.PostureDiffField{}); s != "info" {
                t.Errorf("expected info for empty, got %s", s)
        }
}

func TestComputeDriftSeverity_InfoWarning_Ext2(t *testing.T) {
        fields := []analyzer.PostureDiffField{
                {Severity: "info"},
                {Severity: "warning"},
                {Severity: "info"},
        }
        if s := computeDriftSeverity(fields); s != "warning" {
                t.Errorf("expected warning, got %s", s)
        }
}

func TestShouldPersistResult_AllPositive_Ext2(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, "active", true)
        if !persist {
                t.Error("expected persist")
        }
        if reason != "" {
                t.Errorf("expected empty reason, got %s", reason)
        }
}

func TestShouldPersistResult_Ephemeral_Ext2(t *testing.T) {
        persist, reason := shouldPersistResult(true, false, "active", true)
        if persist {
                t.Error("expected no persist for ephemeral")
        }
        if reason != "ephemeral" {
                t.Errorf("expected reason=ephemeral, got %s", reason)
        }
}

func TestShouldPersistResult_DevNull_Ext2(t *testing.T) {
        persist, reason := shouldPersistResult(false, true, "active", true)
        if persist {
                t.Error("expected no persist for devNull")
        }
        if reason != "devnull" {
                t.Errorf("expected reason=devnull, got %s", reason)
        }
}

func TestShouldPersistResult_NotExist_Ext2(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, "undelegated", true)
        if persist {
                t.Error("expected no persist for non-existent")
        }
        if reason != "nonexistent_domain" {
                t.Errorf("expected reason=nonexistent_domain, got %s", reason)
        }
}

func TestShouldPersistResult_AnalysisFailure_Ext2(t *testing.T) {
        persist, reason := shouldPersistResult(false, false, "active", false)
        if !persist {
                t.Error("expected persist=true for domainExists=true, analysisSuccess=false (no filter on analysisSuccess)")
        }
        if reason != "" {
                t.Errorf("expected empty reason, got %s", reason)
        }
}

func TestShouldRunICAE_AllCombos_Ext2(t *testing.T) {
        tests := []struct {
                name         string
                ephemeral    bool
                domainExists bool
                want         bool
        }{
                {"normal active", false, true, true},
                {"ephemeral active", true, true, false},
                {"normal nonexist", false, false, false},
                {"ephemeral nonexist", true, false, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := shouldRunICAE(tt.ephemeral, tt.domainExists); got != tt.want {
                                t.Errorf("shouldRunICAE(%v, %v) = %v, want %v", tt.ephemeral, tt.domainExists, got, tt.want)
                        }
                })
        }
}

func TestResultsDomainExists_AllCases_Ext2(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    bool
        }{
                {"true bool", map[string]any{"domain_exists": true}, true},
                {"false bool", map[string]any{"domain_exists": false}, false},
                {"missing key", map[string]any{}, true},
                {"string value", map[string]any{"domain_exists": "yes"}, true},
                {"nil value", map[string]any{"domain_exists": nil}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := resultsDomainExists(tt.results); got != tt.want {
                                t.Errorf("resultsDomainExists() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestCsvEscape_SpecialChars_Ext2(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"normal text", "normal text"},
                {"=SUM(A1)", "'=SUM(A1)"},
                {"+cmd", "'+cmd"},
                {"-rm -rf", "'-rm -rf"},
                {"@func", "'@func"},
                {"has,comma", "\"has,comma\""},
                {"has\"quote", "\"has\"\"quote\""},
                {"multi\nline", "\"multi\nline\""},
                {"=both,and\"all", "\"'=both,and\"\"all\""},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := csvEscape(tt.input); got != tt.want {
                                t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestExtractToolVersion_AllCases_Ext2(t *testing.T) {
        tests := []struct {
                name    string
                results map[string]any
                want    string
        }{
                {"present string", map[string]any{"_tool_version": "2.0.0"}, "2.0.0"},
                {"missing", map[string]any{}, ""},
                {"int type", map[string]any{"_tool_version": 42}, ""},
                {"nil value", map[string]any{"_tool_version": nil}, ""},
                {"empty string", map[string]any{"_tool_version": ""}, ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := extractToolVersion(tt.results); got != tt.want {
                                t.Errorf("extractToolVersion() = %q, want %q", got, tt.want)
                        }
                })
        }
}

func TestExtractAnalysisError_AllCases_Ext2(t *testing.T) {
        tests := []struct {
                name        string
                results     map[string]any
                wantSuccess bool
                wantErrNil  bool
        }{
                {"no error", map[string]any{}, true, true},
                {"string error", map[string]any{"error": "fail"}, false, false},
                {"empty error", map[string]any{"error": ""}, true, true},
                {"int error", map[string]any{"error": 42}, true, true},
                {"nil error", map[string]any{"error": nil}, true, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        success, errPtr := extractAnalysisError(tt.results)
                        if success != tt.wantSuccess {
                                t.Errorf("success = %v, want %v", success, tt.wantSuccess)
                        }
                        if (errPtr == nil) != tt.wantErrNil {
                                t.Errorf("errPtr nil = %v, want %v", errPtr == nil, tt.wantErrNil)
                        }
                })
        }
}

func TestUnmarshalRawJSON_ValidComplex_Ext2(t *testing.T) {
        raw := json.RawMessage(`{"spf":{"status":"pass"},"dmarc":{"status":"pass"}}`)
        result := unmarshalRawJSON(raw, "test.com", "complex")
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        resultMap, ok := result.(map[string]any)
        if !ok {
                t.Fatal("expected map result")
        }
        spf, ok := resultMap["spf"].(map[string]any)
        if ok {
                if spf["status"] != "pass" {
                        t.Error("expected spf status=pass")
                }
        }
}

func TestMarshalOrderedJSON_Empty_Ext2(t *testing.T) {
        result := marshalOrderedJSON(nil)
        if result == nil {
                t.Fatal("expected non-nil result")
        }
        if string(result) != "{}" {
                t.Errorf("expected {}, got %s", string(result))
        }
}

func TestMarshalOrderedJSON_Complex_Ext2(t *testing.T) {
        entries := []orderedKV{
                {Key: "domain", Value: "example.com"},
                {Key: "score", Value: 95},
                {Key: "nested", Value: map[string]any{"inner": true}},
        }
        result := marshalOrderedJSON(entries)
        if result == nil {
                t.Fatal("expected non-nil")
        }
        var m map[string]any
        if err := json.Unmarshal(result, &m); err != nil {
                t.Fatalf("invalid JSON: %v", err)
        }
        if m["domain"] != "example.com" {
                t.Error("expected domain=example.com")
        }
}

func TestProtocolRawConfidence_AllStatuses_Ext2(t *testing.T) {
        statusTests := map[string]float64{
                "pass":    1.0,
                "secure":  1.0,
                "valid":   1.0,
                "good":    1.0,
                "warning": 0.7,
                "info":    0.7,
                "partial": 0.7,
                "fail":    0.3,
                "error":   0.0,
                "n/a":     0.0,
                "":        0.0,
                "timeout": 0.5,
                "custom":  0.5,
        }
        for status, want := range statusTests {
                results := map[string]any{"test": map[string]any{"status": status}}
                conf := protocolVerdictSeverity(results, "test")
                if conf != want {
                        t.Errorf("protocolVerdictSeverity(status=%q) = %f, want %f", status, conf, want)
                }
        }
}

func TestProtocolRawConfidence_NotMap_Ext2(t *testing.T) {
        results := map[string]any{"test": "not_a_map"}
        conf := protocolVerdictSeverity(results, "test")
        if conf != 0.0 {
                t.Errorf("expected 0.0 for non-map, got %f", conf)
        }
}

func TestEnrichCurrencyReport_WithScore_Ext2(t *testing.T) {
        data := make(map[string]any)
        results := map[string]any{
                "currency_report": map[string]any{
                        "score":            92,
                        "grade":            "A",
                        "freshness_score":  88,
                },
        }
        enrichCurrencyReport(data, results)
        if data["CurrencyReport"] == nil {
                t.Error("expected CurrencyReport")
        }
}

func TestShouldServeAsyncWait_PostMethod_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/analyze?domain=example.com", nil)
        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false for POST method")
        }
}

func TestShouldServeAsyncWait_SyncOverride_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&sync=1", nil)
        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false for sync=1")
        }
}

func TestShouldServeAsyncWait_AgentNoSelectors_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)
        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false for agent cache-eligible request")
        }
}

func TestShouldServeAsyncWait_AgentWithSelectors_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com&src=agent", nil)
        if !shouldServeAsyncWait(c, []string{"custom"}, false) {
                t.Error("expected true — agent with custom selectors is NOT cache-eligible")
        }
}

func TestShouldServeAsyncWait_FetchXHR_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)
        c.Request.Header.Set("X-Requested-With", "fetch")
        if shouldServeAsyncWait(c, nil, false) {
                t.Error("expected false with X-Requested-With=fetch")
        }
}

func TestShouldServeAsyncWait_NormalGET_Ext2(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/analyze?domain=example.com", nil)
        if !shouldServeAsyncWait(c, nil, false) {
                t.Error("expected true for normal GET without overrides")
        }
}

func TestOptionalStrings_Mixed_Ext2(t *testing.T) {
        a, b := optionalStrings("hello", "")
        if a == nil || *a != "hello" {
                t.Error("expected a='hello'")
        }
        if b != nil {
                t.Error("expected nil for empty b")
        }

        a, b = optionalStrings("", "world")
        if a != nil {
                t.Error("expected nil for empty a")
        }
        if b == nil || *b != "world" {
                t.Error("expected b='world'")
        }
}

func TestShouldRecordUserAssociation_AllCombos_Ext2(t *testing.T) {
        tests := []struct {
                auth bool
                uid  int32
                want bool
        }{
                {true, 1, true},
                {true, 100, true},
                {false, 1, false},
                {false, 0, false},
                {true, 0, false},
        }
        for _, tt := range tests {
                if got := shouldRecordUserAssociation(tt.auth, tt.uid); got != tt.want {
                        t.Errorf("shouldRecordUserAssociation(%v, %d) = %v, want %v", tt.auth, tt.uid, got, tt.want)
                }
        }
}

func TestExtractCurrencyFromResults_TypeAssertions_Ext2(t *testing.T) {
        tests := []struct {
                name    string
                input   any
                wantNil bool
        }{
                {"valid map", map[string]interface{}{"currency_report": map[string]interface{}{"score": 85}}, false},
                {"missing key", map[string]interface{}{"other": "data"}, true},
                {"not map", "string value", true},
                {"nil", nil, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := extractCurrencyFromResults(tt.input)
                        if (result == nil) != tt.wantNil {
                                t.Errorf("extractCurrencyFromResults() nil = %v, want nil = %v", result == nil, tt.wantNil)
                        }
                })
        }
}
