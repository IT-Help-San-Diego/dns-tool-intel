package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/analyzer"
)

func TestIsAnalysisFailure_SuccessExt(t *testing.T) {
	results := map[string]any{"analysis_success": true}
	failed, msg := isAnalysisFailure(results)
	if failed {
		t.Error("expected not failed for success")
	}
	if msg != "" {
		t.Errorf("expected empty msg, got %s", msg)
	}
}

func TestIsAnalysisFailure_FailedExt(t *testing.T) {
	results := map[string]any{"analysis_success": false, "error": "timeout"}
	failed, msg := isAnalysisFailure(results)
	if !failed {
		t.Error("expected failed")
	}
	if msg != "timeout" {
		t.Errorf("expected 'timeout', got %s", msg)
	}
}

func TestIsAnalysisFailure_NoErrorKey(t *testing.T) {
	results := map[string]any{"analysis_success": false}
	failed, _ := isAnalysisFailure(results)
	if failed {
		t.Error("expected not failed when no error key")
	}
}

func TestIsAnalysisFailure_NotBoolType(t *testing.T) {
	results := map[string]any{"analysis_success": "true"}
	failed, _ := isAnalysisFailure(results)
	if failed {
		t.Error("expected not failed when analysis_success is string")
	}
}

func TestComputeDriftSeverity_CriticalExt(t *testing.T) {
	fields := []analyzer.PostureDiffField{
		{Severity: "info"},
		{Severity: "critical"},
		{Severity: "warning"},
	}
	if s := computeDriftSeverity(fields); s != "critical" {
		t.Errorf("expected critical, got %s", s)
	}
}

func TestComputeDriftSeverity_WarningExt(t *testing.T) {
	fields := []analyzer.PostureDiffField{
		{Severity: "info"},
		{Severity: "warning"},
	}
	if s := computeDriftSeverity(fields); s != "warning" {
		t.Errorf("expected warning, got %s", s)
	}
}

func TestComputeDriftSeverity_InfoOnly(t *testing.T) {
	fields := []analyzer.PostureDiffField{
		{Severity: "info"},
	}
	if s := computeDriftSeverity(fields); s != "info" {
		t.Errorf("expected info, got %s", s)
	}
}

func TestComputeDriftSeverity_NilFields(t *testing.T) {
	if s := computeDriftSeverity(nil); s != "info" {
		t.Errorf("expected info for nil, got %s", s)
	}
}

func TestShouldPersistResult_NonExistentDomain(t *testing.T) {
	persist, reason := shouldPersistResult(false, false, false, true)
	if persist {
		t.Error("expected no persist for nonexistent domain")
	}
	if reason != "nonexistent_domain" {
		t.Errorf("expected reason=nonexistent_domain, got %s", reason)
	}
}

func TestShouldPersistResult_NormalSuccess(t *testing.T) {
	persist, reason := shouldPersistResult(false, false, true, true)
	if !persist {
		t.Error("expected persist")
	}
	if reason != "" {
		t.Errorf("expected empty reason, got %s", reason)
	}
}

func TestShouldRunICAE_Ext(t *testing.T) {
	tests := []struct {
		name         string
		ephemeral    bool
		domainExists bool
		want         bool
	}{
		{"normal", false, true, true},
		{"ephemeral", true, true, false},
		{"no domain", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRunICAE(tt.ephemeral, tt.domainExists); got != tt.want {
				t.Errorf("shouldRunICAE(%v, %v) = %v, want %v", tt.ephemeral, tt.domainExists, got, tt.want)
			}
		})
	}
}

func TestShouldRecordUserAssociation_Ext(t *testing.T) {
	tests := []struct {
		name string
		auth bool
		uid  int32
		want bool
	}{
		{"authenticated", true, 1, true},
		{"not authenticated", false, 1, false},
		{"zero uid", true, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRecordUserAssociation(tt.auth, tt.uid); got != tt.want {
				t.Errorf("shouldRecordUserAssociation(%v, %d) = %v, want %v", tt.auth, tt.uid, got, tt.want)
			}
		})
	}
}

func TestResultsDomainExists_Ext(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    bool
	}{
		{"exists true", map[string]any{"domain_exists": true}, true},
		{"exists false", map[string]any{"domain_exists": false}, false},
		{"no key", map[string]any{}, true},
		{"wrong type", map[string]any{"domain_exists": "yes"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resultsDomainExists(tt.results); got != tt.want {
				t.Errorf("resultsDomainExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCsvEscape_Ext(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"=cmd", "'=cmd"},
		{"+cmd", "'+cmd"},
		{"-cmd", "'-cmd"},
		{"@cmd", "'@cmd"},
		{"has,comma", "\"has,comma\""},
		{"has\"quote", "\"has\"\"quote\""},
		{"has\nnewline", "\"has\nnewline\""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := csvEscape(tt.input); got != tt.want {
				t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractCurrencyFromResults_ValidExt(t *testing.T) {
	full := map[string]interface{}{
		"currency_report": map[string]interface{}{"score": 85},
	}
	result := extractCurrencyFromResults(full)
	if result == nil {
		t.Error("expected currency report")
	}
}

func TestExtractCurrencyFromResults_MissingExt(t *testing.T) {
	full := map[string]interface{}{"other": "data"}
	result := extractCurrencyFromResults(full)
	if result != nil {
		t.Error("expected nil for missing currency_report")
	}
}

func TestExtractCurrencyFromResults_NotMapExt(t *testing.T) {
	result := extractCurrencyFromResults("not a map")
	if result != nil {
		t.Error("expected nil for non-map")
	}
}

func TestUnmarshalRawJSON_ValidExt(t *testing.T) {
	raw := json.RawMessage(`{"key":"value"}`)
	result := unmarshalRawJSON(raw, "test.com", "test")
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestUnmarshalRawJSON_EmptyExt(t *testing.T) {
	result := unmarshalRawJSON(nil, "test.com", "test")
	if result != nil {
		t.Error("expected nil for empty raw")
	}
}

func TestUnmarshalRawJSON_InvalidExt(t *testing.T) {
	raw := json.RawMessage(`not json`)
	result := unmarshalRawJSON(raw, "test.com", "test")
	if result != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestExtractToolVersion_Ext(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		want    string
	}{
		{"present", map[string]any{"tool_version": "1.0.0"}, "1.0.0"},
		{"missing", map[string]any{}, ""},
		{"wrong type", map[string]any{"tool_version": 123}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractToolVersion(tt.results); got != tt.want {
				t.Errorf("extractToolVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractAnalysisError_Ext(t *testing.T) {
	tests := []struct {
		name      string
		results   map[string]any
		wantError bool
	}{
		{"no error", map[string]any{}, false},
		{"has error", map[string]any{"error": "something failed"}, true},
		{"wrong type", map[string]any{"error": 123}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasErr, _ := extractAnalysisError(tt.results)
			if hasErr != tt.wantError {
				t.Errorf("extractAnalysisError() hasErr = %v, want %v", hasErr, tt.wantError)
			}
		})
	}
}

func TestOptionalStrings_Ext(t *testing.T) {
	a, b := optionalStrings("hello", "world")
	if a == nil || *a != "hello" {
		t.Error("expected a='hello'")
	}
	if b == nil || *b != "world" {
		t.Error("expected b='world'")
	}

	a, b = optionalStrings("", "")
	if a != nil {
		t.Error("expected nil for empty a")
	}
	if b != nil {
		t.Error("expected nil for empty b")
	}
}

func TestMarshalOrderedJSON_Ext(t *testing.T) {
	entries := []orderedKV{
		{Key: "a", Value: 1},
		{Key: "b", Value: "hello"},
	}
	result := marshalOrderedJSON(entries)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	var m map[string]interface{}
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}

func TestProtocolRawConfidence_Ext(t *testing.T) {
	results := map[string]any{
		"spf": map[string]any{
			"status":     "pass",
			"confidence": 0.95,
		},
	}
	conf := protocolRawConfidence(results, "spf")
	if conf != 0.95 {
		t.Errorf("expected 0.95, got %f", conf)
	}

	conf = protocolRawConfidence(results, "missing")
	if conf != 0.0 {
		t.Errorf("expected 0.0 for missing, got %f", conf)
	}
}

func TestEnrichCurrencyReport_Ext(t *testing.T) {
	data := make(map[string]any)
	results := map[string]any{
		"currency_report": map[string]any{
			"score": 85,
		},
	}
	enrichCurrencyReport(data, results)
	if data["CurrencyReport"] == nil {
		t.Error("expected CurrencyReport to be set")
	}
}

func TestEnrichCurrencyReport_NoCurrency(t *testing.T) {
	data := make(map[string]any)
	results := map[string]any{}
	enrichCurrencyReport(data, results)
	if _, ok := data["CurrencyReport"]; ok {
		t.Error("expected no CurrencyReport for empty results")
	}
}
