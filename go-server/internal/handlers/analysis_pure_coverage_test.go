package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/scanner"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestReportModeTemplate(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"C", "results_covert.html"},
		{"CZ", "results_covert.html"},
		{"B", "results_executive.html"},
		{"E", "results.html"},
		{"Z", "results.html"},
		{"", "results.html"},
		{"X", "results.html"},
	}
	for _, tt := range tests {
		got := reportModeTemplate(tt.mode)
		if got != tt.want {
			t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestIsCovertMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"C", true},
		{"CZ", true},
		{"EC", true},
		{"E", false},
		{"B", false},
		{"Z", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isCovertMode(tt.mode)
		if got != tt.want {
			t.Errorf("isCovertMode(%q) = %v, want %v", tt.mode, got, tt.want)
		}
	}
}

func TestIsAnalysisFailure(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		isFail  bool
		errMsg  string
	}{
		{"success true", map[string]any{"analysis_success": true}, false, ""},
		{"success false with error", map[string]any{"analysis_success": false, "error": "timeout"}, true, "timeout"},
		{"success false no error", map[string]any{"analysis_success": false}, false, ""},
		{"missing success key", map[string]any{}, false, ""},
		{"non-bool success", map[string]any{"analysis_success": "yes"}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isFail, errMsg := isAnalysisFailure(tt.results)
			if isFail != tt.isFail {
				t.Errorf("isAnalysisFailure() isFail = %v, want %v", isFail, tt.isFail)
			}
			if errMsg != tt.errMsg {
				t.Errorf("isAnalysisFailure() errMsg = %q, want %q", errMsg, tt.errMsg)
			}
		})
	}
}

func TestDerefString(t *testing.T) {
	s := "hello"
	if got := derefString(&s); got != "hello" {
		t.Errorf("derefString(&s) = %q, want %q", got, "hello")
	}
	if got := derefString(nil); got != "" {
		t.Errorf("derefString(nil) = %q, want %q", got, "")
	}
}

func TestAnalysisHasProtocol(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		key     string
		want    bool
	}{
		{"success status", map[string]any{"dane_analysis": map[string]any{"status": "success"}}, "dane_analysis", true},
		{"warning status", map[string]any{"dane_analysis": map[string]any{"status": "warning"}}, "dane_analysis", true},
		{"fail status", map[string]any{"dane_analysis": map[string]any{"status": "fail"}}, "dane_analysis", false},
		{"missing section", map[string]any{}, "dane_analysis", false},
		{"wrong type", map[string]any{"dane_analysis": "not a map"}, "dane_analysis", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := analysisHasProtocol(tt.results, tt.key); got != tt.want {
				t.Errorf("analysisHasProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAnalysisError(t *testing.T) {
	tests := []struct {
		name    string
		results map[string]any
		success bool
		hasErr  bool
	}{
		{"no error", map[string]any{}, true, false},
		{"with error", map[string]any{"error": "DNS timeout"}, false, true},
		{"empty error", map[string]any{"error": ""}, true, false},
		{"non-string error", map[string]any{"error": 42}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			success, errPtr := extractAnalysisError(tt.results)
			if success != tt.success {
				t.Errorf("extractAnalysisError() success = %v, want %v", success, tt.success)
			}
			if (errPtr != nil) != tt.hasErr {
				t.Errorf("extractAnalysisError() hasErr = %v, want %v", errPtr != nil, tt.hasErr)
			}
		})
	}
}

func TestOptionalStrings(t *testing.T) {
	a, b := optionalStrings("US", "United States")
	if a == nil || *a != "US" {
		t.Errorf("optionalStrings() a = %v, want 'US'", a)
	}
	if b == nil || *b != "United States" {
		t.Errorf("optionalStrings() b = %v, want 'United States'", b)
	}

	a, b = optionalStrings("", "")
	if a != nil {
		t.Errorf("optionalStrings() a = %v, want nil", a)
	}
	if b != nil {
		t.Errorf("optionalStrings() b = %v, want nil", b)
	}
}

func TestExtractScanFields(t *testing.T) {
	sc := scanner.Classification{IsScan: true, Source: "probe", IP: "1.2.3.4"}
	src, ip := extractScanFields(sc)
	if src == nil || *src != "probe" {
		t.Errorf("extractScanFields() src = %v, want 'probe'", src)
	}
	if ip == nil || *ip != "1.2.3.4" {
		t.Errorf("extractScanFields() ip = %v, want '1.2.3.4'", ip)
	}

	sc2 := scanner.Classification{IsScan: false, Source: "", IP: ""}
	src2, ip2 := extractScanFields(sc2)
	if src2 != nil {
		t.Errorf("extractScanFields() src = %v, want nil", src2)
	}
	if ip2 != nil {
		t.Errorf("extractScanFields() ip = %v, want nil", ip2)
	}
}

func TestGetStringFromResults(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status": "pass",
		},
		"simple_key": "value",
	}

	got := getStringFromResults(results, "spf_analysis", "status")
	if got == nil || *got != "pass" {
		t.Errorf("getStringFromResults() = %v, want 'pass'", got)
	}

	got = getStringFromResults(results, "simple_key", "")
	if got == nil || *got != "value" {
		t.Errorf("getStringFromResults(key='') = %v, want 'value'", got)
	}

	got = getStringFromResults(results, "missing", "status")
	if got != nil {
		t.Errorf("getStringFromResults(missing) = %v, want nil", got)
	}

	got = getStringFromResults(results, "spf_analysis", "missing_key")
	if got != nil {
		t.Errorf("getStringFromResults(missing_key) = %v, want nil", got)
	}

	results2 := map[string]any{"spf_analysis": map[string]any{"status": 42}}
	got = getStringFromResults(results2, "spf_analysis", "status")
	if got != nil {
		t.Errorf("getStringFromResults(int value) = %v, want nil", got)
	}
}

func TestGetJSONFromResults(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{"a": "1.2.3.4"},
		"spf_analysis":  map[string]any{"records": []string{"v=spf1 include:_spf.google.com ~all"}},
	}

	got := getJSONFromResults(results, "basic_records", "")
	if got == nil {
		t.Fatal("getJSONFromResults(basic_records) = nil, want non-nil")
	}

	got = getJSONFromResults(results, "spf_analysis", "records")
	if got == nil {
		t.Fatal("getJSONFromResults(spf_analysis, records) = nil, want non-nil")
	}

	got = getJSONFromResults(results, "missing", "")
	if got != nil {
		t.Errorf("getJSONFromResults(missing) = %v, want nil", got)
	}

	got = getJSONFromResults(results, "spf_analysis", "missing")
	if got != nil {
		t.Errorf("getJSONFromResults(missing key) = %v, want nil", got)
	}
}

func TestProtocolRawConfidence(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   float64
	}{
		{"secure", "secure", 1.0},
		{"pass", "pass", 1.0},
		{"valid", "valid", 1.0},
		{"good", "good", 1.0},
		{"warning", "warning", 0.7},
		{"info", "info", 0.7},
		{"partial", "partial", 0.7},
		{"fail", "fail", 0.3},
		{"danger", "danger", 0.3},
		{"critical", "critical", 0.3},
		{"error", "error", 0.0},
		{"n/a", "n/a", 0.0},
		{"empty", "", 0.0},
		{"unknown", "unknown_status", 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]any{
				"spf_analysis": map[string]any{"status": tt.status},
			}
			got := protocolRawConfidence(results, "spf_analysis")
			if got != tt.want {
				t.Errorf("protocolRawConfidence(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}

	got := protocolRawConfidence(map[string]any{}, "missing")
	if got != 0.0 {
		t.Errorf("protocolRawConfidence(missing) = %v, want 0.0", got)
	}
}

func TestAggregateResolverAgreement(t *testing.T) {
	results := map[string]any{
		"resolver_consensus": map[string]any{
			"per_record_consensus": map[string]any{
				"A": map[string]any{
					"resolver_count": 4,
					"consensus":      true,
				},
				"MX": map[string]any{
					"resolver_count": 4,
					"consensus":      false,
				},
			},
		},
	}
	agree, total := aggregateResolverAgreement(results)
	if agree != 7 || total != 8 {
		t.Errorf("aggregateResolverAgreement() = (%d, %d), want (7, 8)", agree, total)
	}

	agree, total = aggregateResolverAgreement(map[string]any{})
	if agree != 0 || total != 0 {
		t.Errorf("aggregateResolverAgreement(empty) = (%d, %d), want (0, 0)", agree, total)
	}
}

func TestAnalysisTimestamp(t *testing.T) {
	a := dbq.DomainAnalysis{
		CreatedAt: pgtype.Timestamp{Valid: false},
	}
	got := analysisTimestamp(a)
	if got != "N/A" {
		t.Errorf("analysisTimestamp(invalid) = %q, want 'N/A'", got)
	}
}

func TestAnalysisDuration(t *testing.T) {
	dur := 1.5
	a := dbq.DomainAnalysis{AnalysisDuration: &dur}
	got := analysisDuration(a)
	if got != 1.5 {
		t.Errorf("analysisDuration() = %v, want 1.5", got)
	}

	a2 := dbq.DomainAnalysis{AnalysisDuration: nil}
	got2 := analysisDuration(a2)
	if got2 != 0 {
		t.Errorf("analysisDuration(nil) = %v, want 0", got2)
	}
}

func TestLookupCountry_Loopback(t *testing.T) {
	code, name := lookupCountry("")
	if code != "" || name != "" {
		t.Errorf("lookupCountry('') = (%q, %q), want empty", code, name)
	}
	code, name = lookupCountry("127.0.0.1")
	if code != "" || name != "" {
		t.Errorf("lookupCountry(loopback) = (%q, %q), want empty", code, name)
	}
	code, name = lookupCountry("::1")
	if code != "" || name != "" {
		t.Errorf("lookupCountry(::1) = (%q, %q), want empty", code, name)
	}
}

func TestExtractReportsAndDurations_Empty(t *testing.T) {
	reports, durations := extractReportsAndDurations(nil)
	if len(reports) != 0 || len(durations) != 0 {
		t.Errorf("extractReportsAndDurations(nil) = (%d, %d), want (0, 0)", len(reports), len(durations))
	}

	analyses := []dbq.DomainAnalysis{
		{FullResults: nil},
		{FullResults: json.RawMessage(`invalid json`)},
	}
	reports, durations = extractReportsAndDurations(analyses)
	if len(reports) != 0 || len(durations) != 0 {
		t.Errorf("extractReportsAndDurations(bad) = (%d, %d), want (0, 0)", len(reports), len(durations))
	}
}

func TestExtractReportsAndDurations_WithDuration(t *testing.T) {
	dur := 2.5
	analyses := []dbq.DomainAnalysis{
		{
			FullResults:      json.RawMessage(`{"basic_records": {}}`),
			AnalysisDuration: &dur,
		},
	}
	reports, durations := extractReportsAndDurations(analyses)
	if len(reports) != 0 {
		t.Errorf("expected 0 reports, got %d", len(reports))
	}
	if len(durations) != 1 || durations[0] != 2500 {
		t.Errorf("expected [2500], got %v", durations)
	}
}

func TestApplyDevNullHeaders(t *testing.T) {
	w := &mockResponseWriter{headers: make(map[string][]string)}
	c := createTestContext(w)

	applyDevNullHeaders(c, false)
	if w.headers.Get("X-Ephemeral") != "" {
		t.Error("expected no X-Ephemeral header when devNull=false")
	}

	applyDevNullHeaders(c, true)
	if w.headers.Get("X-Ephemeral") != "true" {
		t.Error("expected X-Ephemeral=true when devNull=true")
	}
}

func TestLogEphemeralReason(t *testing.T) {
	logEphemeralReason("test.com", true, true)
	logEphemeralReason("test.com", false, false)
	logEphemeralReason("test.com", true, false)
}
