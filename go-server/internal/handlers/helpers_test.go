package handlers

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestReportModeTemplate(t *testing.T) {
	tests := []struct {
		mode     string
		expected string
	}{
		{"C", "results_covert.html"},
		{"CZ", "results_covert.html"},
		{"B", "results_executive.html"},
		{"E", "results.html"},
		{"Z", "results.html"},
		{"EC", "results.html"},
		{"", "results.html"},
	}
	for _, tt := range tests {
		t.Run("mode_"+tt.mode, func(t *testing.T) {
			got := reportModeTemplate(tt.mode)
			if got != tt.expected {
				t.Errorf("reportModeTemplate(%q) = %q, want %q", tt.mode, got, tt.expected)
			}
		})
	}
}

func TestIsCovertMode(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
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
		t.Run("mode_"+tt.mode, func(t *testing.T) {
			got := isCovertMode(tt.mode)
			if got != tt.expected {
				t.Errorf("isCovertMode(%q) = %v, want %v", tt.mode, got, tt.expected)
			}
		})
	}
}

func TestShortHash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short string", "abc", "abc"},
		{"exactly 16", "1234567890123456", "1234567890123456"},
		{"longer than 16", "12345678901234567890", "1234567890123456"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shortHash(tt.input)
			if got != tt.expected {
				t.Errorf("shortHash(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		expected string
	}{
		{"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)", "ios"},
		{"iPad", "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)", "ios"},
		{"iPod", "Mozilla/5.0 (iPod touch; CPU iPhone OS 16_0)", "ios"},
		{"Android", "Mozilla/5.0 (Linux; Android 13; Pixel 7)", "android"},
		{"macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"},
		{"Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Linux", "Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"empty", "", "unknown"},
		{"bot", "Googlebot/2.1", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPlatform(tt.ua)
			if got != tt.expected {
				t.Errorf("detectPlatform(%q) = %q, want %q", tt.ua, got, tt.expected)
			}
		})
	}
}

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name         string
		input        *string
		wantCategory string
		wantIcon     string
	}{
		{"nil input", nil, "Unknown Error", "fas fa-question-circle"},
		{"empty string", strPtr(""), "Unknown Error", "fas fa-question-circle"},
		{"timeout", strPtr("connection timed out"), "DNS Resolution Timeout", "fas fa-clock"},
		{"deadline", strPtr("context deadline exceeded"), "DNS Resolution Timeout", "fas fa-clock"},
		{"nxdomain", strPtr("no such host"), "Domain Not Found (NXDOMAIN)", "fas fa-unlink"},
		{"nxdomain upper", strPtr("NXDOMAIN returned"), "Domain Not Found (NXDOMAIN)", "fas fa-unlink"},
		{"connection refused", strPtr("connection refused by server"), "Connection Refused", "fas fa-ban"},
		{"connection reset", strPtr("connection reset by peer"), "Connection Refused", "fas fa-ban"},
		{"servfail", strPtr("SERVFAIL from resolver"), "DNS Server Failure (SERVFAIL)", "fas fa-server"},
		{"network unreachable", strPtr("network is unreachable"), "Network Unreachable", "fas fa-wifi"},
		{"tls error", strPtr("TLS handshake failed"), "TLS/Certificate Error", "fas fa-lock"},
		{"x509 error", strPtr("x509 certificate has expired"), "TLS/Certificate Error", "fas fa-lock"},
		{"refused", strPtr("query refused"), "Query Refused", "fas fa-hand-paper"},
		{"rate limit", strPtr("rate limit exceeded"), "Rate Limited", "fas fa-tachometer-alt"},
		{"throttled", strPtr("request throttled"), "Rate Limited", "fas fa-tachometer-alt"},
		{"invalid", strPtr("invalid domain format"), "Invalid Input", "fas fa-exclamation-triangle"},
		{"malformed", strPtr("malformed DNS response"), "Invalid Input", "fas fa-exclamation-triangle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, icon := sanitizeErrorMessage(tt.input)
			if cat != tt.wantCategory {
				t.Errorf("category = %q, want %q", cat, tt.wantCategory)
			}
			if icon != tt.wantIcon {
				t.Errorf("icon = %q, want %q", icon, tt.wantIcon)
			}
		})
	}

	t.Run("redacts IPs", func(t *testing.T) {
		msg := "failed to connect to 192.168.1.100:53"
		cat, _ := sanitizeErrorMessage(&msg)
		if cat == "" {
			t.Error("expected non-empty category")
		}
	})

	t.Run("truncates long messages", func(t *testing.T) {
		long := ""
		for i := 0; i < 100; i++ {
			long += "abcdefgh"
		}
		cat, _ := sanitizeErrorMessage(&long)
		if len(cat) > 200 {
			t.Errorf("expected truncated message, got len %d", len(cat))
		}
	})
}

func TestFormatDiffValue(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"number", float64(42), "42"},
		{"bool", true, "true"},
		{"map", map[string]interface{}{"a": "b"}, `{"a":"b"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDiffValue(tt.input)
			if got != tt.expected {
				t.Errorf("formatDiffValue(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCsvEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain", "hello", "hello"},
		{"with comma", "hello,world", `"hello,world"`},
		{"with quote", `say "hi"`, `"say ""hi"""`},
		{"with newline", "line1\nline2", "\"line1\nline2\""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csvEscape(tt.input)
			if got != tt.expected {
				t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDerefString(t *testing.T) {
	s := "hello"
	if got := derefString(&s); got != "hello" {
		t.Errorf("derefString(&hello) = %q", got)
	}
	if got := derefString(nil); got != "" {
		t.Errorf("derefString(nil) = %q", got)
	}
}

func TestExtractToolVersion(t *testing.T) {
	tests := []struct {
		name     string
		results  map[string]any
		expected string
	}{
		{"present", map[string]any{"_tool_version": "1.2.3"}, "1.2.3"},
		{"missing", map[string]any{}, ""},
		{"wrong type", map[string]any{"_tool_version": 123}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractToolVersion(tt.results)
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestResultsDomainExists(t *testing.T) {
	tests := []struct {
		name     string
		results  map[string]any
		expected bool
	}{
		{"true", map[string]any{"domain_exists": true}, true},
		{"false", map[string]any{"domain_exists": false}, false},
		{"missing", map[string]any{}, true},
		{"wrong type", map[string]any{"domain_exists": "yes"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resultsDomainExists(tt.results)
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExtractAnalysisError(t *testing.T) {
	t.Run("no error", func(t *testing.T) {
		ok, errMsg := extractAnalysisError(map[string]any{})
		if !ok {
			t.Error("expected ok=true")
		}
		if errMsg != nil {
			t.Error("expected nil error message")
		}
	})

	t.Run("with error", func(t *testing.T) {
		ok, errMsg := extractAnalysisError(map[string]any{"error": "something failed"})
		if ok {
			t.Error("expected ok=false")
		}
		if errMsg == nil || *errMsg != "something failed" {
			t.Errorf("expected error message 'something failed', got %v", errMsg)
		}
	})

	t.Run("empty error string", func(t *testing.T) {
		ok, errMsg := extractAnalysisError(map[string]any{"error": ""})
		if !ok {
			t.Error("expected ok=true for empty error")
		}
		if errMsg != nil {
			t.Error("expected nil for empty error")
		}
	})
}

func TestOptionalStrings(t *testing.T) {
	a, b := optionalStrings("hello", "")
	if a == nil || *a != "hello" {
		t.Errorf("expected 'hello', got %v", a)
	}
	if b != nil {
		t.Errorf("expected nil, got %v", b)
	}

	a, b = optionalStrings("", "world")
	if a != nil {
		t.Errorf("expected nil, got %v", a)
	}
	if b == nil || *b != "world" {
		t.Errorf("expected 'world', got %v", b)
	}
}

func TestFormatTimestamp(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
			Valid: true,
		}
		got := formatTimestamp(ts)
		if got != "15 Feb 2026, 14:30 UTC" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{Valid: false}
		got := formatTimestamp(ts)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestFormatTimestampISO(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
			Valid: true,
		}
		got := formatTimestampISO(ts)
		if got != "2026-02-15T14:30:00Z" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		ts := pgtype.Timestamp{Valid: false}
		got := formatTimestampISO(ts)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestRoadmapDataIntegrity(t *testing.T) {
	h := NewRoadmapHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil RoadmapHandler")
	}
}

func TestRoadmapItemsNonEmpty(t *testing.T) {
	done := []RoadmapItem{
		{Title: "Intelligence Confidence Audit Engine (ICAE)", Version: "129 Test Cases", Date: "Feb 2026", Type: "Feature"},
		{Title: "Intelligence Currency Assurance Engine (ICuAE)", Version: "29 Test Cases", Date: "Feb 2026", Type: "Feature"},
	}

	for i, item := range done {
		if item.Title == "" {
			t.Errorf("done[%d] has empty Title", i)
		}
		if item.Version == "" {
			t.Errorf("done[%d] (%s) has empty Version", i, item.Title)
		}
		if item.Date == "" {
			t.Errorf("done[%d] (%s) has empty Date", i, item.Title)
		}
		if item.Type == "" {
			t.Errorf("done[%d] (%s) has empty Type", i, item.Title)
		}
	}
}

func TestRoadmapConstants(t *testing.T) {
	if roadmapDateFeb2026 != "Feb 2026" {
		t.Errorf("unexpected roadmapDateFeb2026: %q", roadmapDateFeb2026)
	}
	if roadmapVersionV2620 != "v26.20.0+" {
		t.Errorf("unexpected roadmapVersionV2620: %q", roadmapVersionV2620)
	}
	if roadmapTypeFeature != "Feature" {
		t.Errorf("unexpected roadmapTypeFeature: %q", roadmapTypeFeature)
	}
}

func TestBuildDiffItems(t *testing.T) {
	diffs := []SectionDiff{
		{
			Key: "spf", Label: "SPF", Icon: "fa-envelope",
			StatusA: "success", StatusB: "warning", Changed: true,
			DetailChanges: []DetailChange{
				{Field: "Record", Old: "v=spf1 -all", New: "v=spf1 ~all"},
			},
		},
		{
			Key: "dmarc", Label: "DMARC", Icon: "fa-shield",
			StatusA: "success", StatusB: "success", Changed: false,
		},
	}

	items, changes := buildDiffItems(diffs)
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if changes != 1 {
		t.Errorf("expected 1 change, got %d", changes)
	}
	if !items[0].Changed {
		t.Error("expected first item to be changed")
	}
	if items[1].Changed {
		t.Error("expected second item to be unchanged")
	}
	if len(items[0].DetailChanges) != 1 {
		t.Errorf("expected 1 detail change, got %d", len(items[0].DetailChanges))
	}
}

func TestTimeAgo(t *testing.T) {
	tests := []struct {
		name     string
		d        time.Duration
		expected string
	}{
		{"just now", 10 * time.Second, "just now"},
		{"1 minute", 90 * time.Second, "1 minute ago"},
		{"5 minutes", 5 * time.Minute, "5 minutes ago"},
		{"1 hour", 90 * time.Minute, "1 hour ago"},
		{"3 hours", 3 * time.Hour, "3 hours ago"},
		{"1 day", 36 * time.Hour, "1 day ago"},
		{"5 days", 5 * 24 * time.Hour, "5 days ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := timeAgo(time.Now().Add(-tt.d))
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
