package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/scanner"
)

func TestExtractScanFields(t *testing.T) {
	t.Run("scan with source and IP", func(t *testing.T) {
		sc := scanner.Classification{IsScan: true, Source: "cisa", IP: "1.2.3.4"}
		src, ip := extractScanFields(sc)
		if src == nil || *src != "cisa" {
			t.Errorf("expected source 'cisa', got %v", src)
		}
		if ip == nil || *ip != "1.2.3.4" {
			t.Errorf("expected ip '1.2.3.4', got %v", ip)
		}
	})

	t.Run("not a scan", func(t *testing.T) {
		sc := scanner.Classification{IsScan: false, Source: "", IP: ""}
		src, ip := extractScanFields(sc)
		if src != nil {
			t.Error("expected nil source for non-scan")
		}
		if ip != nil {
			t.Error("expected nil ip for empty IP")
		}
	})

	t.Run("scan without IP", func(t *testing.T) {
		sc := scanner.Classification{IsScan: true, Source: "qualys", IP: ""}
		src, ip := extractScanFields(sc)
		if src == nil || *src != "qualys" {
			t.Errorf("expected source 'qualys', got %v", src)
		}
		if ip != nil {
			t.Error("expected nil ip for empty IP")
		}
	})
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
		{"other", "something_else", 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]any{
				"test_section": map[string]any{"status": tt.status},
			}
			got := protocolRawConfidence(results, "test_section")
			if got != tt.want {
				t.Errorf("protocolRawConfidence status=%q = %f, want %f", tt.status, got, tt.want)
			}
		})
	}

	t.Run("missing_section", func(t *testing.T) {
		got := protocolRawConfidence(map[string]any{}, "nonexistent")
		if got != 0.0 {
			t.Errorf("expected 0.0 for missing section, got %f", got)
		}
	})

	t.Run("non_map_section", func(t *testing.T) {
		got := protocolRawConfidence(map[string]any{"test": "not a map"}, "test")
		if got != 0.0 {
			t.Errorf("expected 0.0 for non-map section, got %f", got)
		}
	})
}

func TestAggregateResolverAgreement(t *testing.T) {
	t.Run("no consensus data", func(t *testing.T) {
		agree, total := aggregateResolverAgreement(map[string]any{})
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("with consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": map[string]any{
						"resolver_count": 4,
						"consensus":      true,
					},
					"MX": map[string]any{
						"resolver_count": 3,
						"consensus":      false,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if total != 7 {
			t.Errorf("expected total=7, got %d", total)
		}
		if agree != 6 {
			t.Errorf("expected agree=6 (4 all agree + 3-1 disagree), got %d", agree)
		}
	})

	t.Run("zero resolvers no consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": map[string]any{
						"resolver_count": 0,
						"consensus":      false,
					},
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("missing per_record_consensus", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})

	t.Run("non-map record entry", func(t *testing.T) {
		results := map[string]any{
			"resolver_consensus": map[string]any{
				"per_record_consensus": map[string]any{
					"A": "not a map",
				},
			},
		}
		agree, total := aggregateResolverAgreement(results)
		if agree != 0 || total != 0 {
			t.Errorf("expected (0,0), got (%d,%d)", agree, total)
		}
	})
}

func TestGetStringFromResults(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"status": "pass",
			"count":  42,
		},
		"simple_key": "simple_value",
	}

	t.Run("nested key", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "status")
		if got == nil || *got != "pass" {
			t.Errorf("expected 'pass', got %v", got)
		}
	})

	t.Run("nested non-string value", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "count")
		if got != nil {
			t.Errorf("expected nil for non-string value, got %v", *got)
		}
	})

	t.Run("missing section", func(t *testing.T) {
		got := getStringFromResults(results, "nonexistent", "status")
		if got != nil {
			t.Error("expected nil for missing section")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		got := getStringFromResults(results, "spf_analysis", "nonexistent")
		if got != nil {
			t.Error("expected nil for missing key")
		}
	})

	t.Run("top-level string with empty key", func(t *testing.T) {
		got := getStringFromResults(results, "simple_key", "")
		if got == nil || *got != "simple_value" {
			t.Errorf("expected 'simple_value', got %v", got)
		}
	})

	t.Run("top-level non-string with empty key", func(t *testing.T) {
		r := map[string]any{"numbers": 42}
		got := getStringFromResults(r, "numbers", "")
		if got != nil {
			t.Error("expected nil for non-string top-level value")
		}
	})
}

func TestGetJSONFromResults(t *testing.T) {
	results := map[string]any{
		"spf_analysis": map[string]any{
			"records": []string{"v=spf1 include:example.com ~all"},
		},
		"basic_records": map[string]any{
			"A": []string{"1.2.3.4"},
		},
	}

	t.Run("nested key", func(t *testing.T) {
		got := getJSONFromResults(results, "spf_analysis", "records")
		if got == nil {
			t.Fatal("expected non-nil JSON")
		}
		var arr []string
		if err := json.Unmarshal(got, &arr); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if len(arr) != 1 {
			t.Errorf("expected 1 record, got %d", len(arr))
		}
	})

	t.Run("top-level section with empty key", func(t *testing.T) {
		got := getJSONFromResults(results, "basic_records", "")
		if got == nil {
			t.Fatal("expected non-nil JSON")
		}
	})

	t.Run("missing section", func(t *testing.T) {
		got := getJSONFromResults(results, "nonexistent", "key")
		if got != nil {
			t.Error("expected nil for missing section")
		}
	})

	t.Run("nil data value", func(t *testing.T) {
		r := map[string]any{"section": map[string]any{"key": nil}}
		got := getJSONFromResults(r, "section", "key")
		if got != nil {
			t.Error("expected nil for nil data")
		}
	})
}

func TestLookupCountry_LocalIPs(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{""},
		{"127.0.0.1"},
		{"::1"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			code, name := lookupCountry(tt.ip)
			if code != "" || name != "" {
				t.Errorf("expected empty for local IP %q, got (%q, %q)", tt.ip, code, name)
			}
		})
	}
}

func TestProtocolResultKeys(t *testing.T) {
	expectedKeys := []string{"SPF", "DKIM", "DMARC", "DANE", "DNSSEC", "BIMI", "MTA_STS", "TLS_RPT", "CAA"}
	for _, key := range expectedKeys {
		if _, ok := protocolResultKeys[key]; !ok {
			t.Errorf("expected protocolResultKeys to contain %q", key)
		}
	}
}

func TestApplyDevNullHeaders(t *testing.T) {
}

func TestLogEphemeralReason_DoesNotPanic(t *testing.T) {
	logEphemeralReason("example.com", true, true)
	logEphemeralReason("example.com", false, false)
	logEphemeralReason("example.com", false, true)
}
