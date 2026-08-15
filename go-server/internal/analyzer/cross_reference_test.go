// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"testing"
)

func TestNormalizeRecordData(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		rtype  string
		expect string
	}{
		{"trailing dot A", "93.184.216.34.", "A", "93.184.216.34"},
		{"no trailing dot", "93.184.216.34", "A", "93.184.216.34"},
		{"MX with trailing dot", "10 mail.example.com.", "MX", "10 mail.example.com"},
		{"TXT quoted", "\"v=spf1 include:_spf.google.com ~all\"", "TXT", "v=spf1 include:_spf.google.com ~all"},
		{"TXT unquoted", "v=spf1 -all", "TXT", "v=spf1 -all"},
		{"CNAME trailing dot", "www.example.com.", "CNAME", "www.example.com"},
		{"NS trailing dot", "ns1.example.com.", "NS", "ns1.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeRecordData(tc.data, tc.rtype)
			if got != tc.expect {
				t.Errorf("normalizeRecordData(%q, %q) = %q, want %q", tc.data, tc.rtype, got, tc.expect)
			}
		})
	}
}

func TestSetsEqual(t *testing.T) {
	tests := []struct {
		name   string
		a, b   []string
		expect bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different order", []string{"b", "a"}, []string{"a", "b"}, false},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different content", []string{"a"}, []string{"b"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := setsEqual(tc.a, tc.b)
			if got != tc.expect {
				t.Errorf("setsEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.expect)
			}
		})
	}
}

func TestSetsOverlap(t *testing.T) {
	tests := []struct {
		name   string
		a, b   []string
		expect bool
	}{
		{"no overlap", []string{"a"}, []string{"b"}, false},
		{"overlap", []string{"a", "b"}, []string{"b", "c"}, true},
		{"both empty", []string{}, []string{}, false},
		{"one empty", []string{"a"}, []string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := setsOverlap(tc.a, tc.b)
			if got != tc.expect {
				t.Errorf("setsOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.expect)
			}
		})
	}
}

func TestCompareRecordSets(t *testing.T) {
	tests := []struct {
		name        string
		ours        []string
		theirs      []string
		rtype       string
		theirFailed bool
		expect      string
	}{
		{"both empty absent", []string{}, []string{}, "A", false, "absent"},
		{"identical records", []string{"1.2.3.4"}, []string{"1.2.3.4"}, "A", false, "match"},
		{"case insensitive match", []string{"NS1.EXAMPLE.COM"}, []string{"ns1.example.com"}, "NS", false, "match"},
		{"partial overlap", []string{"1.2.3.4", "5.6.7.8"}, []string{"1.2.3.4", "9.10.11.12"}, "A", false, "partial"},
		{"no overlap mismatch", []string{"1.2.3.4"}, []string{"5.6.7.8"}, "A", false, "mismatch"},
		{"one empty one present mismatch", []string{"1.2.3.4"}, []string{}, "A", false, "mismatch"},
		{"failed lookup unavailable", []string{"1.2.3.4"}, []string{}, "A", true, "unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compareRecordSets(tc.ours, tc.theirs, tc.rtype, tc.theirFailed)
			if got != tc.expect {
				t.Errorf("compareRecordSets() = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestAnyToStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		expect int
	}{
		{"nil", nil, 0},
		{"string slice", []string{"a", "b"}, 2},
		{"any slice", []any{"a", "b", "c"}, 3},
		{"empty any slice", []any{}, 0},
		{"non-string any", []any{1, 2}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := anyToStringSlice(tc.input)
			if len(got) != tc.expect {
				t.Errorf("anyToStringSlice() returned %d items, want %d", len(got), tc.expect)
			}
		})
	}
}

func TestComputeSummary(t *testing.T) {
	result := &CrossRefResult{
		Comparisons: map[string][]CrossRefComparison{
			"google": {
				{Match: "match"},
				{Match: "match"},
				{Match: "mismatch"},
				{Match: "absent"},
			},
			"cloudflare": {
				{Match: "match"},
				{Match: "partial"},
				{Match: "unavailable"},
				{Match: "absent"},
			},
		},
	}

	computeSummary(result)

	if result.Summary.TotalChecks != 8 {
		t.Errorf("TotalChecks = %d, want 8", result.Summary.TotalChecks)
	}
	if result.Summary.Matched != 3 {
		t.Errorf("Matched = %d, want 3 (partial must NOT count as matched)", result.Summary.Matched)
	}
	if result.Summary.Absent != 2 {
		t.Errorf("Absent = %d, want 2", result.Summary.Absent)
	}
	if result.Summary.Partial != 1 {
		t.Errorf("Partial = %d, want 1", result.Summary.Partial)
	}
	if result.Summary.Mismatched != 1 {
		t.Errorf("Mismatched = %d, want 1", result.Summary.Mismatched)
	}
	if result.Summary.Unavailable != 1 {
		t.Errorf("Unavailable = %d, want 1", result.Summary.Unavailable)
	}
	if result.Summary.Verdict != "discrepancy_detected" {
		t.Errorf("Verdict = %q, want discrepancy_detected", result.Summary.Verdict)
	}
}

func TestComputeSummary_AllMatch(t *testing.T) {
	result := &CrossRefResult{
		Comparisons: map[string][]CrossRefComparison{
			"google": {
				{Match: "match"},
				{Match: "match"},
			},
		},
	}

	computeSummary(result)

	if result.Summary.Verdict != "corroborated" {
		t.Errorf("Verdict = %q, want corroborated", result.Summary.Verdict)
	}
}

func TestBuildManualVerifyLinks(t *testing.T) {
	links := buildManualVerifyLinks("example.com")

	if len(links) != 6 {
		t.Errorf("expected 6 manual verify links, got %d", len(links))
	}

	if links["google_dig_a"] != "https://toolbox.googleapps.com/apps/dig/#A/example.com" {
		t.Errorf("unexpected google_dig_a link: %s", links["google_dig_a"])
	}

	if links["google_doh"] != "https://dns.google/resolve?name=example.com&type=A" {
		t.Errorf("unexpected google_doh link: %s", links["google_doh"])
	}
}

func TestExtractAnswers(t *testing.T) {
	doh := dohResponse{
		Answer: []dohAnswer{
			{Name: "example.com.", Type: 1, Data: "93.184.216.34"},
			{Name: "example.com.", Type: 1, Data: "93.184.216.35"},
			{Name: "example.com.", Type: 28, Data: "2606:2800:220:1:248:1893:25c8:1946"},
		},
	}

	aRecords := extractAnswers(doh, 1, "A")
	if len(aRecords) != 2 {
		t.Errorf("expected 2 A records, got %d", len(aRecords))
	}

	aaaaRecords := extractAnswers(doh, 28, "AAAA")
	if len(aaaaRecords) != 1 {
		t.Errorf("expected 1 AAAA record, got %d", len(aaaaRecords))
	}

	mxRecords := extractAnswers(doh, 15, "MX")
	if len(mxRecords) != 0 {
		t.Errorf("expected 0 MX records, got %d", len(mxRecords))
	}
}

func TestCrossRefToMap(t *testing.T) {
	result := &CrossRefResult{
		SchemaVersion: "1.0",
		Domain:        "example.com",
		RecordTypes:   []string{"A"},
		Providers:     map[string]*CrossRefProvider{},
		Comparisons:   map[string][]CrossRefComparison{},
		Summary:       CrossRefSummary{Verdict: "corroborated"},
		ManualVerify:  map[string]string{"test": "url"},
	}

	m := crossRefToMap(result)
	if m["schema_version"] != "1.0" {
		t.Errorf("schema_version = %v, want 1.0", m["schema_version"])
	}
	if m["domain"] != "example.com" {
		t.Errorf("domain = %v, want example.com", m["domain"])
	}
}
