// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
	"testing"
)

func TestGenerateSuggestedConfig_InsufficientData(t *testing.T) {
	stats := RollingStats{ScanCount: 2}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	if config.HasSuggestions() {
		t.Error("expected no suggestions with < 3 scans")
	}
	if config.Confidence != "low" {
		t.Errorf("expected 'low' confidence, got %q", config.Confidence)
	}
}

func TestGenerateSuggestedConfig_HealthyDomain(t *testing.T) {
	stats := RollingStats{
		ScanCount:            5,
		AvgResolverAgreement: 95,
		TTLDeviations:        map[string]float64{},
		RecordTypeErrors:     map[string]int{},
		AvgScanDuration:      8000,
	}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	if config.HasSuggestions() {
		t.Errorf("expected no suggestions for healthy domain, got %d", len(config.Suggestions))
	}
	if config.Confidence != "medium" {
		t.Errorf("expected 'medium' confidence with 5 scans, got %q", config.Confidence)
	}
}

func TestGenerateSuggestedConfig_HighConfidence(t *testing.T) {
	stats := RollingStats{
		ScanCount:            15,
		AvgResolverAgreement: 95,
		AvgScanDuration:      8000,
	}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	if config.Confidence != "high" {
		t.Errorf("expected 'high' confidence with 15 scans, got %q", config.Confidence)
	}
}

func TestGenerateSuggestedConfig_LowResolverAgreement(t *testing.T) {
	stats := RollingStats{
		ScanCount:            5,
		AvgResolverAgreement: 55,
		AvgScanDuration:      8000,
	}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	if !config.HasSuggestions() {
		t.Fatal("expected resolver suggestions for 55% agreement")
	}
	found := false
	for _, s := range config.Suggestions {
		if s.Category == "resolver" {
			found = true
			if s.Severity != "medium" {
				t.Errorf("expected 'medium' severity for 55%% agreement, got %q", s.Severity)
			}
		}
	}
	if !found {
		t.Error("expected resolver suggestion not found")
	}
}

func TestGenerateSuggestedConfig_VeryLowResolverAgreement(t *testing.T) {
	stats := RollingStats{
		ScanCount:            5,
		AvgResolverAgreement: 40,
		AvgScanDuration:      8000,
	}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	found := false
	for _, s := range config.Suggestions {
		if s.Category == "resolver" && s.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Error("expected high-severity resolver suggestion for 40% agreement")
	}
}

func TestGenerateSuggestedConfig_SlowScans(t *testing.T) {
	stats := RollingStats{
		ScanCount:            5,
		AvgResolverAgreement: 90,
		AvgScanDuration:      35000,
	}
	config := GenerateSuggestedConfig(stats, DefaultProfile)
	found := false
	for _, s := range config.Suggestions {
		if s.Category == "timeout" {
			found = true
		}
	}
	if !found {
		t.Error("expected timeout suggestion for 35s avg scan duration")
	}
}

func TestBuildRollingStats_Empty(t *testing.T) {
	stats := BuildRollingStats(nil, nil)
	if stats.ScanCount != 0 {
		t.Errorf("expected 0 scans, got %d", stats.ScanCount)
	}
}

func TestBuildRollingStats_WithReports(t *testing.T) {
	reports := []CurrencyReport{
		{
			Dimensions: []DimensionScore{
				{Dimension: DimensionSourceCredibility, Score: 90},
				{Dimension: DimensionTTLRelevance, Score: 50, Findings: []TTLFinding{
					{RecordType: "MX", Ratio: 0.083},
				}},
			},
		},
		{
			Dimensions: []DimensionScore{
				{Dimension: DimensionSourceCredibility, Score: 80},
				{Dimension: DimensionTTLRelevance, Score: 60},
			},
		},
	}
	durations := []float64{5000, 7000}
	stats := BuildRollingStats(reports, durations)

	if stats.ScanCount != 2 {
		t.Errorf("expected 2 scans, got %d", stats.ScanCount)
	}
	if stats.AvgResolverAgreement != 85 {
		t.Errorf("expected 85%% avg agreement, got %.1f", stats.AvgResolverAgreement)
	}
	if stats.AvgScanDuration != 6000 {
		t.Errorf("expected 6000ms avg duration, got %.1f", stats.AvgScanDuration)
	}
	if _, ok := stats.TTLDeviations["MX"]; !ok {
		t.Error("expected MX TTL deviation tracked")
	}
}

func TestProfileSuggestion_SeverityClass(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"high", "danger"},
		{"medium", "warning"},
		{"low", "info"},
	}
	for _, tt := range tests {
		s := ProfileSuggestion{Severity: tt.severity}
		if got := s.SeverityClass(); got != tt.want {
			t.Errorf("SeverityClass(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestProfileSuggestion_CategoryIcon(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{"resolver", "fa-server"},
		{"retry", "fa-redo"},
		{"timeout", "fa-clock"},
		{"priority", "fa-sort-amount-down"},
		{"unknown", "fa-cog"},
	}
	for _, tt := range tests {
		s := ProfileSuggestion{Category: tt.category}
		if got := s.CategoryIcon(); got != tt.want {
			t.Errorf("CategoryIcon(%q) = %q, want %q", tt.category, got, tt.want)
		}
	}
}

func TestSuggestedConfig_ConfidenceClass(t *testing.T) {
	tests := []struct {
		conf string
		want string
	}{
		{"high", "success"},
		{"medium", "info"},
		{"low", "secondary"},
	}
	for _, tt := range tests {
		sc := SuggestedConfig{Confidence: tt.conf}
		if got := sc.ConfidenceClass(); got != tt.want {
			t.Errorf("ConfidenceClass(%q) = %q, want %q", tt.conf, got, tt.want)
		}
	}
}

func TestBuildPriorityOrder(t *testing.T) {
	stats := RollingStats{
		RecordTypeErrors: map[string]int{
			"TLSA": 5,
			"A":    0,
			"MX":   1,
		},
	}
	order := buildPriorityOrder(stats)
	if len(order) == 0 {
		t.Fatal("expected non-empty priority order")
	}
	if order[0] == "TLSA" {
		t.Error("TLSA should not be first (highest errors)")
	}
}
