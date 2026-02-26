package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestBuildCompareAnalysis(t *testing.T) {
	t.Run("full data", func(t *testing.T) {
		dur := 1.234
		ts := pgtype.Timestamp{
			Time:  time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC),
			Valid: true,
		}
		fullResults, _ := json.Marshal(map[string]interface{}{
			"_tool_version": "26.20.88",
		})
		a := dbq.DomainAnalysis{
			CreatedAt:        ts,
			AnalysisDuration: &dur,
			FullResults:      fullResults,
		}

		ca := buildCompareAnalysis(a)
		if ca.CreatedAt != "2026-02-15 14:30:00 UTC" {
			t.Errorf("unexpected CreatedAt: %q", ca.CreatedAt)
		}
		if ca.ToolVersion != "26.20.88" {
			t.Errorf("unexpected ToolVersion: %q", ca.ToolVersion)
		}
		if !ca.HasToolVersion {
			t.Error("expected HasToolVersion=true")
		}
		if ca.AnalysisDuration != "1.2s" {
			t.Errorf("unexpected AnalysisDuration: %q", ca.AnalysisDuration)
		}
		if !ca.HasDuration {
			t.Error("expected HasDuration=true")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		a := dbq.DomainAnalysis{}
		ca := buildCompareAnalysis(a)
		if ca.CreatedAt != "" {
			t.Errorf("expected empty CreatedAt, got %q", ca.CreatedAt)
		}
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false")
		}
		if ca.HasDuration {
			t.Error("expected HasDuration=false")
		}
	})

	t.Run("no tool version in results", func(t *testing.T) {
		fullResults, _ := json.Marshal(map[string]interface{}{
			"some_key": "some_value",
		})
		a := dbq.DomainAnalysis{FullResults: fullResults}
		ca := buildCompareAnalysis(a)
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false when no _tool_version")
		}
	})

	t.Run("invalid JSON results", func(t *testing.T) {
		a := dbq.DomainAnalysis{FullResults: []byte("not json")}
		ca := buildCompareAnalysis(a)
		if ca.HasToolVersion {
			t.Error("expected HasToolVersion=false for invalid JSON")
		}
	})
}

func TestBuildSelectAnalysisItem(t *testing.T) {
	spf := "success"
	dmarc := "warning"
	dkim := "unknown"
	dur := 2.5
	ts := pgtype.Timestamp{
		Time:  time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC),
		Valid: true,
	}
	fullResults, _ := json.Marshal(map[string]interface{}{
		"_tool_version": "26.14.0",
	})

	a := dbq.DomainAnalysis{
		ID:               42,
		Domain:           "example.com",
		AsciiDomain:      "example.com",
		SpfStatus:        &spf,
		DmarcStatus:      &dmarc,
		DkimStatus:       &dkim,
		AnalysisDuration: &dur,
		CreatedAt:        ts,
		FullResults:      fullResults,
	}

	item := buildSelectAnalysisItem(a)

	if item.ID != 42 {
		t.Errorf("expected ID=42, got %d", item.ID)
	}
	if item.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %q", item.Domain)
	}
	if item.SpfStatus != "success" {
		t.Errorf("expected SpfStatus=success, got %q", item.SpfStatus)
	}
	if item.DmarcStatus != "warning" {
		t.Errorf("expected DmarcStatus=warning, got %q", item.DmarcStatus)
	}
	if item.DkimStatus != "unknown" {
		t.Errorf("expected DkimStatus=unknown, got %q", item.DkimStatus)
	}
	if item.AnalysisDuration != 2.5 {
		t.Errorf("expected AnalysisDuration=2.5, got %f", item.AnalysisDuration)
	}
	if item.CreatedAt != "2026-01-10 08:00:00 UTC" {
		t.Errorf("unexpected CreatedAt: %q", item.CreatedAt)
	}
	if item.ToolVersion != "26.14.0" {
		t.Errorf("expected ToolVersion=26.14.0, got %q", item.ToolVersion)
	}
}

func TestBuildSelectAnalysisItemNilFields(t *testing.T) {
	a := dbq.DomainAnalysis{
		ID:     1,
		Domain: "test.com",
	}

	item := buildSelectAnalysisItem(a)

	if item.SpfStatus != "" {
		t.Errorf("expected empty SpfStatus, got %q", item.SpfStatus)
	}
	if item.DmarcStatus != "" {
		t.Errorf("expected empty DmarcStatus, got %q", item.DmarcStatus)
	}
	if item.DkimStatus != "" {
		t.Errorf("expected empty DkimStatus, got %q", item.DkimStatus)
	}
	if item.AnalysisDuration != 0.0 {
		t.Errorf("expected AnalysisDuration=0, got %f", item.AnalysisDuration)
	}
	if item.CreatedAt != "" {
		t.Errorf("expected empty CreatedAt, got %q", item.CreatedAt)
	}
	if item.ToolVersion != "" {
		t.Errorf("expected empty ToolVersion, got %q", item.ToolVersion)
	}
}

func TestCompareConstants(t *testing.T) {
	if templateCompare != "compare.html" {
		t.Errorf("unexpected templateCompare: %q", templateCompare)
	}
	if templateCompareSelect != "compare_select.html" {
		t.Errorf("unexpected templateCompareSelect: %q", templateCompareSelect)
	}
}
