// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
	"context"
	"errors"
	"testing"
	"time"

	"dnstool/go-server/internal/dbq"
)

// The /confidence Grade Distribution is a published page. Before the 018
// grade-width migration the schema could not record three of the five grades
// (VARCHAR(5)), so the stored distribution was filtered by string length. Once
// 018 lands, an unscoped GROUP BY would silently blend that filtered history
// with honest rows and look plausible. These tests pin the two guards:
// the distribution is scoped to rows at/after the 018 adoption (derived from
// the migration ledger, not a hardcoded date), and when 018 is not yet applied
// the page renders no distribution at all — never an unfiltered one.

type gradeDistFake struct {
	cutoff    time.Time
	cutoffErr error
	dist      []dbq.ICuAEGetGradeDistributionRow
	distErr   error
}

func (f gradeDistFake) ICuAEInsertScanScore(context.Context, dbq.ICuAEInsertScanScoreParams) (dbq.ICuAEInsertScanScoreRow, error) {
	return dbq.ICuAEInsertScanScoreRow{}, nil
}
func (f gradeDistFake) ICuAEInsertDimensionScore(context.Context, dbq.ICuAEInsertDimensionScoreParams) error {
	return nil
}
func (f gradeDistFake) ICuAEGetAggregateStats(context.Context) (dbq.ICuAEGetAggregateStatsRow, error) {
	return dbq.ICuAEGetAggregateStatsRow{}, nil
}
func (f gradeDistFake) ICuAEGetGradeDistribution(context.Context) ([]dbq.ICuAEGetGradeDistributionRow, error) {
	return f.dist, f.distErr
}
func (f gradeDistFake) ICuAEGetGradeDistributionCutoff(context.Context) (time.Time, error) {
	return f.cutoff, f.cutoffErr
}
func (f gradeDistFake) ICuAEGetDimensionAverages(context.Context) ([]dbq.ICuAEGetDimensionAveragesRow, error) {
	return nil, nil
}
func (f gradeDistFake) ICuAEGetRecentTrend(context.Context, int32) ([]dbq.ICuAEGetRecentTrendRow, error) {
	return nil, nil
}

func TestLoadGradeDistributionScopesToLedgerCutoff(t *testing.T) {
	adopted := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fake := gradeDistFake{
		cutoff: adopted,
		dist: []dbq.ICuAEGetGradeDistributionRow{
			{Grade: "excellent", Count: 3},
			{Grade: "good", Count: 7},
		},
	}
	items, cutoff, applied := loadGradeDistribution(context.Background(), fake)
	if !applied {
		t.Fatal("applied = false, want true when 018 is applied")
	}
	if cutoff != "2026-08-01" {
		t.Errorf("cutoff = %q, want 2026-08-01 (rendered from the ledger, not prose)", cutoff)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	// excellent now representable post-018 and present in the scoped distribution.
	var sawExcellent bool
	for _, it := range items {
		if it.Grade == "excellent" {
			sawExcellent = true
			if it.PctDisplay != "30" {
				t.Errorf("excellent pct = %q, want 30 (3 of 10)", it.PctDisplay)
			}
		}
	}
	if !sawExcellent {
		t.Error("scoped distribution must include excellent (the grade VARCHAR(5) could not hold)")
	}
}

func TestLoadGradeDistributionRendersNothingWhen018NotApplied(t *testing.T) {
	fake := gradeDistFake{
		cutoffErr: errors.New("no rows in result set"), // pgx.ErrNoRows shape
		dist: []dbq.ICuAEGetGradeDistributionRow{
			{Grade: "good", Count: 16},
			{Grade: "stale", Count: 1},
		},
	}
	items, cutoff, applied := loadGradeDistribution(context.Background(), fake)
	if applied {
		t.Error("applied = true, want false when 018 is not yet applied")
	}
	if cutoff != "" {
		t.Errorf("cutoff = %q, want empty (no date to render)", cutoff)
	}
	if items != nil {
		t.Errorf("items = %v, want nil — page must render NO distribution, not an unfiltered one", items)
	}
}
