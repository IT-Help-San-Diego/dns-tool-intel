// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae

import (
	"context"
	"fmt"
	"log/slog"
	"math"

	"dnstool/go-server/internal/dbq"
)

type DBTX interface {
	ICuAEInsertScanScore(ctx context.Context, arg dbq.ICuAEInsertScanScoreParams) (dbq.ICuAEInsertScanScoreRow, error)
	ICuAEInsertDimensionScore(ctx context.Context, arg dbq.ICuAEInsertDimensionScoreParams) error
	ICuAEGetAggregateStats(ctx context.Context) (dbq.ICuAEGetAggregateStatsRow, error)
	ICuAEGetGradeDistribution(ctx context.Context) ([]dbq.ICuAEGetGradeDistributionRow, error)
	ICuAEGetDimensionAverages(ctx context.Context) ([]dbq.ICuAEGetDimensionAveragesRow, error)
	ICuAEGetRecentTrend(ctx context.Context, limit int32) ([]dbq.ICuAEGetRecentTrendRow, error)
}

func RecordScanResult(ctx context.Context, queries DBTX, domain string, report CurrencyReport, appVersion string) {
	domainPtr := &domain
	versionPtr := &appVersion

	row, err := queries.ICuAEInsertScanScore(ctx, dbq.ICuAEInsertScanScoreParams{
		Domain:        domainPtr,
		OverallScore:  float32(report.OverallScore),
		OverallGrade:  report.OverallGrade,
		ResolverCount: int32(report.ResolverCount),
		RecordCount:   int32(report.RecordCount),
		AppVersion:    versionPtr,
	})
	if err != nil {
		slog.Warn("ICuAE: failed to record scan score", "domain", domain, "error", err)
		return
	}

	for _, dim := range report.Dimensions {
		if err := queries.ICuAEInsertDimensionScore(ctx, dbq.ICuAEInsertDimensionScoreParams{
			ScanID:               row.ID,
			Dimension:            dim.Dimension,
			Score:                float32(dim.Score),
			Grade:                dim.Grade,
			RecordTypesEvaluated: int32(dim.RecordTypes),
		}); err != nil {
			slog.Warn("ICuAE: failed to record dimension score", "dimension", dim.Dimension, "error", err)
		}
	}
}

type RuntimeMetrics struct {
	TotalScans      int
	AvgScore        float64
	AvgScoreDisplay string
	StddevScore     float64
	StabilityGrade  string
	StabilityLabel  string
	LastEvaluatedAt string
	TrendDirection  string
	TrendArrow      string
	GradeDist       []GradeDistItem
	DimensionStats  []DimensionStat
	HasData         bool
}

type GradeDistItem struct {
	Grade      string
	Display    string
	Count      int
	Pct        float64
	PctDisplay string
	BootClass  string
}

type DimensionStat struct {
	Dimension   string
	Display     string
	Standard    string
	AvgScore    float64
	AvgDisplay  string
	Stddev      float64
	Grade       string
	BootClass   string
	SampleCount int
}

func LoadRuntimeMetrics(ctx context.Context, queries DBTX) *RuntimeMetrics {
	stats, err := queries.ICuAEGetAggregateStats(ctx)
	if err != nil {
		slog.Warn("ICuAE: failed to load aggregate stats", "error", err)
		return nil
	}

	if stats.TotalScans == 0 {
		return &RuntimeMetrics{HasData: false}
	}

	m := &RuntimeMetrics{
		TotalScans:      int(stats.TotalScans),
		AvgScore:        float64(stats.AvgScore),
		AvgScoreDisplay: fmt.Sprintf("%.1f", stats.AvgScore),
		StddevScore:     float64(stats.StddevScore),
		HasData:         true,
	}

	if stats.LastEvaluatedAt.Valid {
		m.LastEvaluatedAt = stats.LastEvaluatedAt.Time.Format("2006-01-02 15:04 UTC")
	}

	m.StabilityGrade, m.StabilityLabel = computeStability(float64(stats.StddevScore))

	gradeDist, err := queries.ICuAEGetGradeDistribution(ctx)
	if err == nil {
		total := 0
		for _, g := range gradeDist {
			total += int(g.Count)
		}
		for _, g := range gradeDist {
			pct := 0.0
			if total > 0 {
				pct = float64(g.Count) / float64(total) * 100
			}
			m.GradeDist = append(m.GradeDist, GradeDistItem{
				Grade:      g.Grade,
				Display:    GradeDisplayNames[g.Grade],
				Count:      int(g.Count),
				Pct:        pct,
				PctDisplay: fmt.Sprintf("%.0f", pct),
				BootClass:  GradeBootstrapClass[g.Grade],
			})
		}
	}

	dimAvgs, err := queries.ICuAEGetDimensionAverages(ctx)
	if err == nil {
		for _, d := range dimAvgs {
			avgGrade := scoreToGrade(float64(d.AvgScore))
			m.DimensionStats = append(m.DimensionStats, DimensionStat{
				Dimension:   d.Dimension,
				Display:     DimensionDisplayNames[d.Dimension],
				Standard:    DimensionStandards[d.Dimension],
				AvgScore:    float64(d.AvgScore),
				AvgDisplay:  fmt.Sprintf("%.1f", d.AvgScore),
				Stddev:      float64(d.StddevScore),
				Grade:       avgGrade,
				BootClass:   GradeBootstrapClass[avgGrade],
				SampleCount: int(d.SampleCount),
			})
		}
	}

	trend, err := queries.ICuAEGetRecentTrend(ctx, 20)
	if err == nil && len(trend) >= 2 {
		m.TrendDirection, m.TrendArrow = computeTrend(trend)
	} else {
		m.TrendDirection = "insufficient"
		m.TrendArrow = "fas fa-minus"
	}

	return m
}

func computeStability(stddev float64) (string, string) {
	switch {
	case stddev < 5:
		return "high", "High Stability"
	case stddev < 10:
		return "good", "Good Stability"
	case stddev < 20:
		return "moderate", "Moderate Stability"
	default:
		return "variable", "Variable"
	}
}

func computeTrend(points []dbq.ICuAEGetRecentTrendRow) (string, string) {
	n := len(points)
	if n < 2 {
		return "insufficient", "fas fa-minus"
	}

	recentHalf := points[:n/2]
	olderHalf := points[n/2:]

	recentAvg := avgScores(recentHalf)
	olderAvg := avgScores(olderHalf)

	delta := recentAvg - olderAvg
	if math.Abs(delta) < 3.0 {
		return "stable", "fas fa-equals"
	}
	if delta > 0 {
		return "improving", "fas fa-arrow-trend-up"
	}
	return "declining", "fas fa-arrow-trend-down"
}

func avgScores(rows []dbq.ICuAEGetRecentTrendRow) float64 {
	if len(rows) == 0 {
		return 0
	}
	total := 0.0
	for _, r := range rows {
		total += float64(r.OverallScore)
	}
	return total / float64(len(rows))
}
