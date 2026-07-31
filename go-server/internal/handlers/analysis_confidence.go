// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"log/slog"

	"dnstool/go-server/internal/icuae"
)

var protocolResultKeys = map[string]string{
	"SPF":     mapKeySpfAnalysis,
	"DKIM":    mapKeyDkimAnalysis,
	"DMARC":   mapKeyDmarcAnalysis,
	"DANE":    "dane_analysis",
	"DNSSEC":  "dnssec_analysis",
	"BIMI":    "bimi_analysis",
	"MTA_STS": "mta_sts_analysis",
	"TLS_RPT": "tlsrpt_analysis",
	"CAA":     "caa_analysis",
}

var icuaeToDimChart = map[string]string{
	icuae.DimensionSourceCredibility: "SourceCredibility",
	icuae.DimensionCurrentness:       "TemporalValidity",
	icuae.DimensionCompleteness:      "ChainCompleteness",
	icuae.DimensionTTLCompliance:     "TTLCompliance",
	icuae.DimensionTTLRelevance:      "ResolverConsensus",
}

func (h *AnalysisHandler) applyConfidenceEngines(results map[string]any) {
	cr, ok := results[mapKeyCurrencyReport].(icuae.CurrencyReport)
	if !ok {
		return
	}

	calibrated := h.computeCalibratedConfidence(results, cr)
	results["calibrated_confidence"] = calibrated

	ewmaSnapshot := h.recordDimensionCharts(cr)
	results["ewma_drift"] = ewmaSnapshot

	slog.Info("Confidence engines applied",
		"protocols_calibrated", len(calibrated),
		"ewma_dimensions", len(ewmaSnapshot),
	)
}

func (h *AnalysisHandler) computeCalibratedConfidence(results map[string]any, cr icuae.CurrencyReport) map[string]float64 {
	totalAgree, totalResolvers := aggregateResolverAgreement(results)

	calibrated := make(map[string]float64, len(protocolResultKeys))
	for protocol, resultKey := range protocolResultKeys {
		severity := protocolVerdictSeverity(results, resultKey)
		cc := h.Calibration.CalibratedConfidence(protocol, severity, totalAgree, totalResolvers)
		calibrated[protocol] = cc
	}
	return calibrated
}

// protocolVerdictSeverity encodes the stored verdict's SEVERITY on a 0-1
// scale — it is not a probability and must never be renamed back to one.
// A refit was attempted and came back negative (Claude Science, 2026-07-30):
// the outcome such a probability would predict is 99.6% one class across
// 52,053 observations, so no meaningful probability can be fitted to replace
// this encoding. What blends downstream ("calibrated_confidence") is
// therefore severity shaded by resolver agreement and fixture-agreement
// priors — useful as a display weight, not calibration against outcomes.
func protocolVerdictSeverity(results map[string]any, resultKey string) float64 {
	section, ok := results[resultKey].(map[string]any)
	if !ok {
		return 0.0
	}
	status, _ := section[mapKeyStatus].(string) //nolint:errcheck // zero-value fallback is intentional
	switch status {
	case "secure", "pass", "valid", "good":
		return 1.0
	case mapKeyWarning, "info", "partial":
		return 0.7
	case "fail", mapKeyDanger, mapKeyCritical:
		return 0.3
	case mapKeyError, "n/a", "":
		return 0.0
	case "indeterminate", "inconclusive":
		// Transient / unmeasurable result — we could not determine the protocol's
		// state. Contribute the neutral midpoint: it must NOT read as a clean
		// pass (1.0), nor be penalized as a confirmed failure (0.3) or a
		// confirmed error/absence (0.0). Handled explicitly (not via the default
		// catch-all) so a future status-string change cannot silently fold an
		// unmeasurable result into a clean one (analytic confidence is its
		// own declared axis, separate from the verdict).
		return 0.5
	default:
		return 0.5
	}
}

func aggregateResolverAgreement(results map[string]any) (int, int) {
	consensus, ok := results["resolver_consensus"].(map[string]any)
	if !ok {
		return 0, 0
	}
	perRecord, ok := consensus["per_record_consensus"].(map[string]any)
	if !ok {
		return 0, 0
	}
	totalAgree := 0
	totalResolvers := 0
	for _, data := range perRecord {
		rd, ok := data.(map[string]any)
		if !ok {
			continue
		}
		rc, _ := rd["resolver_count"].(int)      //nolint:errcheck // zero-value fallback is intentional
		isConsensus, _ := rd["consensus"].(bool) //nolint:errcheck // zero-value fallback is intentional
		agreeCount := rc
		if !isConsensus {
			agreeCount = rc - 1
			if agreeCount < 0 {
				agreeCount = 0
			}
		}
		totalAgree += agreeCount
		totalResolvers += rc
	}
	return totalAgree, totalResolvers
}

func (h *AnalysisHandler) recordDimensionCharts(cr icuae.CurrencyReport) map[string]icuae.ChartSnapshot {
	scores := make(map[string]float64, len(cr.Dimensions))
	for _, dim := range cr.Dimensions {
		if chartKey, ok := icuaeToDimChart[dim.Dimension]; ok {
			scores[chartKey] = dim.Score
		}
	}
	h.DimCharts.RecordDimensionScores(scores)
	return h.DimCharts.Summary()
}
