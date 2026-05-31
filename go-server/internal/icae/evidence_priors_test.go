// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Tests for the evidence-weighted prior path (ApplyEvidence). These verify that
// accumulated maturity evidence raises priors honestly via Beta-Binomial
// shrinkage inspired by Bayesian reasoning, that the cap and min(analysis,
// collection) rules hold, and — critically — that the calibration validator
// still PUNISHES over-confidence on genuine failures (anti-gaming guardrail).
package icae

import (
        "math"
        "testing"
)

// metricsWithLayers builds a ReportMetrics where every protocol carries the
// given analysis/collection consecutive-pass counts.
func metricsWithLayers(analysisPasses, collectionPasses int) *ReportMetrics {
        protos := []string{
                ProtoSPF, ProtoDKIM, ProtoDMARC, ProtoDANE, ProtoDNSSEC,
                ProtoBIMI, ProtoMTASTS, ProtoTLSRPT, ProtoCAA,
        }
        m := &ReportMetrics{}
        for _, p := range protos {
                m.Protocols = append(m.Protocols, ProtocolReport{
                        Protocol:         p,
                        AnalysisPasses:   analysisPasses,
                        CollectionPasses: collectionPasses,
                })
        }
        return m
}

// TestApplyEvidenceRaisesDANEPriorToCap verifies the canonical lab result:
// DANE with abundant clean passes, capped at 250, yields effective prior
// (85+250)/(85+15+250) = 335/350 = 0.957142857...
func TestApplyEvidenceRaisesDANEPriorToCap(t *testing.T) {
        ce := NewCalibrationEngine()
        ce.ApplyEvidence(metricsWithLayers(4000, 4000), DefaultEvidenceCap)

        got := ce.PriorMean("DANE")
        want := 335.0 / 350.0
        if math.Abs(got-want) > 1e-9 {
                t.Errorf("DANE prior after cap-250 evidence = %v, want %v", got, want)
        }
}

// TestApplyEvidenceRespectsCap verifies that evidence above the cap is clamped,
// and evidence below the cap is applied verbatim.
func TestApplyEvidenceRespectsCap(t *testing.T) {
        // Far above the cap → same as exactly the cap.
        ceHigh := NewCalibrationEngine()
        ceHigh.ApplyEvidence(metricsWithLayers(10000, 10000), 250)

        ceExact := NewCalibrationEngine()
        ceExact.ApplyEvidence(metricsWithLayers(250, 250), 250)

        if math.Abs(ceHigh.PriorMean("DANE")-ceExact.PriorMean("DANE")) > 1e-9 {
                t.Errorf("cap not enforced: 10000 passes gave %v, 250 passes gave %v",
                        ceHigh.PriorMean("DANE"), ceExact.PriorMean("DANE"))
        }

        // Below the cap → applied verbatim: (85+100)/(85+15+100) = 185/200 = 0.925.
        ceLow := NewCalibrationEngine()
        ceLow.ApplyEvidence(metricsWithLayers(100, 100), 250)
        if got, want := ceLow.PriorMean("DANE"), 185.0/200.0; math.Abs(got-want) > 1e-9 {
                t.Errorf("DANE prior with 100 passes = %v, want %v", got, want)
        }
}

// TestApplyEvidenceUsesMinOfLayers verifies that the evidence source is the
// MINIMUM of analysis and collection consecutive passes — a protocol cannot
// claim maturity it has only demonstrated on one layer.
func TestApplyEvidenceUsesMinOfLayers(t *testing.T) {
        ce := NewCalibrationEngine()
        // Analysis strong (4000) but collection thin (30) → evidence must be 30.
        ce.ApplyEvidence(&ReportMetrics{Protocols: []ProtocolReport{
                {Protocol: ProtoDANE, AnalysisPasses: 4000, CollectionPasses: 30},
        }}, DefaultEvidenceCap)

        got := ce.PriorMean("DANE")
        want := (85.0 + 30.0) / (85.0 + 15.0 + 30.0) // 115/130
        if math.Abs(got-want) > 1e-9 {
                t.Errorf("min-of-layers not honored: DANE prior = %v, want %v (evidence=30)", got, want)
        }
}

// TestApplyEvidenceNoEvidenceLeavesPriorUnchanged verifies that a protocol with
// zero clean passes (or no collection layer) keeps its conservative bootstrap
// prior — evidence never lowers it and absence never inflates it.
func TestApplyEvidenceNoEvidenceLeavesPriorUnchanged(t *testing.T) {
        ce := NewCalibrationEngine()
        base := ce.PriorMean("DANE")

        // Zero passes on both layers.
        ce.ApplyEvidence(&ReportMetrics{Protocols: []ProtocolReport{
                {Protocol: ProtoDANE, AnalysisPasses: 0, CollectionPasses: 0},
        }}, DefaultEvidenceCap)
        if got := ce.PriorMean("DANE"); math.Abs(got-base) > 1e-9 {
                t.Errorf("zero evidence changed prior: got %v, want %v", got, base)
        }

        // Strong analysis but NO collection layer (collection=0) → min=0 → unchanged.
        ce2 := NewCalibrationEngine()
        ce2.ApplyEvidence(&ReportMetrics{Protocols: []ProtocolReport{
                {Protocol: ProtoDANE, AnalysisPasses: 4000, CollectionPasses: 0},
        }}, DefaultEvidenceCap)
        if got := ce2.PriorMean("DANE"); math.Abs(got-base) > 1e-9 {
                t.Errorf("missing collection layer inflated prior: got %v, want %v", got, base)
        }
}

// TestApplyEvidenceNeverAddsFailures verifies that the evidence path only ever
// adds clean-pass mass to Alpha; the failure side (Beta) is never touched. This
// is what keeps the update honest — it cannot be used to launder failures away.
func TestApplyEvidenceNeverAddsFailures(t *testing.T) {
        ce := NewCalibrationEngine()
        _, beta0, _ := ce.PriorForCategory("DANE")
        ce.ApplyEvidence(metricsWithLayers(4000, 4000), DefaultEvidenceCap)
        alpha1, beta1, _ := ce.PriorForCategory("DANE")

        if beta1 != beta0 {
                t.Errorf("evidence path mutated Beta (failure mass): got %v, want %v", beta1, beta0)
        }
        if alpha1 != 85+250 {
                t.Errorf("evidence path Alpha = %v, want %v", alpha1, 85+250)
        }
}

// TestApplyEvidenceDegradedProtocolStaysConservative verifies that a protocol
// that recently regressed (low consecutive passes) is NOT granted excellence.
// Consecutive-pass counters reset on regression, so the evidence path naturally
// reflects real, current track record — not lifetime totals.
func TestApplyEvidenceDegradedProtocolStaysConservative(t *testing.T) {
        ce := NewCalibrationEngine()
        // Freshly regressed: only 5 clean passes since the last failure.
        ce.ApplyEvidence(&ReportMetrics{Protocols: []ProtocolReport{
                {Protocol: ProtoDANE, AnalysisPasses: 5, CollectionPasses: 5},
        }}, DefaultEvidenceCap)

        got := ce.PriorMean("DANE")
        want := (85.0 + 5.0) / (85.0 + 15.0 + 5.0) // 90/105 ≈ 0.857
        if math.Abs(got-want) > 1e-9 {
                t.Errorf("degraded DANE prior = %v, want %v", got, want)
        }
        if got >= 0.875 {
                t.Errorf("freshly-regressed DANE should stay below the 0.875 escape threshold, got %v", got)
        }
}

// TestApplyEvidenceNilAndCapGuards verifies defensive no-ops.
func TestApplyEvidenceNilAndCapGuards(t *testing.T) {
        ce := NewCalibrationEngine()
        base := ce.PriorMean("DANE")

        ce.ApplyEvidence(nil, DefaultEvidenceCap) // nil metrics
        if got := ce.PriorMean("DANE"); math.Abs(got-base) > 1e-9 {
                t.Errorf("nil metrics changed prior: %v", got)
        }

        ce.ApplyEvidence(metricsWithLayers(4000, 4000), 0) // non-positive cap
        if got := ce.PriorMean("DANE"); math.Abs(got-base) > 1e-9 {
                t.Errorf("zero cap changed prior: %v", got)
        }
}

// TestBaselineDegradedHasEightyNinetyGap LOCKS the documented "before" state:
// the static bootstrap engine produces a populated 80–90% reliability bin,
// driven by DANE/TLSA at 1/5 resolver agreement (0.2*1.0 + 0.8*0.85 = 0.88).
// If a future change silently erases this gap WITHOUT adding evidence, this
// test fails — guarding against cosmetic relabeling.
func TestBaselineDegradedHasEightyNinetyGap(t *testing.T) {
        ce := NewCalibrationEngine()
        result := RunDegradedCalibration(ce)

        // Bin index 8 covers [0.80, 0.90).
        bin := result.Bins[8]
        if bin.Count == 0 {
                t.Fatal("expected a populated 80–90% bin in the baseline, got none")
        }
        if bin.Gap < 0.10 {
                t.Errorf("baseline 80–90%% bin gap = %v, expected the documented under-confidence (~0.12)", bin.Gap)
        }
}

// TestEvidencePriorClosesEightyNinetyGap is the core integration proof: with
// abundant clean passes on both layers (capped at 250), the evidence-weighted
// engine moves DANE/TLSA's 1/5 confidence above 90%, emptying the 80–90% bin,
// and brings EVERY per-protocol gap into the "excellent" band (< 0.02).
func TestEvidencePriorClosesEightyNinetyGap(t *testing.T) {
        ce := NewCalibrationEngine()
        ce.ApplyEvidence(metricsWithLayers(4000, 4000), DefaultEvidenceCap)
        result := RunDegradedCalibration(ce)

        if got := result.Bins[8].Count; got != 0 {
                t.Errorf("80–90%% bin should be empty after evidence prior, got %d predictions", got)
        }

        for proto, cal := range result.PerProtocol {
                if cal.CalibrationGap >= 0.02 {
                        t.Errorf("protocol %s gap = %.4f, expected < 0.02 (excellent) after evidence prior",
                                proto, cal.CalibrationGap)
                }
        }
}

// worstProtocolGap returns the largest per-protocol calibration gap in a result.
func worstProtocolGap(result CalibrationResult) float64 {
        worst := 0.0
        for _, cal := range result.PerProtocol {
                if cal.CalibrationGap > worst {
                        worst = cal.CalibrationGap
                }
        }
        return worst
}

// TestEvidenceCapSensitivity de-risks the "honest calibration" claim against
// benchmark overfitting: it shows DefaultEvidenceCap is NOT a magic number but a
// conservative point on a monotone sensitivity curve. With abundant evidence, the
// worst-protocol gap shrinks monotonically as the cap rises; cap=200 sits exactly
// on the 0.02 boundary (DANE prior = 285/300 = 0.95), and cap=250 clears it with
// margin (0.0171). Picking 250 — not 200 — deliberately buys headroom past the
// prior>0.95 threshold rather than tuning to the knife's edge.
func TestEvidenceCapSensitivity(t *testing.T) {
        caps := []int{100, 150, 200, 250, 300}
        worst := make(map[int]float64, len(caps))
        for _, c := range caps {
                ce := NewCalibrationEngine()
                ce.ApplyEvidence(metricsWithLayers(4000, 4000), c)
                worst[c] = worstProtocolGap(RunDegradedCalibration(ce))
                t.Logf("cap=%d  worst per-protocol gap=%.4f", c, worst[c])
        }

        // Monotone non-increasing: more evidence never worsens calibration.
        for i := 1; i < len(caps); i++ {
                if worst[caps[i]] > worst[caps[i-1]]+1e-9 {
                        t.Errorf("gap not monotone: cap=%d gap=%.4f > cap=%d gap=%.4f",
                                caps[i], worst[caps[i]], caps[i-1], worst[caps[i-1]])
                }
        }

        // cap=200 is on the boundary (~0.02); cap=250 clears excellent with margin.
        if worst[200] < 0.02-1e-9 {
                t.Errorf("expected cap=200 worst gap on/above the 0.02 boundary, got %.4f", worst[200])
        }
        if worst[250] >= 0.02 {
                t.Errorf("expected cap=250 (DefaultEvidenceCap) worst gap < 0.02, got %.4f", worst[250])
        }
        if DefaultEvidenceCap != 250 {
                t.Errorf("DefaultEvidenceCap drifted from the documented sensitivity analysis: %d", DefaultEvidenceCap)
        }
}

// TestCalibrationPunishesOverconfidentFailures is the anti-gaming guardrail:
// it proves the validator is NOT rigged to always report "excellent". When
// confidence is high but a real fraction of outcomes are failures, Brier, ECE,
// and the per-protocol gap must all degrade into poor/weak territory. Without
// this, pushing every confidence to ~1.0 on an all-passing golden set would be
// a hollow victory; this test ensures genuine failures are caught.
func TestCalibrationPunishesOverconfidentFailures(t *testing.T) {
        var preds []PredictionOutcome
        for i := 0; i < 70; i++ {
                preds = append(preds, PredictionOutcome{Protocol: "dane", Confidence: 0.99, Outcome: 1.0})
        }
        for i := 0; i < 30; i++ {
                preds = append(preds, PredictionOutcome{Protocol: "dane", Confidence: 0.99, Outcome: 0.0})
        }
        result := ComputeCalibration(preds, 10)

        if result.BrierRating != "poor" {
                t.Errorf("over-confidence on 30%% failures should rate Brier 'poor', got %q (%.4f)",
                        result.BrierRating, result.BrierScore)
        }
        if result.ECERating != "poor" {
                t.Errorf("over-confidence on 30%% failures should rate ECE 'poor', got %q (%.4f)",
                        result.ECERating, result.ECE)
        }
        dane := result.PerProtocol["dane"]
        if dane.GapRating == "excellent" || dane.GapRating == "good" {
                t.Errorf("per-protocol gap should not be excellent/good under 30%% failures, got %q (%.4f)",
                        dane.GapRating, dane.CalibrationGap)
        }
}
