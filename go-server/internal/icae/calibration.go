// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Calibration Validation — empirical accuracy of the confidence scoring system.
//
// Computes Brier score and Expected Calibration Error (ECE) from golden fixture
// test results. These metrics answer: "When we assign X% confidence, are we
// correct approximately X% of the time?"
//
// Brier score: Mean squared error between predicted probability and binary outcome.
//   - Perfect: 0.0 (every prediction was 0 or 1 and correct)
//   - No skill: 0.25 (equivalent to always predicting 0.5)
//   - Worse than random: >0.25
//
// ECE: Mean absolute gap between predicted confidence and observed accuracy,
// weighted by bin population. Measures reliability — how well the system's
// stated confidence matches its actual performance.
//
// Reference: Brier (1950), Naeini et al. (2015) for ECE.
// dns-tool:scrutiny science
package icae

import (
        "math"
        "sort"
)

type CalibrationResult struct {
        BrierScore         float64              `json:"brier_score"`
        BrierInterpretation string              `json:"brier_interpretation"`
        ECE                float64              `json:"ece"`
        ECEInterpretation  string              `json:"ece_interpretation"`
        TotalPredictions   int                  `json:"total_predictions"`
        Bins               []CalibrationBin     `json:"bins"`
        PerProtocol        map[string]ProtocolCalibration `json:"per_protocol"`
}

type CalibrationBin struct {
        BinStart          float64 `json:"bin_start"`
        BinEnd            float64 `json:"bin_end"`
        Count             int     `json:"count"`
        MeanPredicted     float64 `json:"mean_predicted"`
        MeanObserved      float64 `json:"mean_observed"`
        Gap               float64 `json:"gap"`
}

type ProtocolCalibration struct {
        Protocol       string  `json:"protocol"`
        BrierScore     float64 `json:"brier_score"`
        TotalCases     int     `json:"total_cases"`
        PassRate       float64 `json:"pass_rate"`
        MeanConfidence float64 `json:"mean_confidence"`
        CalibrationGap float64 `json:"calibration_gap"`
}

type PredictionOutcome struct {
        Protocol   string
        Confidence float64
        Outcome    float64
}

func ComputeCalibration(predictions []PredictionOutcome, numBins int) CalibrationResult {
        if len(predictions) == 0 {
                return CalibrationResult{
                        BrierScore:          0,
                        BrierInterpretation: "No predictions to evaluate",
                        ECE:                 0,
                        ECEInterpretation:   "No predictions to evaluate",
                }
        }

        if numBins <= 0 {
                numBins = 10
        }

        brier := computeBrierScore(predictions)
        bins := computeCalibrationBins(predictions, numBins)
        ece := computeECE(bins, len(predictions))
        perProto := computePerProtocolCalibration(predictions)

        return CalibrationResult{
                BrierScore:          brier,
                BrierInterpretation: interpretBrier(brier),
                ECE:                 ece,
                ECEInterpretation:   interpretECE(ece),
                TotalPredictions:    len(predictions),
                Bins:                bins,
                PerProtocol:         perProto,
        }
}

func computeBrierScore(predictions []PredictionOutcome) float64 {
        sumSqErr := 0.0
        for _, p := range predictions {
                diff := p.Confidence - p.Outcome
                sumSqErr += diff * diff
        }
        return sumSqErr / float64(len(predictions))
}

func computeCalibrationBins(predictions []PredictionOutcome, numBins int) []CalibrationBin {
        binWidth := 1.0 / float64(numBins)
        bins := make([]CalibrationBin, numBins)

        for i := range bins {
                bins[i].BinStart = float64(i) * binWidth
                bins[i].BinEnd = float64(i+1) * binWidth
        }

        for _, p := range predictions {
                idx := int(p.Confidence / binWidth)
                if idx >= numBins {
                        idx = numBins - 1
                }
                if idx < 0 {
                        idx = 0
                }
                bins[idx].Count++
                bins[idx].MeanPredicted += p.Confidence
                bins[idx].MeanObserved += p.Outcome
        }

        for i := range bins {
                if bins[i].Count > 0 {
                        bins[i].MeanPredicted /= float64(bins[i].Count)
                        bins[i].MeanObserved /= float64(bins[i].Count)
                        bins[i].Gap = math.Abs(bins[i].MeanPredicted - bins[i].MeanObserved)
                }
        }

        return bins
}

func computeECE(bins []CalibrationBin, totalPredictions int) float64 {
        if totalPredictions == 0 {
                return 0
        }
        ece := 0.0
        for _, bin := range bins {
                if bin.Count > 0 {
                        weight := float64(bin.Count) / float64(totalPredictions)
                        ece += weight * bin.Gap
                }
        }
        return ece
}

func computePerProtocolCalibration(predictions []PredictionOutcome) map[string]ProtocolCalibration {
        grouped := make(map[string][]PredictionOutcome)
        for _, p := range predictions {
                grouped[p.Protocol] = append(grouped[p.Protocol], p)
        }

        result := make(map[string]ProtocolCalibration)
        for proto, preds := range grouped {
                sumConf := 0.0
                sumOutcome := 0.0
                sumSqErr := 0.0
                for _, p := range preds {
                        sumConf += p.Confidence
                        sumOutcome += p.Outcome
                        diff := p.Confidence - p.Outcome
                        sumSqErr += diff * diff
                }
                n := float64(len(preds))
                meanConf := sumConf / n
                meanOutcome := sumOutcome / n

                result[proto] = ProtocolCalibration{
                        Protocol:       proto,
                        BrierScore:     sumSqErr / n,
                        TotalCases:     len(preds),
                        PassRate:       meanOutcome,
                        MeanConfidence: meanConf,
                        CalibrationGap: math.Abs(meanConf - meanOutcome),
                }
        }
        return result
}

func interpretBrier(score float64) string {
        switch {
        case score < 0.01:
                return "Excellent — near-perfect probabilistic accuracy"
        case score < 0.05:
                return "Good — strong calibration, minor deviations"
        case score < 0.10:
                return "Adequate — reasonable accuracy with room for improvement"
        case score < 0.25:
                return "Weak — systematic over- or under-confidence detected"
        default:
                return "Poor — worse than random baseline (0.25)"
        }
}

func interpretECE(ece float64) string {
        switch {
        case ece < 0.02:
                return "Excellent — stated confidence closely matches observed accuracy"
        case ece < 0.05:
                return "Good — minor calibration gap, operationally reliable"
        case ece < 0.10:
                return "Adequate — noticeable gap between confidence and accuracy"
        case ece < 0.20:
                return "Weak — significant miscalibration, confidence scores unreliable"
        default:
                return "Poor — severe miscalibration, confidence scores misleading"
        }
}

func RunFixtureCalibration(ce *CalibrationEngine) CalibrationResult {
        fixtures := FixtureTestCases()

        var predictions []PredictionOutcome
        for _, tc := range fixtures {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)
                confidence := ce.CalibratedConfidence(protoKey, 1.0, 5, 5)

                predictions = append(predictions, PredictionOutcome{
                        Protocol:   tc.Protocol,
                        Confidence: confidence,
                        Outcome:    outcome,
                })
        }

        return ComputeCalibration(predictions, 10)
}

func RunFullCalibration(ce *CalibrationEngine) CalibrationResult {
        var allCases []TestCase
        allCases = append(allCases, AnalysisTestCases()...)
        allCases = append(allCases, CollectionTestCases()...)

        var predictions []PredictionOutcome
        for _, tc := range allCases {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)
                confidence := ce.CalibratedConfidence(protoKey, 1.0, 5, 5)

                predictions = append(predictions, PredictionOutcome{
                        Protocol:   tc.Protocol,
                        Confidence: confidence,
                        Outcome:    outcome,
                })
        }

        sort.Slice(predictions, func(i, j int) bool {
                return predictions[i].Confidence < predictions[j].Confidence
        })

        return ComputeCalibration(predictions, 10)
}

func RunDegradedCalibration(ce *CalibrationEngine) CalibrationResult {
        var allCases []TestCase
        allCases = append(allCases, AnalysisTestCases()...)
        allCases = append(allCases, CollectionTestCases()...)

        resolverScenarios := []struct {
                agree int
                total int
        }{
                {5, 5},
                {4, 5},
                {3, 5},
                {2, 5},
                {1, 5},
        }

        var predictions []PredictionOutcome
        for _, tc := range allCases {
                _, passed := tc.RunFn()

                outcome := 0.0
                if passed {
                        outcome = 1.0
                }

                protoKey := mapProtocolToCalibrationKey(tc.Protocol)

                for _, scenario := range resolverScenarios {
                        confidence := ce.CalibratedConfidence(protoKey, 1.0, scenario.agree, scenario.total)

                        predictions = append(predictions, PredictionOutcome{
                                Protocol:   tc.Protocol,
                                Confidence: confidence,
                                Outcome:    outcome,
                        })
                }
        }

        sort.Slice(predictions, func(i, j int) bool {
                return predictions[i].Confidence < predictions[j].Confidence
        })

        return ComputeCalibration(predictions, 10)
}

func mapProtocolToCalibrationKey(protocol string) string {
        keyMap := map[string]string{
                "spf":     "SPF",
                "dkim":    "DKIM",
                "dmarc":   "DMARC",
                "dane":    "DANE",
                "dnssec":  "DNSSEC",
                "bimi":    "BIMI",
                "mta_sts": "MTA_STS",
                "tlsrpt":  "TLS_RPT",
                "caa":     "CAA",
        }
        if k, ok := keyMap[protocol]; ok {
                return k
        }
        return protocol
}
