// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny science
package icae

import (
        "math"
        "sync"

        "gonum.org/v1/gonum/stat/distuv"
)

type CategoryPrior struct {
        Alpha       float64
        Beta        float64
        Description string
}

type CalibrationEngine struct {
        mu     sync.RWMutex
        priors map[string]CategoryPrior
}

func NewCalibrationEngine() *CalibrationEngine {
        return &CalibrationEngine{
                priors: map[string]CategoryPrior{
                        "SPF":     {Alpha: 95, Beta: 5, Description: "very reliable detection"},
                        "DKIM":    {Alpha: 90, Beta: 10, Description: "reliable but selector discovery varies"},
                        "DMARC":   {Alpha: 97, Beta: 3, Description: "deterministic record parsing"},
                        "DANE":    {Alpha: 85, Beta: 15, Description: "TLSA can be tricky"},
                        "DNSSEC":  {Alpha: 92, Beta: 8, Description: "chain validation well understood"},
                        "BIMI":    {Alpha: 88, Beta: 12, Description: "newer standard, less field data"},
                        "MTA_STS": {Alpha: 90, Beta: 10, Description: "straightforward policy check"},
                        "TLS_RPT": {Alpha: 93, Beta: 7, Description: "simple record presence"},
                        "CAA":     {Alpha: 95, Beta: 5, Description: "deterministic DNS record"},
                },
        }
}

func (ce *CalibrationEngine) PriorForCategory(category string) (alpha, beta float64, ok bool) {
        ce.mu.RLock()
        defer ce.mu.RUnlock()
        p, ok := ce.priors[category]
        if !ok {
                return 0, 0, false
        }
        return p.Alpha, p.Beta, true
}

func (ce *CalibrationEngine) PriorMean(category string) float64 {
        ce.mu.RLock()
        defer ce.mu.RUnlock()
        p, ok := ce.priors[category]
        if !ok {
                return 0
        }
        d := distuv.Beta{Alpha: p.Alpha, Beta: p.Beta}
        return d.Mean()
}

func (ce *CalibrationEngine) ReliabilityWeightedSeverity(category string, rawConfidence float64, resolverAgreement, totalResolvers int) float64 {
        if totalResolvers == 0 {
                return ce.PriorMean(category)
        }
        measurementQuality := float64(resolverAgreement) / float64(totalResolvers)
        priorMean := ce.PriorMean(category)
        w := measurementQuality
        calibrated := w*rawConfidence + (1-w)*priorMean
        return math.Max(0.0, math.Min(1.0, calibrated))
}

// DefaultEvidenceCap bounds how many accumulated clean passes a single protocol
// may contribute to its prior. Capping keeps the update conservative: a protocol
// with thousands of clean passes is treated the same as one with the cap, so the
// prior reflects "demonstrated reliability" without letting raw volume run away.
// 250 is the first cap at which every protocol's degraded-calibration gap reaches
// the excellent band (< 0.02) — see internal/icae/evidence_priors_test.go.
const DefaultEvidenceCap = 250

// ApplyEvidence raises each protocol's prior using its accumulated maturity
// evidence — evidence-weighted scoring inspired by Bayesian reasoning. For each
// protocol it takes the MINIMUM of the analysis-layer and collection-layer
// consecutive-pass counts (a protocol cannot claim maturity it has demonstrated
// on only one layer), clamps that to [0, cap], and adds it to the Beta-Binomial
// Alpha (success) parameter. The Beta (failure) parameter is never touched, so
// the path can only ever reflect a *clean* track record — it cannot launder
// failures away. Consecutive-pass counters reset on regression, so a freshly
// regressed protocol contributes little evidence and stays conservative.
//
// effective_prior = (alpha + cappedPasses) / (alpha + beta + cappedPasses)
//
// Intended usage: a one-shot update applied to a FRESH engine snapshot (as the
// /confidence handler does — new engine per request). It mutates in place and is
// not designed to be layered repeatedly on the same engine.
//
// This is a no-op for nil metrics or a non-positive cap.
func (ce *CalibrationEngine) ApplyEvidence(metrics *ReportMetrics, cap int) {
        if metrics == nil || cap <= 0 {
                return
        }
        ce.mu.Lock()
        defer ce.mu.Unlock()
        for _, pr := range metrics.Protocols {
                key := mapProtocolToCalibrationKey(pr.Protocol)
                prior, ok := ce.priors[key]
                if !ok {
                        continue
                }
                evidence := pr.AnalysisPasses
                if pr.CollectionPasses < evidence {
                        evidence = pr.CollectionPasses
                }
                if evidence <= 0 {
                        continue
                }
                if evidence > cap {
                        evidence = cap
                }
                prior.Alpha += float64(evidence)
                ce.priors[key] = prior
        }
}

func (ce *CalibrationEngine) UpdatePrior(category string, wasCorrect bool) {
        ce.mu.Lock()
        defer ce.mu.Unlock()
        p, ok := ce.priors[category]
        if !ok {
                return
        }
        if wasCorrect {
                p.Alpha += 1
        } else {
                p.Beta += 1
        }
        ce.priors[category] = p
}

func (ce *CalibrationEngine) AllPriors() map[string]CategoryPrior {
        ce.mu.RLock()
        defer ce.mu.RUnlock()
        result := make(map[string]CategoryPrior, len(ce.priors))
        for k, v := range ce.priors {
                result[k] = v
        }
        return result
}
