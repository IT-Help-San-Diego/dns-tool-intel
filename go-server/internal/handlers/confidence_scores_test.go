// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "testing"
        "time"
)

func confidenceTestTime() time.Time {
        return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
}

func TestConfidenceScoresProtocolDBName(t *testing.T) {
        cases := map[string]string{
                "SPF":     "SPF",
                "DKIM":    "DKIM",
                "DMARC":   "DMARC",
                "MTA_STS": "MTA-STS",
                "TLS_RPT": "TLS-RPT",
                "DNSSEC":  "DNSSEC",
        }
        for in, want := range cases {
                if got := confidenceProtocolDBName(in); got != want {
                        t.Errorf("confidenceProtocolDBName(%q) = %q, want %q", in, got, want)
                }
        }
}

func TestConfidenceScoresAsFloat64(t *testing.T) {
        if v, ok := asFloat64(float64(0.85)); !ok || v != 0.85 {
                t.Errorf("float64: got %v %v", v, ok)
        }
        if v, ok := asFloat64(int(3)); !ok || v != 3 {
                t.Errorf("int: got %v %v", v, ok)
        }
        if v, ok := asFloat64(json.Number("0.5")); !ok || v != 0.5 {
                t.Errorf("json.Number: got %v %v", v, ok)
        }
        if _, ok := asFloat64("nope"); ok {
                t.Error("string should not convert")
        }
        if _, ok := asFloat64(nil); ok {
                t.Error("nil should not convert")
        }
}

func TestConfidenceScoresClamp01(t *testing.T) {
        if clamp01(-0.5) != 0 {
                t.Error("negative should clamp to 0")
        }
        if clamp01(1.5) != 1 {
                t.Error(">1 should clamp to 1")
        }
        if clamp01(0.42) != 0.42 {
                t.Error("in-range value should pass through")
        }
}

func TestConfidenceScoresCalibratedMapLiveShape(t *testing.T) {
        results := map[string]any{
                "calibrated_confidence": map[string]float64{"SPF": 0.9, "DMARC": 1.0},
        }
        m := reliabilityWeightedSeverityMap(results)
        if len(m) != 2 || m["SPF"] != 0.9 || m["DMARC"] != 1.0 {
                t.Errorf("live shape: got %v", m)
        }
}

func TestConfidenceScoresCalibratedMapJSONShape(t *testing.T) {
        raw := []byte(`{"calibrated_confidence":{"SPF":0.9,"DKIM":0.7}}`)
        var results map[string]any
        if err := json.Unmarshal(raw, &results); err != nil {
                t.Fatal(err)
        }
        m := reliabilityWeightedSeverityMap(results)
        if len(m) != 2 || m["SPF"] != 0.9 || m["DKIM"] != 0.7 {
                t.Errorf("JSON shape: got %v", m)
        }
}

func TestConfidenceScoresCalibratedMapMissing(t *testing.T) {
        if m := reliabilityWeightedSeverityMap(map[string]any{}); m != nil {
                t.Errorf("missing map should return nil, got %v", m)
        }
}

func TestConfidenceScoresExtractRowsLive(t *testing.T) {
        results := map[string]any{
                "calibrated_confidence": map[string]float64{"SPF": 0.95, "MTA_STS": 0.7},
                mapKeySpfAnalysis:       map[string]any{mapKeyStatus: "secure"},
                "mta_sts_analysis":      map[string]any{mapKeyStatus: mapKeyWarning},
        }
        rows := extractConfidenceRows(results)
        if len(rows) != 2 {
                t.Fatalf("expected 2 rows, got %d", len(rows))
        }
        byProto := map[string]confidenceScoreRow{}
        for _, r := range rows {
                byProto[r.Protocol] = r
        }
        spf := byProto["SPF"]
        if spf.Calibrated != 0.95 || spf.Raw != 1.0 || spf.Status != "secure" {
                t.Errorf("SPF row: %+v", spf)
        }
        mtaSts := byProto["MTA_STS"]
        if mtaSts.Calibrated != 0.7 || mtaSts.Raw != 0.7 {
                t.Errorf("MTA_STS row: %+v", mtaSts)
        }
}

func TestConfidenceScoresExtractRowsJSONRoundTrip(t *testing.T) {
        raw := []byte(`{
                "calibrated_confidence": {"DMARC": 0.88},
                "dmarc_analysis": {"status": "indeterminate"}
        }`)
        var results map[string]any
        if err := json.Unmarshal(raw, &results); err != nil {
                t.Fatal(err)
        }
        rows := extractConfidenceRows(results)
        if len(rows) != 1 {
                t.Fatalf("expected 1 row, got %d", len(rows))
        }
        if rows[0].Protocol != "DMARC" || rows[0].Calibrated != 0.88 || rows[0].Raw != 0.5 || rows[0].Status != "indeterminate" {
                t.Errorf("DMARC row: %+v", rows[0])
        }
}

func TestConfidenceScoresExtractRowsNoCalibratedMap(t *testing.T) {
        results := map[string]any{
                mapKeySpfAnalysis: map[string]any{mapKeyStatus: "secure"},
        }
        if rows := extractConfidenceRows(results); rows != nil {
                t.Errorf("no calibrated map should yield nil rows, got %v", rows)
        }
}

func TestConfidenceScoresResolverAgreementTolerantLiveInts(t *testing.T) {
        results := map[string]any{
                "resolver_consensus": map[string]any{
                        "per_record_consensus": map[string]any{
                                "A":  map[string]any{"resolver_count": int(4), "consensus": true},
                                "MX": map[string]any{"resolver_count": int(4), "consensus": false},
                        },
                },
        }
        agree, total := aggregateResolverAgreementTolerant(results)
        if agree != 7 || total != 8 {
                t.Errorf("live ints: agree=%d total=%d, want 7/8", agree, total)
        }
}

func TestConfidenceScoresResolverAgreementTolerantJSONFloats(t *testing.T) {
        raw := []byte(`{
                "resolver_consensus": {
                        "per_record_consensus": {
                                "A":  {"resolver_count": 4, "consensus": true},
                                "MX": {"resolver_count": 4, "consensus": false}
                        }
                }
        }`)
        var results map[string]any
        if err := json.Unmarshal(raw, &results); err != nil {
                t.Fatal(err)
        }
        agree, total := aggregateResolverAgreementTolerant(results)
        if agree != 7 || total != 8 {
                t.Errorf("JSON floats: agree=%d total=%d, want 7/8", agree, total)
        }
}

func TestConfidenceScoresResolverAgreementTolerantMissing(t *testing.T) {
        agree, total := aggregateResolverAgreementTolerant(map[string]any{})
        if agree != 0 || total != 0 {
                t.Errorf("missing consensus: agree=%d total=%d, want 0/0", agree, total)
        }
}

func TestConfidenceScoresNumericFromFloat(t *testing.T) {
        n, err := numericFromFloat(0.9375)
        if err != nil {
                t.Fatal(err)
        }
        if !n.Valid {
                t.Error("numeric should be valid")
        }
        f, err := n.Float64Value()
        if err != nil {
                t.Fatal(err)
        }
        if f.Float64 != 0.9375 {
                t.Errorf("round-trip: got %v, want 0.9375", f.Float64)
        }
}

func TestConfidenceScoresBuildParams(t *testing.T) {
        row := confidenceScoreRow{Protocol: "TLS_RPT", Calibrated: 0.82, Raw: 0.7, Status: "warning"}
        params, err := buildConfidenceScoreParams(42, "example.com", row, 7, 8, confidenceTestTime(), confidenceSourceScan, "26.51-test")
        if err != nil {
                t.Fatal(err)
        }
        if params.AnalysisID == nil || *params.AnalysisID != 42 {
                t.Errorf("analysis_id: %v", params.AnalysisID)
        }
        if params.Protocol != "TLS-RPT" {
                t.Errorf("protocol should map to DB spelling, got %q", params.Protocol)
        }
        if params.Domain != "example.com" || params.Source != confidenceSourceScan {
                t.Errorf("domain/source: %q %q", params.Domain, params.Source)
        }
        if params.ResolverCount == nil || *params.ResolverCount != 8 {
                t.Errorf("resolver_count: %v", params.ResolverCount)
        }
        if !params.ResolverAgreement.Valid {
                t.Error("resolver_agreement should be set when total > 0")
        }
        var factors map[string]any
        if err := json.Unmarshal(params.EvidenceFactors, &factors); err != nil {
                t.Fatal(err)
        }
        if factors["status"] != "warning" || factors["resolver_scope"] != "aggregate" || factors["app_version"] != "26.51-test" {
                t.Errorf("evidence_factors: %v", factors)
        }
        if !params.ScannedAt.Valid {
                t.Error("scanned_at should be valid")
        }
}

func TestConfidenceScoresBuildParamsNoResolvers(t *testing.T) {
        row := confidenceScoreRow{Protocol: "SPF", Calibrated: 1.0, Raw: 1.0, Status: "secure"}
        params, err := buildConfidenceScoreParams(7, "example.org", row, 0, 0, confidenceTestTime(), confidenceSourceImport, "")
        if err != nil {
                t.Fatal(err)
        }
        if params.ResolverCount != nil {
                t.Errorf("resolver_count should be nil when total == 0, got %v", *params.ResolverCount)
        }
        if params.ResolverAgreement.Valid {
                t.Error("resolver_agreement should be NULL when total == 0")
        }
        var factors map[string]any
        if err := json.Unmarshal(params.EvidenceFactors, &factors); err != nil {
                t.Fatal(err)
        }
        if _, present := factors["app_version"]; present {
                t.Error("app_version should be omitted when empty")
        }
}
