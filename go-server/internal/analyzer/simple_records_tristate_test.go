// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "strings"
        "testing"

        "dnstool/go-server/internal/dnsclient"
)

// fabricatedAbsencePhrases are the confirmed-absence wordings that must NEVER
// appear in a verdict reason when the underlying lookup was indeterminate.
var fabricatedAbsencePhrases = []string{
        "no BIMI brand verification",
        "no CAA certificate restriction",
        "no transport enforcement policy is active",
        "adding CAA records",
}

func assertNoFabricatedAbsence(t *testing.T, reason string) {
        t.Helper()
        low := strings.ToLower(reason)
        for _, p := range fabricatedAbsencePhrases {
                if strings.Contains(low, strings.ToLower(p)) {
                        t.Errorf("verdict reason fabricates a confirmed absence for an indeterminate lookup: %q\nfound phrase: %q", reason, p)
                }
        }
        if !strings.Contains(low, "could not be verified") && !strings.Contains(low, "could not verify") {
                t.Errorf("verdict reason for an indeterminate lookup should invite a re-run, got: %q", reason)
        }
}

// These tests extend the Zero-Fabrication tri-state honesty already proven for
// SPF/DMARC/DANE/DNSSEC to the four "simple record" analyzers: BIMI, MTA-STS,
// TLS-RPT and CAA. The invariant under test: a transient DNS failure
// (SERVFAIL/timeout/REFUSED → LookupError) or an unresolved multi-resolver
// conflict (LookupConflict, DNS mid-propagation) must NEVER be reported as a
// confirmed "no record found". It must surface as statusIndeterminate with a
// tri-state of indeterminate, while an authoritative empty answer remains a real
// absent_confirmed finding. These are network-free; they drive the analyzers
// through MockDNSClient deterministically.

// simpleRecordTriCase is one row of the shared present/absent/indeterminate
// table reused by each simple-record analyzer.
type simpleRecordTriCase struct {
        name      string
        records   []string
        status    dnsclient.LookupStatus
        wantState string
        wantIndet bool // top-level status must equal statusIndeterminate
}

func simpleRecordTriCases(presentRecord string) []simpleRecordTriCase {
        return []simpleRecordTriCase{
                {
                        name:      "resolved record is present",
                        records:   []string{presentRecord},
                        status:    dnsclient.LookupResolved,
                        wantState: triStatePresent,
                        wantIndet: false,
                },
                {
                        name:      "authoritative absence is a real confirmed-absent finding",
                        records:   nil,
                        status:    dnsclient.LookupAbsent,
                        wantState: triStateAbsentConf,
                        wantIndet: false,
                },
                {
                        name:      "transient failure is indeterminate, not absent",
                        records:   nil,
                        status:    dnsclient.LookupError,
                        wantState: triStateIndeterminate,
                        wantIndet: true,
                },
                {
                        name:      "resolver conflict is indeterminate, not absent",
                        records:   nil,
                        status:    dnsclient.LookupConflict,
                        wantState: triStateIndeterminate,
                        wantIndet: true,
                },
        }
}

// assertSimpleRecordTri checks the tri-state contract for one analyzer result.
func assertSimpleRecordTri(t *testing.T, res map[string]any, stateKey string, tc simpleRecordTriCase) {
        t.Helper()
        if got, _ := res[stateKey].(string); got != tc.wantState {
                t.Errorf("%s = %q, want %q", stateKey, got, tc.wantState)
        }
        gotStatus, _ := res[mapKeyStatus].(string)
        if tc.wantIndet && gotStatus != statusIndeterminate {
                t.Errorf("status = %q, want %q (transient/conflict must not fabricate absence)", gotStatus, statusIndeterminate)
        }
        if !tc.wantIndet && gotStatus == statusIndeterminate {
                t.Errorf("status = %q, must NOT be indeterminate for a resolved/authoritative answer", gotStatus)
        }
}

func TestAnalyzeBIMI_TriState(t *testing.T) {
        const domain = "example.com"
        const fqdn = "default._bimi.example.com"
        // A v=BIMI1 record with no l= keeps the present case network-free (no logo
        // fetch); the tri-state is set on the success path regardless of logo status.
        for _, tc := range simpleRecordTriCases("v=BIMI1;") {
                t.Run(tc.name, func(t *testing.T) {
                        mock := NewMockDNSClient()
                        mock.AddStatusResponse("TXT", fqdn, tc.records, tc.status)
                        a := &Analyzer{DNS: mock, HTTP: NewMockHTTPClient()}
                        res := a.AnalyzeBIMI(context.Background(), domain)
                        assertSimpleRecordTri(t, res, mapKeyBimiState, tc)
                })
        }
}

func TestAnalyzeMTASTS_TriState(t *testing.T) {
        const domain = "example.com"
        const fqdn = "_mta-sts.example.com"
        for _, tc := range simpleRecordTriCases("v=STSv1; id=20240101000000Z;") {
                t.Run(tc.name, func(t *testing.T) {
                        mock := NewMockDNSClient()
                        mock.AddStatusResponse("TXT", fqdn, tc.records, tc.status)
                        // HTTP mock present so the policy fetch on the resolved path cannot
                        // nil-panic; an unconfigured URL returns an error, which the analyzer
                        // handles gracefully while still publishing the present tri-state.
                        a := &Analyzer{DNS: mock, HTTP: NewMockHTTPClient()}
                        res := a.AnalyzeMTASTS(context.Background(), domain)
                        assertSimpleRecordTri(t, res, mapKeyMtaStsState, tc)
                })
        }
}

func TestAnalyzeTLSRPT_TriState(t *testing.T) {
        const domain = "example.com"
        const fqdn = "_smtp._tls.example.com"
        for _, tc := range simpleRecordTriCases("v=TLSRPTv1; rua=mailto:tlsrpt@example.com") {
                t.Run(tc.name, func(t *testing.T) {
                        mock := NewMockDNSClient()
                        mock.AddStatusResponse("TXT", fqdn, tc.records, tc.status)
                        a := &Analyzer{DNS: mock}
                        res := a.AnalyzeTLSRPT(context.Background(), domain)
                        assertSimpleRecordTri(t, res, mapKeyTlsrptState, tc)
                })
        }
}

func TestAnalyzeCAA_TriState(t *testing.T) {
        const domain = "example.com"
        for _, tc := range simpleRecordTriCases(`0 issue "letsencrypt.org"`) {
                t.Run(tc.name, func(t *testing.T) {
                        mock := NewMockDNSClient()
                        mock.AddStatusResponse("CAA", domain, tc.records, tc.status)
                        a := &Analyzer{DNS: mock}
                        res := a.AnalyzeCAA(context.Background(), domain)
                        assertSimpleRecordTri(t, res, mapKeyCaaState, tc)
                })
        }
}

// TestSimpleProtocolIndeterminate confirms the posture-layer reader only treats
// an explicit indeterminate tri-state as indeterminate — a present/absent state,
// a missing key, or a nil result must all read as not-indeterminate.
func TestSimpleProtocolIndeterminate(t *testing.T) {
        cases := []struct {
                name   string
                result map[string]any
                want   bool
        }{
                {"nil result", nil, false},
                {"missing state key", map[string]any{mapKeyStatus: "warning"}, false},
                {"present", map[string]any{mapKeyCaaState: triStatePresent}, false},
                {"absent_confirmed", map[string]any{mapKeyCaaState: triStateAbsentConf}, false},
                {"indeterminate", map[string]any{mapKeyCaaState: triStateIndeterminate}, true},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        if got := simpleProtocolIndeterminate(tc.result, mapKeyCaaState); got != tc.want {
                                t.Errorf("simpleProtocolIndeterminate = %v, want %v", got, tc.want)
                        }
                })
        }
}

// TestClassifyPresenceTri_IndeterminateRoutesToMonitoring locks the core fix:
// an indeterminate simple-protocol lookup is routed to the monitoring bucket
// ("could not verify"), never to the absent bucket — so a transient DNS failure
// can never be reported as a confirmed missing control.
func TestClassifyPresenceTri_IndeterminateRoutesToMonitoring(t *testing.T) {
        t.Run("indeterminate goes to monitoring, not absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyPresenceTri(false, true, "CAA", acc)
                for _, a := range acc.absent {
                        if a == "CAA" {
                                t.Fatalf("indeterminate CAA wrongly classified as absent: %v", acc.absent)
                        }
                }
                if len(acc.monitoring) != 1 {
                        t.Fatalf("monitoring = %v, want one could-not-verify entry", acc.monitoring)
                }
                if len(acc.unmeasurable) != 1 || acc.unmeasurable[0] != "CAA" {
                        t.Fatalf("unmeasurable = %v, want [CAA] (surfaced loudly as excluded from the score)", acc.unmeasurable)
                }
        })

        t.Run("authoritative absence still goes to absent", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyPresenceTri(false, false, "CAA", acc)
                if len(acc.absent) != 1 || acc.absent[0] != "CAA" {
                        t.Fatalf("absent = %v, want [CAA] (a real absence must still be reported)", acc.absent)
                }
        })

        t.Run("present goes to configured", func(t *testing.T) {
                acc := &postureAccumulator{}
                classifyPresenceTri(true, false, "CAA", acc)
                if len(acc.configured) != 1 || acc.configured[0] != "CAA" {
                        t.Fatalf("configured = %v, want [CAA]", acc.configured)
                }
        })
}

// TestBuildCAAVerdict_Indeterminate confirms an indeterminate CAA lookup yields a
// "Could Not Verify" certificate-control verdict, never a fabricated
// "any CA can issue" absence verdict.
func TestBuildCAAVerdict_Indeterminate(t *testing.T) {
        verdicts := map[string]any{}
        buildCAAVerdict(protocolState{caaIndeterminate: true}, verdicts)
        v, _ := verdicts["certificate_control"].(map[string]any)
        if v == nil {
                t.Fatal("expected certificate_control verdict")
        }
        if lbl, _ := v[mapKeyLabel].(string); lbl != "Could Not Verify" {
                t.Errorf("certificate_control label = %q, want %q", lbl, "Could Not Verify")
        }
        if ans, _ := v[mapKeyAnswer].(string); ans != "Unknown" {
                t.Errorf("certificate_control answer = %q, want %q", ans, "Unknown")
        }
}

// TestBuildTransportVerdict_Indeterminate confirms an indeterminate MTA-STS or
// TLS-RPT lookup yields a "Could Not Verify" transport verdict instead of
// "Not Enforced" — a failed measurement must not collapse into an absence claim.
func TestBuildTransportVerdict_Indeterminate(t *testing.T) {
        cases := []struct {
                name string
                ps   protocolState
        }{
                {"mta-sts indeterminate", protocolState{mtaStsIndeterminate: true}},
                {"tls-rpt indeterminate", protocolState{tlsrptIndeterminate: true}},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        verdicts := map[string]any{}
                        buildTransportVerdict(tc.ps, verdicts)
                        v, _ := verdicts[mapKeyTransport].(map[string]any)
                        if v == nil {
                                t.Fatal("expected transport verdict")
                        }
                        if lbl, _ := v[mapKeyLabel].(string); lbl != "Could Not Verify" {
                                t.Errorf("transport label = %q, want %q", lbl, "Could Not Verify")
                        }
                })
        }
}

// TestCalculatePosture_SimpleProtocolIndeterminate is the end-to-end guard: when
// the CAA analyzer reports indeterminate, the overall posture must NOT list CAA
// among absent controls and must render a "Could Not Verify" certificate verdict.
func TestCalculatePosture_SimpleProtocolIndeterminate(t *testing.T) {
        results := map[string]any{
                "caa_analysis": map[string]any{
                        mapKeyStatus:   statusIndeterminate,
                        mapKeyCaaState: triStateIndeterminate,
                },
                "mta_sts_analysis": map[string]any{
                        mapKeyStatus:      statusIndeterminate,
                        mapKeyMtaStsState: triStateIndeterminate,
                },
        }
        a := &Analyzer{}
        out := a.CalculatePosture(results)

        absent, _ := out["absent"].([]string)
        for _, name := range absent {
                if name == "CAA" || name == protocolMTASTS {
                        t.Errorf("indeterminate control %q wrongly listed as absent: %v", name, absent)
                }
        }

        verdicts, _ := out["verdicts"].(map[string]any)
        if verdicts == nil {
                t.Fatal("expected verdicts in posture output")
        }
        if cc, _ := verdicts["certificate_control"].(map[string]any); cc != nil {
                if lbl, _ := cc[mapKeyLabel].(string); lbl != "Could Not Verify" {
                        t.Errorf("certificate_control label = %q, want %q", lbl, "Could Not Verify")
                }
        } else {
                t.Error("expected certificate_control verdict under indeterminate CAA")
        }
}

// TestBuildTransportVerdict_MTAStsIndeterminateWithTLSRPTPresent guards the
// precedence fix: an MTA-STS lookup that did not complete must NOT be downgraded
// to a "monitoring only / no enforcement" verdict just because TLS-RPT exists —
// an enforcing MTA-STS policy may be present, so the honest answer is "could not
// verify", not a fabricated absence of enforcement.
func TestBuildTransportVerdict_MTAStsIndeterminateWithTLSRPTPresent(t *testing.T) {
        verdicts := map[string]any{}
        buildTransportVerdict(protocolState{mtaStsIndeterminate: true, tlsrptOK: true}, verdicts)
        v, _ := verdicts[mapKeyTransport].(map[string]any)
        if v == nil {
                t.Fatal("expected transport verdict")
        }
        if lbl, _ := v[mapKeyLabel].(string); lbl != "Could Not Verify" {
                t.Errorf("transport label = %q, want %q", lbl, "Could Not Verify")
        }
        reason, _ := v[mapKeyReason].(string)
        if strings.Contains(strings.ToLower(reason), "no transport enforcement policy is active") {
                t.Errorf("transport reason fabricates absence of enforcement under indeterminate MTA-STS: %q", reason)
        }
}

// TestBuildTransportVerdict_DANEOverridesMTAStsIndeterminate confirms a real
// positive signal still wins: when DANE enforces transport, an indeterminate
// MTA-STS lookup must not downgrade the verdict to "could not verify".
func TestBuildTransportVerdict_DANEOverridesMTAStsIndeterminate(t *testing.T) {
        verdicts := map[string]any{}
        buildTransportVerdict(protocolState{mtaStsIndeterminate: true, daneOK: true}, verdicts)
        v, _ := verdicts[mapKeyTransport].(map[string]any)
        if lbl, _ := v[mapKeyLabel].(string); lbl == "Could Not Verify" {
                t.Errorf("DANE enforcement should yield a protected verdict, got %q", lbl)
        }
}

// TestBuildBrandVerdict_BimiCaaIndeterminate locks the brand-impersonation
// verdicts: under DMARC reject/quarantine, an indeterminate BIMI or CAA lookup
// must read "could not be verified", never a confirmed "no BIMI"/"no CAA".
func TestBuildBrandVerdict_BimiCaaIndeterminate(t *testing.T) {
        builders := map[string]func(protocolState) map[string]any{
                "reject":     buildBrandRejectVerdict,
                "quarantine": buildBrandQuarantineVerdict,
        }
        states := map[string]protocolState{
                "bimi indeterminate, caa absent": {bimiIndeterminate: true},
                "caa indeterminate, bimi absent": {caaIndeterminate: true},
                "both indeterminate":             {bimiIndeterminate: true, caaIndeterminate: true},
                "caa present, bimi indeterminate": {caaOK: true, bimiIndeterminate: true},
                "bimi present, caa indeterminate": {bimiOK: true, caaIndeterminate: true},
        }
        for bName, build := range builders {
                for sName, ps := range states {
                        t.Run(bName+"/"+sName, func(t *testing.T) {
                                v := build(ps)
                                reason, _ := v[mapKeyReason].(string)
                                low := strings.ToLower(reason)
                                if ps.bimiIndeterminate && strings.Contains(low, "no bimi brand verification") {
                                        t.Errorf("fabricated 'no BIMI' under indeterminate BIMI: %q", reason)
                                }
                                if ps.caaIndeterminate {
                                        if strings.Contains(low, "no caa certificate restriction") {
                                                t.Errorf("fabricated 'no CAA' under indeterminate CAA: %q", reason)
                                        }
                                        if strings.Contains(low, "adding caa records") {
                                                t.Errorf("suggested adding CAA under indeterminate CAA (may already exist): %q", reason)
                                        }
                                }
                                if (ps.bimiIndeterminate || ps.caaIndeterminate) && !strings.Contains(low, "could not be verified") {
                                        t.Errorf("indeterminate brand reason should say 'could not be verified': %q", reason)
                                }
                        })
                }
        }
}

// TestCalculatePosture_TransportAndBrandIndeterminate is the end-to-end guard for
// the remaining simple protocols: an indeterminate TLS-RPT and BIMI must not be
// listed among absent controls, and the transport verdict must read
// "Could Not Verify" rather than "Not Enforced".
func TestCalculatePosture_TransportAndBrandIndeterminate(t *testing.T) {
        results := map[string]any{
                "tlsrpt_analysis": map[string]any{
                        mapKeyStatus:      statusIndeterminate,
                        mapKeyTlsrptState: triStateIndeterminate,
                },
                "bimi_analysis": map[string]any{
                        mapKeyStatus:    statusIndeterminate,
                        mapKeyBimiState: triStateIndeterminate,
                },
        }
        a := &Analyzer{}
        out := a.CalculatePosture(results)

        absent, _ := out["absent"].([]string)
        for _, name := range absent {
                if name == protocolTLSRPT || name == "BIMI" {
                        t.Errorf("indeterminate control %q wrongly listed as absent: %v", name, absent)
                }
        }

        verdicts, _ := out["verdicts"].(map[string]any)
        if tv, _ := verdicts[mapKeyTransport].(map[string]any); tv != nil {
                if lbl, _ := tv[mapKeyLabel].(string); lbl == "Not Enforced" {
                        t.Errorf("transport verdict claims 'Not Enforced' under indeterminate TLS-RPT: %v", tv)
                }
        }
}
