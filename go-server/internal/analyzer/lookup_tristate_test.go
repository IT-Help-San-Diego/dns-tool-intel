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

// TestAnalyzeSPF_TriState verifies that AnalyzeSPF distinguishes a published
// record, an authoritative absence, and a transient lookup failure (RFC 7208
// §4.6: a temperror is NOT a "none" result). A SERVFAIL must never be reported
// as a missing record.
func TestAnalyzeSPF_TriState(t *testing.T) {
        const domain = "example.com"

        tests := []struct {
                name       string
                records    []string
                status     dnsclient.LookupStatus
                wantStatus string
                wantState  string
        }{
                {
                        name:       "resolved record is present",
                        records:    []string{"v=spf1 include:_spf.google.com ~all"},
                        status:     dnsclient.LookupResolved,
                        wantStatus: "success",
                        wantState:  spfStatePresent,
                },
                {
                        name:       "authoritative absence is a real missing finding",
                        records:    nil,
                        status:     dnsclient.LookupAbsent,
                        wantStatus: "missing",
                        wantState:  spfStateAbsentConf,
                },
                {
                        name:       "transient failure is indeterminate, not missing",
                        records:    nil,
                        status:     dnsclient.LookupError,
                        wantStatus: statusIndeterminate,
                        wantState:  spfStateIndeterminate,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        mock := &statusMockDNS{
                                records: map[string][]string{domain: tt.records},
                                status:  map[string]dnsclient.LookupStatus{domain: tt.status},
                        }
                        a := &Analyzer{DNS: mock}
                        res := a.AnalyzeSPF(context.Background(), domain)

                        if got, _ := res["status"].(string); got != tt.wantStatus {
                                t.Errorf("status = %q, want %q", got, tt.wantStatus)
                        }
                        if got, _ := res[mapKeySpfState].(string); got != tt.wantState {
                                t.Errorf("spf_state = %q, want %q", got, tt.wantState)
                        }
                })
        }
}

// TestAnalyzeDMARC_TriState mirrors the SPF check for DMARC (RFC 7489 §6.6.3: a
// DNS temporary error is a TempError, never an absence of policy).
func TestAnalyzeDMARC_TriState(t *testing.T) {
        const (
                domain      = "example.com"
                dmarcDomain = "_dmarc.example.com"
        )

        tests := []struct {
                name       string
                records    []string
                status     dnsclient.LookupStatus
                wantStatus string
                wantState  string
        }{
                {
                        name:       "resolved record is present",
                        records:    []string{"v=DMARC1; p=reject; rua=mailto:r@example.com"},
                        status:     dnsclient.LookupResolved,
                        wantStatus: "success",
                        wantState:  dmarcStatePresent,
                },
                {
                        name:       "authoritative absence is a real missing finding",
                        records:    nil,
                        status:     dnsclient.LookupAbsent,
                        wantStatus: "missing",
                        wantState:  dmarcStateAbsentConf,
                },
                {
                        name:       "transient failure is indeterminate, not missing",
                        records:    nil,
                        status:     dnsclient.LookupError,
                        wantStatus: statusIndeterminate,
                        wantState:  dmarcStateIndeterminate,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        mock := &statusMockDNS{
                                records: map[string][]string{dmarcDomain: tt.records},
                                status:  map[string]dnsclient.LookupStatus{dmarcDomain: tt.status},
                        }
                        a := &Analyzer{DNS: mock}
                        res := a.AnalyzeDMARC(context.Background(), domain)

                        if got, _ := res[mapKeyStatus].(string); got != tt.wantStatus {
                                t.Errorf("status = %q, want %q", got, tt.wantStatus)
                        }
                        if got, _ := res[mapKeyDmarcState].(string); got != tt.wantState {
                                t.Errorf("dmarc_state = %q, want %q", got, tt.wantState)
                        }
                })
        }
}

// TestEvaluateState_IndeterminateExcluded confirms the posture evaluators treat
// an indeterminate SPF/DMARC result as neither configured nor absent — a
// transient failure must not be scored as a missing record.
func TestEvaluateState_IndeterminateExcluded(t *testing.T) {
        spf := map[string]any{mapKeyStatus: statusIndeterminate, mapKeySpfState: spfStateIndeterminate}
        spfOK, _, spfMissing, _, _, _, _, _ := evaluateSPFState(spf)
        if spfOK || spfMissing {
                t.Errorf("indeterminate SPF: got spfOK=%v spfMissing=%v, want both false", spfOK, spfMissing)
        }

        dmarc := map[string]any{mapKeyStatus: statusIndeterminate, mapKeyDmarcState: dmarcStateIndeterminate}
        dmarcOK, _, dmarcMissing, _, _, _ := evaluateDMARCState(dmarc)
        if dmarcOK || dmarcMissing {
                t.Errorf("indeterminate DMARC: got dmarcOK=%v dmarcMissing=%v, want both false", dmarcOK, dmarcMissing)
        }
}

// TestBuildMissingSteps_IndeterminateSuppressed confirms the remediation plan
// does not recommend publishing SPF/DMARC when the lookup was indeterminate.
func TestBuildMissingSteps_IndeterminateSuppressed(t *testing.T) {
        mf := mailFlags{spfIndet: true, dmarcIndet: true}
        steps := buildMissingSteps(mf)
        for _, s := range steps {
                if ctrl, _ := s["control"].(string); ctrl == "SPF Record" || ctrl == "DMARC Policy" {
                        t.Errorf("indeterminate should suppress %q remediation step", ctrl)
                }
        }
}

// TestEmailSpoofability_IndeterminateNotFabricated confirms a transient lookup
// failure never produces a concrete spoofability verdict. Even when DMARC
// resolves to p=reject, an indeterminate SPF measurement must yield an
// inconclusive answer — not "No — SPF and DMARC reject policy enforced" — because
// the SPF half of that claim was never verified (RFC 7208 §4.6).
func TestEmailSpoofability_IndeterminateNotFabricated(t *testing.T) {
        cases := []struct {
                name string
                ps   protocolState
        }{
                {
                        name: "spf indeterminate, dmarc reject",
                        ps:   protocolState{spfIndeterminate: true, dmarcOK: true, dmarcPolicy: mapKeyReject},
                },
                {
                        name: "dmarc indeterminate, spf present",
                        ps:   protocolState{spfOK: true, dmarcIndeterminate: true},
                },
                {
                        name: "both indeterminate",
                        ps:   protocolState{spfIndeterminate: true, dmarcIndeterminate: true},
                },
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        // hasSPF/hasDMARC are present-only in production; indeterminate
                        // yields false for both. Pass that through here.
                        hasSPF := tc.ps.spfOK && !tc.ps.spfIndeterminate
                        hasDMARC := tc.ps.dmarcOK && !tc.ps.dmarcIndeterminate

                        if cls := classifyEmailSpoofability(tc.ps, hasSPF, hasDMARC); cls != emailSpoofIndeterminate {
                                t.Errorf("classifyEmailSpoofability = %v, want emailSpoofIndeterminate", cls)
                        }

                        ans := buildEmailAnswerStructured(tc.ps, hasSPF, hasDMARC)
                        if ans[mapKeyAnswer] != "Could not verify" {
                                t.Errorf("email answer = %q, want %q", ans[mapKeyAnswer], "Could not verify")
                        }

                        verdicts := map[string]any{}
                        buildEmailVerdict(verdictInput{ps: tc.ps, hasSPF: hasSPF, hasDMARC: hasDMARC}, verdicts)
                        v, _ := verdicts[mapKeyEmailSpoofing].(map[string]any)
                        if lbl, _ := v[mapKeyLabel].(string); lbl != "Inconclusive" {
                                t.Errorf("email_spoofing label = %q, want %q", lbl, "Inconclusive")
                        }
                })
        }
}

// TestCalculatePosture_IndeterminateNotPresent confirms the end-to-end posture
// path treats an indeterminate SPF/DMARC result as not-present (hasSPF/hasDMARC
// derived present-only), so a SERVFAIL is never reported as a published record.
func TestCalculatePosture_IndeterminateNotPresent(t *testing.T) {
        results := map[string]any{
                "spf_analysis": map[string]any{
                        mapKeyStatus:   statusIndeterminate,
                        mapKeySpfState: spfStateIndeterminate,
                },
                "dmarc_analysis": map[string]any{
                        mapKeyStatus:     statusIndeterminate,
                        mapKeyDmarcState: dmarcStateIndeterminate,
                },
        }
        a := &Analyzer{}
        out := a.CalculatePosture(results)
        verdicts, _ := out["verdicts"].(map[string]any)
        if verdicts == nil {
                t.Fatal("expected verdicts in posture output")
        }
        if ans, _ := verdicts["email_answer_short"].(string); ans != "Could not verify" {
                t.Errorf("email_answer_short = %q, want %q", ans, "Could not verify")
        }
        v, _ := verdicts[mapKeyEmailSpoofing].(map[string]any)
        if lbl, _ := v[mapKeyLabel].(string); lbl != "Inconclusive" {
                t.Errorf("email_spoofing label = %q, want %q", lbl, "Inconclusive")
        }

        // The overall grade must not collapse to absence-based "unprotected"
        // critical-risk text off an unverified measurement.
        if msg, _ := out["message"].(string); strings.Contains(msg, "unprotected") || strings.Contains(msg, "No SPF or DMARC") {
                t.Errorf("grade message fabricated absence under indeterminate: %q", msg)
        }
        if st, _ := out["state"].(string); st == riskCritical {
                t.Errorf("grade state = %q (critical) under indeterminate; want non-fabricated", st)
        }
}

// TestClassifyMailGrade_IndeterminateNotCritical confirms the mail-grade path
// never returns absence-based critical risk when SPF/DMARC was indeterminate.
func TestClassifyMailGrade_IndeterminateNotCritical(t *testing.T) {
        cases := []protocolState{
                {spfIndeterminate: true},
                {dmarcIndeterminate: true},
                {spfIndeterminate: true, dmarcIndeterminate: true},
        }
        for _, ps := range cases {
                // hasSPF/hasDMARC false (present-only), as production derives them.
                state, _, _, msg := classifyMailGrade(ps, gradeInput{hasSPF: false, hasDMARC: false})
                if state == riskCritical {
                        t.Errorf("classifyMailGrade state = %q (critical) under indeterminate", state)
                }
                if strings.Contains(msg, "No SPF or DMARC") || strings.Contains(msg, "unprotected") {
                        t.Errorf("classifyMailGrade fabricated absence message: %q", msg)
                }
        }
}

// TestMailPosture_IndeterminateNotUnprotected confirms the remediation
// mail_posture JSON surface reports inconclusive — never "unprotected" — when
// SPF/DMARC could not be verified.
func TestMailPosture_IndeterminateNotUnprotected(t *testing.T) {
        cases := []mailFlags{
                {spfIndet: true},
                {dmarcIndet: true},
                {spfIndet: true, dmarcIndet: true},
        }
        for _, mf := range cases {
                if cls, label := computeMailVerdict(mf); cls != "inconclusive" || label != "Could Not Verify" {
                        t.Errorf("computeMailVerdict = (%q,%q), want (inconclusive, Could Not Verify)", cls, label)
                }
                mc := classifyMailPosture(mf, 0, "example.com", protocolState{})
                if mc.classification != "inconclusive" {
                        t.Errorf("classifyMailPosture classification = %q, want inconclusive", mc.classification)
                }
                if strings.Contains(mc.summary, "vulnerable to spoofing") {
                        t.Errorf("classifyMailPosture fabricated vulnerability summary: %q", mc.summary)
                }
        }
}
