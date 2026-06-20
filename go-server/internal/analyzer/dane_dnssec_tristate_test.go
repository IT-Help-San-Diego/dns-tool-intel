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

// These tests are network-free: they drive AnalyzeDANE / AnalyzeDNSSEC and
// ComputePostureDiff through MockDNSClient so the DANE/DNSSEC tri-state
// (present / absent_confirmed / indeterminate) is exercised deterministically.
// They are the regression guard for the false-drift-flapping fix (a transient
// lookup failure must read as "could not verify", never as posture change).

const (
        triStateMX       = "mail.tristate-example.test"
        triStateTLSAName = "_25._tcp." + triStateMX
        triStateDomain   = "tristate-example.test"
)

func newTriStateMX() []string { return []string{"10 " + triStateMX + "."} }

func TestAnalyzeDANE_TriState_Present(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", triStateTLSAName,
                dnsclient.RecordWithTTL{Records: []string{"3 1 1 abcdef0123456789"}, Authenticated: true},
                dnsclient.LookupResolved)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, newTriStateMX())

        if got := result["dane_state"]; got != daneStatePresent {
                t.Fatalf("dane_state = %v, want %s", got, daneStatePresent)
        }
        if got, _ := result["has_dane"].(bool); !got {
                t.Fatalf("has_dane = %v, want true", result["has_dane"])
        }
}

func TestAnalyzeDANE_TriState_AbsentConfirmed(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", triStateTLSAName,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, newTriStateMX())

        if got := result["dane_state"]; got != daneStateAbsentConf {
                t.Fatalf("dane_state = %v, want %s", got, daneStateAbsentConf)
        }
        if got, _ := result["has_dane"].(bool); got {
                t.Fatalf("has_dane = %v, want false", result["has_dane"])
        }
}

func TestAnalyzeDANE_TriState_Indeterminate(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", triStateTLSAName,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, newTriStateMX())

        if got := result["dane_state"]; got != daneStateIndeterminate {
                t.Fatalf("dane_state = %v, want %s", got, daneStateIndeterminate)
        }
        if got, _ := result["has_dane"].(bool); got {
                t.Fatalf("has_dane = %v, want false (transient failure is not presence)", result["has_dane"])
        }
        indet, _ := result["indeterminate_hosts"].([]string)
        if len(indet) != 1 || indet[0] != triStateMX {
                t.Fatalf("indeterminate_hosts = %v, want [%s]", result["indeterminate_hosts"], triStateMX)
        }
}

// TestAnalyzeDANE_ProviderNoInbound_TransientIsIndeterminate locks the Zero
// Fabrication rule: even for a provider that does not support inbound DANE (e.g.
// Microsoft 365), a TRANSIENT TLSA lookup failure must report indeterminate
// ("could not verify"), NOT a fabricated confirmed-absence. Provider capability
// is advisory deployment context only — it must never override a failed
// measurement into an absence verdict (RFC 6698 §1).
func TestAnalyzeDANE_ProviderNoInbound_TransientIsIndeterminate(t *testing.T) {
        const m365MX = "example-com.mail.protection.outlook.com"
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", "_25._tcp."+m365MX,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, []string{"10 " + m365MX + "."})

        if got := result["dane_state"]; got != daneStateIndeterminate {
                t.Fatalf("dane_state = %v, want %s (transient TLSA failure must be indeterminate even for a no-inbound-DANE provider)", got, daneStateIndeterminate)
        }
}

// TestAnalyzeDANE_ProviderNoInbound_AuthoritativeAbsentConfirmed verifies the
// legitimate confirmed-absence path is still reachable: when the TLSA lookup
// returns an AUTHORITATIVE no-record (LookupAbsent), absence is real and the
// state is absent_confirmed — derived from the resolver answer, not the provider.
func TestAnalyzeDANE_ProviderNoInbound_AuthoritativeAbsentConfirmed(t *testing.T) {
        const m365MX = "example-com.mail.protection.outlook.com"
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", "_25._tcp."+m365MX,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, []string{"10 " + m365MX + "."})

        if got := result["dane_state"]; got != daneStateAbsentConf {
                t.Fatalf("dane_state = %v, want %s (authoritative no-record is a real confirmed absence)", got, daneStateAbsentConf)
        }
}

func TestAnalyzeDNSSEC_TriState_Present(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}, Authenticated: true},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"12345 13 2 abc123"}},
                dnsclient.LookupResolved)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStatePresent {
                t.Fatalf("dnssec_state = %v, want %s", got, dnssecStatePresent)
        }
}

func TestAnalyzeDNSSEC_TriState_AbsentConfirmed(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateAbsentConf {
                t.Fatalf("dnssec_state = %v, want %s", got, dnssecStateAbsentConf)
        }
}

func TestAnalyzeDNSSEC_TriState_Indeterminate(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (transient lookup must not read as unsigned)", got, dnssecStateIndeterminate)
        }
        if got := result[mapKeyStatus]; got != statusUnknown {
                t.Fatalf("status = %v, want %s", got, statusUnknown)
        }
}

// TestAnalyzeDNSSEC_TriState_MixedErrorAbsent locks the mixed-status invariant:
// a single transient lookup (DNSKEY errored) with the other authoritatively
// absent and no AD flag must read as indeterminate — one failed probe means we
// genuinely cannot assert "unsigned".
func TestAnalyzeDNSSEC_TriState_MixedErrorAbsent(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (one errored lookup means we cannot assert unsigned)", got, dnssecStateIndeterminate)
        }
        if got := result[mapKeyStatus]; got != statusUnknown {
                t.Fatalf("status = %v, want %s", got, statusUnknown)
        }
}

// TestAnalyzeDNSSEC_TriState_MixedDNSKEYErrorDSResolved locks the regression the
// code review flagged: DNSKEY lookup errored transiently while DS resolved, with
// no AD flag. The old guard required !hasDNSKEY && !hasDS, so this mixed case fell
// through to buildDNSSECResult and was fabricated as "DNSSEC not configured"
// (absent_confirmed). A single errored half means we cannot assert unsigned.
func TestAnalyzeDNSSEC_TriState_MixedDNSKEYErrorDSResolved(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"12345 13 2 abc123"}},
                dnsclient.LookupResolved)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (DNSKEY errored — must not read as 'not configured')", got, dnssecStateIndeterminate)
        }
        if got := result[mapKeyStatus]; got != statusUnknown {
                t.Fatalf("status = %v, want %s", got, statusUnknown)
        }
}

// TestAnalyzeDNSSEC_TriState_MixedDSErrorDNSKEYResolved is the partner case: DS
// lookup errored transiently while DNSKEY resolved, no AD flag. The old guard let
// this reach buildDNSSECResult's hasDNSKEY && !hasDS branch and fabricate "DNSSEC
// partially configured — DS record missing at registrar". A transient DS failure
// is not evidence the DS is missing at the registrar.
func TestAnalyzeDNSSEC_TriState_MixedDSErrorDNSKEYResolved(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (DS errored — must not read as 'DS missing at registrar')", got, dnssecStateIndeterminate)
        }
        if msg, _ := result[mapKeyMessage].(string); strings.Contains(msg, "missing at registrar") {
                t.Fatalf("fabricated DS-absence message under transient DS failure: %q", msg)
        }
}

// TestComputePostureDiff_SuppressesIndeterminateFlapping is the core regression
// guard: a present → indeterminate → present sequence must produce zero drift
// events, because the indeterminate scan is an incomplete probe, not a change.
func TestComputePostureDiff_SuppressesIndeterminateFlapping(t *testing.T) {
        present := map[string]any{
                mapKeyDaneAnalysis: map[string]any{
                        mapKeyStatus: "success",
                        "dane_state": daneStatePresent,
                        "has_dane":   true,
                },
                "dnssec_analysis": map[string]any{
                        mapKeyStatus:      "success",
                        mapKeyDnssecState: dnssecStatePresent,
                },
        }
        indeterminate := map[string]any{
                mapKeyDaneAnalysis: map[string]any{
                        mapKeyStatus: statusUnknown,
                        "dane_state": daneStateIndeterminate,
                        "has_dane":   false,
                },
                "dnssec_analysis": map[string]any{
                        mapKeyStatus:      statusUnknown,
                        mapKeyDnssecState: dnssecStateIndeterminate,
                },
        }

        if diffs := ComputePostureDiff(present, indeterminate); len(diffs) != 0 {
                t.Fatalf("present→indeterminate produced %d drift fields, want 0: %+v", len(diffs), diffs)
        }
        if diffs := ComputePostureDiff(indeterminate, present); len(diffs) != 0 {
                t.Fatalf("indeterminate→present produced %d drift fields, want 0: %+v", len(diffs), diffs)
        }
}

// TestComputePostureDiff_RealTransitionStillDrifts confirms the suppression is
// scoped: an authoritatively-confirmed present → absent transition (no
// indeterminate on either side) must still surface as drift.
func TestComputePostureDiff_RealTransitionStillDrifts(t *testing.T) {
        present := map[string]any{
                mapKeyDaneAnalysis: map[string]any{
                        mapKeyStatus: "success",
                        "dane_state": daneStatePresent,
                        "has_dane":   true,
                },
        }
        absent := map[string]any{
                mapKeyDaneAnalysis: map[string]any{
                        mapKeyStatus: "warning",
                        "dane_state": daneStateAbsentConf,
                        "has_dane":   false,
                },
        }

        diffs := ComputePostureDiff(present, absent)
        if len(diffs) == 0 {
                t.Fatal("present→absent_confirmed produced 0 drift fields, want a real drift event")
        }
}

// TestEvaluateDNSSECState_Indeterminate verifies a transient DNSSEC lookup
// (dnssec_state=indeterminate, status=unknown) is classified as neither OK nor
// broken — it sets the dedicated indeterminate flag so downstream posture stays
// neutral and never reads the zone as unsigned (RFC 4035).
func TestEvaluateDNSSECState_Indeterminate(t *testing.T) {
        var ps protocolState
        evaluateDNSSECState(map[string]any{
                mapKeyStatus:      statusUnknown,
                mapKeyDnssecState: dnssecStateIndeterminate,
        }, &ps)

        if !ps.dnssecIndeterminate {
                t.Fatal("dnssecIndeterminate = false, want true for dnssec_state=indeterminate")
        }
        if ps.dnssecOK || ps.dnssecBroken {
                t.Fatalf("indeterminate must be neither OK nor broken; got dnssecOK=%v dnssecBroken=%v", ps.dnssecOK, ps.dnssecBroken)
        }
}

// TestClassifyDNSSEC_IndeterminateNotAbsent locks the core honesty rule: an
// inconclusive DNSSEC lookup must NOT land in the "absent" list (which renders as
// a missing/unsigned finding). It surfaces as a neutral monitoring note instead.
func TestClassifyDNSSEC_IndeterminateNotAbsent(t *testing.T) {
        acc := &postureAccumulator{}
        classifyDNSSEC(protocolState{dnssecIndeterminate: true}, acc)

        for _, a := range acc.absent {
                if a == "DNSSEC" {
                        t.Fatal("indeterminate DNSSEC was added to absent list — must stay inconclusive, not a finding")
                }
        }
        if len(acc.monitoring) == 0 {
                t.Fatal("indeterminate DNSSEC produced no neutral monitoring note")
        }
}

// TestBuildDNSVerdict_IndeterminateNotMissing verifies the DNS-tampering verdict
// for inconclusive DNSSEC reads "Could Not Verify" (neutral), never the
// "Not Configured / not deployed" absence verdict.
func TestBuildDNSVerdict_IndeterminateNotMissing(t *testing.T) {
        verdicts := map[string]any{}
        buildDNSVerdict(protocolState{dnssecIndeterminate: true}, verdicts)

        v, ok := verdicts[mapKeyDnsTampering].(map[string]any)
        if !ok {
                t.Fatal("no dns_tampering verdict produced")
        }
        if got := v[mapKeyLabel]; got != "Could Not Verify" {
                t.Fatalf("label = %v, want \"Could Not Verify\" (must not assert Not Configured)", got)
        }
        if got, _ := v[mapKeyReason].(string); strings.Contains(got, "not deployed") {
                t.Fatalf("verdict reason fabricates absence: %q", got)
        }
}

// TestClassifyRegistryGrade_IndeterminateNotUnsigned verifies the registry-zone
// grade for inconclusive DNSSEC does not assert "not DNSSEC-signed".
func TestClassifyRegistryGrade_IndeterminateNotUnsigned(t *testing.T) {
        _, _, _, msg := classifyRegistryGrade(protocolState{dnssecIndeterminate: true}, gradeInput{})
        if strings.Contains(msg, "not DNSSEC-signed") {
                t.Fatalf("registry grade fabricates absence for inconclusive DNSSEC: %q", msg)
        }
        if !strings.Contains(msg, "could not be verified") {
                t.Fatalf("registry grade should report inconclusive; got %q", msg)
        }
}
