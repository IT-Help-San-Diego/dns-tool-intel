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

// parent-authoritative DS confirmation fixtures. parentZoneFromDomain(triStateDomain)
// is "test"; the analyzer resolves the parent NS, then its A record, then queries
// DS for the child directly at that parent IP with recursion disabled.
const (
        triStateParentNS = "a.nic.test"
        triStateParentIP = "192.0.2.53"
)

func addParentNS(m *MockDNSClient) {
        m.AddResponse("NS", "test", []string{triStateParentNS + "."})
        m.AddResponse("A", triStateParentNS, []string{triStateParentIP})
}

// TestAnalyzeDNSSEC_FalseAbsentDS_ConfirmedPresentAtParent locks the core
// Zero-Fabrication fix: DNSKEY is present but the recursive/consensus DS lookup
// returned a (false) authoritative-absent, with no AD flag. The analyzer must NOT
// declare "DS missing at registrar" — it must confirm at the parent, find the DS,
// and report a complete chain (RFC 4035 §3.2.3, RFC 6781 §4.2.2).
func TestAnalyzeDNSSEC_FalseAbsentDS_ConfirmedPresentAtParent(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        addParentNS(mockDNS)
        mockDNS.AddSpecificResolverResponse("DS", triStateDomain, triStateParentIP,
                []string{"12345 13 2 abc123"})
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStatePresent {
                t.Fatalf("dnssec_state = %v, want %s (DS confirmed present at parent — must not read as broken)", got, dnssecStatePresent)
        }
        if got := result[mapKeyChainOfTrust]; got != "complete" {
                t.Fatalf("chain_of_trust = %v, want complete", got)
        }
        if got, _ := result[mapKeyHasDs].(bool); !got {
                t.Fatalf("has_ds = %v, want true (DS adopted from authoritative parent answer)", result[mapKeyHasDs])
        }
}

// TestAnalyzeDNSSEC_ConfirmedNoDS_IslandOfSecurity verifies the genuine broken
// chain is still surfaced: DNSKEY present, no DS via consensus, and the parent's
// authoritative servers confirm there is truly no DS. This is a real island of
// security (RFC 6781 §4.2.2) — chain_of_trust=broken — but dnssec_state must be
// "partial" (signed zone, incomplete chain), never the contradictory "present".
func TestAnalyzeDNSSEC_ConfirmedNoDS_IslandOfSecurity(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        addParentNS(mockDNS)
        mockDNS.AddSpecificResolverResponse("DS", triStateDomain, triStateParentIP, []string{})
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStatePartial {
                t.Fatalf("dnssec_state = %v, want %s (signed zone, DS confirmed absent at parent)", got, dnssecStatePartial)
        }
        if got := result[mapKeyChainOfTrust]; got != "broken" {
                t.Fatalf("chain_of_trust = %v, want broken (authoritatively confirmed island of security)", got)
        }
        if got, _ := result[mapKeyHasDs].(bool); got {
                t.Fatalf("has_ds = %v, want false", result[mapKeyHasDs])
        }
}

// TestAnalyzeDNSSEC_DSUnconfirmable_Indeterminate locks the honesty rule: DNSKEY
// present, no DS via consensus, no AD flag, and the parent cannot be reached to
// confirm (NS discovery fails). Absence is only assertable from an authoritative
// answer (RFC 4035) — so an unconfirmable DS must read as indeterminate ("could
// not verify"), never a fabricated "DS missing at registrar".
func TestAnalyzeDNSSEC_DSUnconfirmable_Indeterminate(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        // No parent NS configured: queryParentAuthoritativeDS cannot confirm.
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (parent unreachable — must not assert broken/absent)", got, dnssecStateIndeterminate)
        }
        if got := result[mapKeyStatus]; got != statusUnknown {
                t.Fatalf("status = %v, want %s", got, statusUnknown)
        }
        if msg, _ := result[mapKeyMessage].(string); strings.Contains(msg, "missing at registrar") {
                t.Fatalf("fabricated DS-absence message when parent was unconfirmable: %q", msg)
        }
}

// TestAnalyzeDNSSEC_DSParentServfail_Indeterminate locks the blocking gap the
// architect flagged: the parent IS reachable, but its authoritative server answers
// the DS query with SERVFAIL. A SERVFAIL carries no answer section, so the old
// (records, error) path folded it into a (false) confirmed absence. Per RFC 4035
// §3.2.3 absence is only assertable from an authoritative answer — a server-failure
// must read as indeterminate ("could not verify"), never "DS missing at registrar".
func TestAnalyzeDNSSEC_DSParentServfail_Indeterminate(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        addParentNS(mockDNS)
        // Parent authoritative server returns SERVFAIL (no answer, not an absence).
        mockDNS.AddSpecificResolverAuthResponse("DS", triStateDomain, triStateParentIP,
                nil, false, "SERVFAIL")
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (parent SERVFAIL — must not assert broken/absent)", got, dnssecStateIndeterminate)
        }
        if msg, _ := result[mapKeyMessage].(string); strings.Contains(msg, "missing at registrar") {
                t.Fatalf("fabricated DS-absence message on parent SERVFAIL: %q", msg)
        }
}

// TestAnalyzeDNSSEC_DSParentNonAuthoritative_Indeterminate locks the AA-bit guard:
// the parent query returns a clean NOERROR with an empty answer (NODATA shape) but
// the AA bit is NOT set, meaning the responder was not authoritative for the parent
// zone (e.g. a recursive cache hop). An empty answer from a non-authoritative
// responder cannot prove the DS is absent (RFC 4035 §3.2.3) — it must read as
// indeterminate, never a confirmed island of security.
func TestAnalyzeDNSSEC_DSParentNonAuthoritative_Indeterminate(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("DNSKEY", triStateDomain,
                dnsclient.RecordWithTTL{Records: []string{"257 3 13 mIIBI..."}},
                dnsclient.LookupResolved)
        mockDNS.AddTTLStatusResponse("DS", triStateDomain,
                dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent)
        addParentNS(mockDNS)
        // NOERROR + empty answer but AA=0: not an authoritative absence.
        mockDNS.AddSpecificResolverAuthResponse("DS", triStateDomain, triStateParentIP,
                []string{}, false, "")
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDNSSEC(context.Background(), triStateDomain)

        if got := result[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Fatalf("dnssec_state = %v, want %s (non-authoritative empty answer — must not assert absent)", got, dnssecStateIndeterminate)
        }
        if got := result[mapKeyChainOfTrust]; got == "broken" {
                t.Fatalf("chain_of_trust = broken fabricated from a non-authoritative empty parent answer")
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

// TestComputeInternalScore_IndeterminateNeutral verifies available-denominator
// normalization: a transient SPF/DMARC lookup failure earns neither presence
// points nor an absence penalty. Its weight is removed from BOTH the earned
// points and the denominator, so an otherwise-perfect posture still scores 100
// (judgment and analytic confidence are separate axes; RFC 7208 / RFC 7489).
func TestComputeInternalScore_IndeterminateNeutral(t *testing.T) {
        spfIndet := protocolState{
                spfIndeterminate: true,
                dmarcOK:          true, dmarcPolicy: "reject",
                dnssecOK: true, daneOK: true, mtaStsOK: true,
                tlsrptOK: true, caaOK: true, bimiOK: true,
        }
        if got := computeInternalScore(spfIndet, DKIMSuccess); got != 100 {
                t.Errorf("SPF indeterminate + otherwise perfect: score = %d, want 100 (no penalty for an unmeasurable protocol)", got)
        }

        dmarcIndet := protocolState{
                spfOK: true, spfHardFail: true,
                dmarcIndeterminate: true,
                dnssecOK:           true, daneOK: true, mtaStsOK: true,
                tlsrptOK: true, caaOK: true, bimiOK: true,
        }
        if got := computeInternalScore(dmarcIndet, DKIMSuccess); got != 100 {
                t.Errorf("DMARC indeterminate + otherwise perfect: score = %d, want 100", got)
        }
}

// TestComputeInternalScore_IndeterminateBeatsMissing locks the core asymmetry: an
// indeterminate SPF (could-not-measure) must score strictly HIGHER than a
// confirmed-missing SPF on the same otherwise-identical posture, because a missing
// record is a real absence penalty while an unmeasurable one is not.
func TestComputeInternalScore_IndeterminateBeatsMissing(t *testing.T) {
        withRest := func(spf protocolState) protocolState {
                spf.dmarcMissing = true
                spf.dnssecOK = true
                spf.daneOK = true
                spf.mtaStsOK = true
                spf.tlsrptOK = true
                spf.caaOK = true
                spf.bimiOK = true
                return spf
        }
        indeterminate := computeInternalScore(withRest(protocolState{spfIndeterminate: true}), DKIMSuccess)
        missing := computeInternalScore(withRest(protocolState{spfMissing: true}), DKIMSuccess)
        if indeterminate <= missing {
                t.Errorf("indeterminate SPF (%d) must score higher than missing SPF (%d)", indeterminate, missing)
        }
}

// TestComputeScore_IndeterminateRawIsZero verifies the per-protocol raw score is 0
// for an indeterminate measurement (neutrality comes from denominator removal in
// computeInternalScore, not from awarding phantom presence points).
func TestComputeScore_IndeterminateRawIsZero(t *testing.T) {
        if got := computeSPFScore(protocolState{spfIndeterminate: true}); got != 0 {
                t.Errorf("indeterminate SPF raw score = %d, want 0 (no phantom presence credit)", got)
        }
        if got := computeDMARCScore(protocolState{dmarcIndeterminate: true}); got != 0 {
                t.Errorf("indeterminate DMARC raw score = %d, want 0 (no phantom presence credit)", got)
        }
}

// TestClassifyNoMailGrade_Indeterminate verifies a no-mail domain with a transient
// SPF/DMARC failure is NOT graded as "missing"/"no records" — it returns an
// explicit could-not-verify medium grade, mirroring classifyRegistryGrade.
func TestClassifyNoMailGrade_Indeterminate(t *testing.T) {
        state, _, _, msg := classifyNoMailGrade(protocolState{spfIndeterminate: true, dmarcIndeterminate: true}, gradeInput{})
        if state != riskMedium {
                t.Fatalf("both indeterminate: state = %q, want %q (could-not-verify, not 'no records')", state, riskMedium)
        }
        if !strings.Contains(strings.ToLower(msg), "could not") {
                t.Fatalf("message %q should state authentication could not be verified", msg)
        }

        state, _, _, _ = classifyNoMailGrade(protocolState{spfIndeterminate: true}, gradeInput{hasDMARC: true})
        if state != riskMedium {
                t.Fatalf("one indeterminate: state = %q, want %q (cannot assert the indeterminate record missing)", state, riskMedium)
        }
}

// TestComputePostureDiff_SuppressesAuxIndeterminate extends tri-state drift
// suppression to CAA / MTA-STS / TLS-RPT / BIMI status+mode and to the
// SPF/DMARC/CAA record/tag set diffs: a transient lookup (state=indeterminate on
// either side) must not fabricate a removal/restoration pair.
func TestComputePostureDiff_SuppressesAuxIndeterminate(t *testing.T) {
        present := map[string]any{
                "caa_analysis":     map[string]any{mapKeyStatus: "secure", mapKeyCaaState: triStatePresent, mapKeyRecords: []any{map[string]any{"tag": "issue", "value": "letsencrypt.org"}}},
                "mta_sts_analysis": map[string]any{mapKeyStatus: "secure", mapKeyMtaStsState: triStatePresent, "mode": "enforce"},
                "tlsrpt_analysis":  map[string]any{mapKeyStatus: "secure", mapKeyTlsrptState: triStatePresent},
                "bimi_analysis":    map[string]any{mapKeyStatus: "secure", mapKeyBimiState: triStatePresent},
                "spf_analysis":     map[string]any{mapKeyStatus: "secure", mapKeySpfState: triStatePresent, mapKeyRecords: []any{"v=spf1 -all"}},
                mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: "secure", mapKeyDmarcState: triStatePresent, mapKeyRecords: []any{"v=DMARC1; p=reject"}},
        }
        indeterminate := map[string]any{
                "caa_analysis":     map[string]any{mapKeyStatus: statusIndeterminate, mapKeyCaaState: triStateIndeterminate, mapKeyRecords: []any{}},
                "mta_sts_analysis": map[string]any{mapKeyStatus: statusIndeterminate, mapKeyMtaStsState: triStateIndeterminate, "mode": ""},
                "tlsrpt_analysis":  map[string]any{mapKeyStatus: statusIndeterminate, mapKeyTlsrptState: triStateIndeterminate},
                "bimi_analysis":    map[string]any{mapKeyStatus: statusIndeterminate, mapKeyBimiState: triStateIndeterminate},
                "spf_analysis":     map[string]any{mapKeyStatus: statusIndeterminate, mapKeySpfState: triStateIndeterminate, mapKeyRecords: []any{}},
                mapKeyDmarcAnalysis: map[string]any{mapKeyStatus: statusIndeterminate, mapKeyDmarcState: triStateIndeterminate, mapKeyRecords: []any{}},
        }
        if diffs := ComputePostureDiff(present, indeterminate); len(diffs) != 0 {
                t.Fatalf("indeterminate aux protocols must not drift; got %d: %+v", len(diffs), diffs)
        }
        if diffs := ComputePostureDiff(indeterminate, present); len(diffs) != 0 {
                t.Fatalf("restoration from indeterminate must not drift; got %d: %+v", len(diffs), diffs)
        }
}

// TestComputePostureDiff_AuxRealTransitionStillDrifts is the over-suppression
// guard: a CONFIRMED change (present -> confirmed-absent, an authoritative answer)
// must still surface as drift for the aux protocols and their record/tag sets.
func TestComputePostureDiff_AuxRealTransitionStillDrifts(t *testing.T) {
        present := map[string]any{
                "caa_analysis":     map[string]any{mapKeyStatus: "secure", mapKeyCaaState: triStatePresent, mapKeyRecords: []any{map[string]any{"tag": "issue", "value": "letsencrypt.org"}}},
                "mta_sts_analysis": map[string]any{mapKeyStatus: "secure", mapKeyMtaStsState: triStatePresent, "mode": "enforce"},
        }
        absent := map[string]any{
                "caa_analysis":     map[string]any{mapKeyStatus: mapKeyWarning, mapKeyCaaState: triStateAbsentConf, mapKeyRecords: []any{}},
                "mta_sts_analysis": map[string]any{mapKeyStatus: mapKeyWarning, mapKeyMtaStsState: triStateAbsentConf, "mode": ""},
        }
        if diffs := ComputePostureDiff(present, absent); len(diffs) == 0 {
                t.Fatal("confirmed present->absent on aux protocols must still drift (suppression must not be over-broad)")
        }
}
