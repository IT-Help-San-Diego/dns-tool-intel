// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
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

// TestAnalyzeDANE_ProviderNoInbound_StaysAbsentUnderTransient locks the
// provider-no-inbound invariant: for a provider that authoritatively does not
// support inbound DANE (e.g. Microsoft 365), a missing/transient TLSA lookup must
// stay a STABLE absent_confirmed and never flap to indeterminate.
func TestAnalyzeDANE_ProviderNoInbound_StaysAbsentUnderTransient(t *testing.T) {
        const m365MX = "example-com.mail.protection.outlook.com"
        mockDNS := NewMockDNSClient()
        mockDNS.AddTTLStatusResponse("TLSA", "_25._tcp."+m365MX,
                dnsclient.RecordWithTTL{}, dnsclient.LookupError)
        a := &Analyzer{DNS: mockDNS}

        result := a.AnalyzeDANE(context.Background(), triStateDomain, []string{"10 " + m365MX + "."})

        if got := result["dane_state"]; got != daneStateAbsentConf {
                t.Fatalf("dane_state = %v, want %s (provider-no-inbound must not flap to indeterminate on transient TLSA failure)", got, daneStateAbsentConf)
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
