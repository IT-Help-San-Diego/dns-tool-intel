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

// These network-free tests lock the LookupConflict semantics introduced by the
// resolver-consensus fix: when public resolvers return DIFFERENT records with no
// majority winner (DNS in flux / mid-propagation), SPF/DMARC/DNSSEC must report
// INDETERMINATE — never a fabricated absence, and never one resolver's value as
// truth. This is the regression guard for the stale-single-resolver bug where a
// lone stale recursive cache could decide a security verdict.

func TestAnalyzeSPF_Conflict_IsIndeterminate(t *testing.T) {
        const domain = "flux.example"
        mock := &statusMockDNS{
                records: map[string][]string{domain: nil},
                status:  map[string]dnsclient.LookupStatus{domain: dnsclient.LookupConflict},
        }
        a := &Analyzer{DNS: mock}
        res := a.AnalyzeSPF(context.Background(), domain)

        if got, _ := res["status"].(string); got != statusIndeterminate {
                t.Errorf("status = %q, want %q (resolver conflict is not a finding of absence)", got, statusIndeterminate)
        }
        if got, _ := res[mapKeySpfState].(string); got != spfStateIndeterminate {
                t.Errorf("spf_state = %q, want %q", got, spfStateIndeterminate)
        }
        if msg, _ := res["message"].(string); !strings.Contains(msg, "no majority winner") {
                t.Errorf("message = %q, want it to name the resolver disagreement (no majority winner)", msg)
        }
}

func TestAnalyzeDMARC_Conflict_IsIndeterminate(t *testing.T) {
        const (
                domain      = "flux.example"
                dmarcDomain = "_dmarc.flux.example"
        )
        mock := &statusMockDNS{
                records: map[string][]string{dmarcDomain: nil},
                status:  map[string]dnsclient.LookupStatus{dmarcDomain: dnsclient.LookupConflict},
        }
        a := &Analyzer{DNS: mock}
        res := a.AnalyzeDMARC(context.Background(), domain)

        if got, _ := res[mapKeyStatus].(string); got != statusIndeterminate {
                t.Errorf("status = %q, want %q (resolver conflict is not a finding of absence)", got, statusIndeterminate)
        }
        if got, _ := res[mapKeyDmarcState].(string); got != dmarcStateIndeterminate {
                t.Errorf("dmarc_state = %q, want %q", got, dmarcStateIndeterminate)
        }
        if msg, _ := res[mapKeyMessage].(string); !strings.Contains(msg, "no majority winner") {
                t.Errorf("message = %q, want it to name the resolver disagreement (no majority winner)", msg)
        }
}

func TestAnalyzeDNSSEC_Conflict_IsIndeterminate(t *testing.T) {
        const domain = "flux.example"
        mock := NewMockDNSClient()
        // Resolvers disagree on the DNSKEY/DS sets with no majority winner. With
        // no definitive positive evidence (no agreed DNSKEY+DS, no resolver AD
        // flag), this must read as indeterminate — never "not configured".
        mock.AddTTLStatusResponse("DNSKEY", domain, dnsclient.RecordWithTTL{}, dnsclient.LookupConflict)
        mock.AddTTLStatusResponse("DS", domain, dnsclient.RecordWithTTL{}, dnsclient.LookupConflict)
        a := &Analyzer{DNS: mock}
        res := a.AnalyzeDNSSEC(context.Background(), domain)

        if got := res[mapKeyDnssecState]; got != dnssecStateIndeterminate {
                t.Errorf("dnssec_state = %v, want %s (resolver conflict must not read as absence)", got, dnssecStateIndeterminate)
        }
}
