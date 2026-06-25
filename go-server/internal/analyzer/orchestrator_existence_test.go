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

// TestCheckDomainExists_TransientIsIndeterminate guards the precision rule that a
// domain whose authoritative nameservers fail transiently (SERVFAIL / timeout)
// must NOT be reported as non-existent. Regression: johnsoncustombuilders.com was
// mid-migration between DNS providers (its old auth servers returned SERVFAIL) and
// was falsely labelled "Non-existent / Undelegated". Absence may only be asserted
// from an authoritative answer (RFC 7489 §7.1 / RFC 7208 §4.6).
func TestCheckDomainExists_TransientIsIndeterminate(t *testing.T) {
        mock := NewMockDNSClient()
        for _, rtype := range []string{"A", "TXT", "MX", "NS"} {
                mock.AddStatusResponse(rtype, "transient.example", nil, dnsclient.LookupError)
        }
        a := &Analyzer{DNS: mock}

        exists, status, msg := a.checkDomainExists(context.Background(), "transient.example")
        if exists {
                t.Fatalf("transient SERVFAIL must not resolve as existing")
        }
        if status != statusIndeterminate {
                t.Fatalf("expected status %q, got %q", statusIndeterminate, status)
        }
        if status == "undelegated" {
                t.Fatalf("transient failure must never be reported as undelegated")
        }
        if msg == nil || !strings.Contains(strings.ToLower(*msg), "not a confirmation") {
                t.Fatalf("indeterminate message must clarify it is not a confirmation of non-existence, got %v", msg)
        }
}

// TestCheckDomainExists_AuthoritativeAbsenceIsUndelegated verifies a genuine
// NXDOMAIN/NODATA on every probed type still yields the definitive "undelegated"
// verdict — the tri-state must not over-correct transient handling into never
// reporting real non-existent domains.
func TestCheckDomainExists_AuthoritativeAbsenceIsUndelegated(t *testing.T) {
        mock := NewMockDNSClient()
        for _, rtype := range []string{"A", "TXT", "MX", "NS"} {
                mock.AddStatusResponse(rtype, "gone.example", nil, dnsclient.LookupAbsent)
        }
        a := &Analyzer{DNS: mock}

        exists, status, _ := a.checkDomainExists(context.Background(), "gone.example")
        if exists {
                t.Fatalf("authoritative absence must not resolve as existing")
        }
        if status != "undelegated" {
                t.Fatalf("expected status %q, got %q", "undelegated", status)
        }
}

// TestCheckDomainExists_ResolvedIsActive verifies a domain with any record is
// reported active.
func TestCheckDomainExists_ResolvedIsActive(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddStatusResponse("A", "live.example", []string{"203.0.113.7"}, dnsclient.LookupResolved)
        a := &Analyzer{DNS: mock}

        exists, status, _ := a.checkDomainExists(context.Background(), "live.example")
        if !exists {
                t.Fatalf("domain with an A record must resolve as existing")
        }
        if status != "active" {
                t.Fatalf("expected status %q, got %q", "active", status)
        }
}

// TestCheckDomainExists_MixedTransientAndAbsence verifies that a single
// authoritative absence among otherwise-transient probes is enough to assert
// undelegated — an authoritative NODATA on any type is definitive.
func TestCheckDomainExists_MixedTransientAndAbsence(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddStatusResponse("A", "mixed.example", nil, dnsclient.LookupError)
        mock.AddStatusResponse("TXT", "mixed.example", nil, dnsclient.LookupError)
        mock.AddStatusResponse("MX", "mixed.example", nil, dnsclient.LookupError)
        mock.AddStatusResponse("NS", "mixed.example", nil, dnsclient.LookupAbsent)
        a := &Analyzer{DNS: mock}

        exists, status, _ := a.checkDomainExists(context.Background(), "mixed.example")
        if exists {
                t.Fatalf("must not resolve as existing")
        }
        if status != "undelegated" {
                t.Fatalf("expected status %q, got %q", "undelegated", status)
        }
}
