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

// bimiFallbackMockDNS drives AnalyzeBIMI's org-domain fallback without the
// network: per-name TXT records and per-name lookup status.
type bimiFallbackMockDNS struct {
	MockDNSClient
	records map[string][]string
	status  map[string]dnsclient.LookupStatus
}

func (m *bimiFallbackMockDNS) QueryDNS(_ context.Context, _, domain string) []string {
	return m.records[domain]
}

func (m *bimiFallbackMockDNS) QueryDNSWithStatus(_ context.Context, _, domain string) ([]string, dnsclient.LookupStatus) {
	st, ok := m.status[domain]
	if !ok {
		st = dnsclient.LookupAbsent
	}
	return m.records[domain], st
}

// A subdomain with no own BIMI assertion record falls back to the
// organizational domain's default._bimi record (BIMI draft §7.2, the
// DMARC-§6.6.3-mirroring lookup) — the CAA-#478 defect class, BIMI instance.
func TestAnalyzeBIMI_OrgDomainFallback(t *testing.T) {
	mock := &bimiFallbackMockDNS{
		records: map[string][]string{
			// no l=/a= URLs: the fallback LOOKUP is under test, not the
			// logo/VMC fetchers (which need a live HTTP client)
			"default._bimi.example.com": {"v=BIMI1;"},
		},
		status: map[string]dnsclient.LookupStatus{
			"default._bimi.sub.example.com": dnsclient.LookupAbsent,
			"default._bimi.example.com":     dnsclient.LookupResolved,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeBIMI(context.Background(), "sub.example.com")

	if res[mapKeyBimiState] != triStatePresent {
		t.Fatalf("bimi_state = %v, want %v (org-domain record applies)", res[mapKeyBimiState], triStatePresent)
	}
	if res["bimi_source"] != "example.com" {
		t.Errorf("bimi_source = %v, want example.com", res["bimi_source"])
	}
	if res["inherited"] != true {
		t.Errorf("inherited = %v, want true", res["inherited"])
	}
	msg, _ := res[mapKeyMessage].(string)
	if !strings.Contains(msg, "organizational-domain BIMI") {
		t.Errorf("message must name the org-domain fallback, got: %q", msg)
	}
}

// An indeterminate org-domain lookup must yield indeterminate — never
// fabricate confirmed absence past a label that could not be read.
func TestAnalyzeBIMI_OrgFallbackIndeterminateStopsHonestly(t *testing.T) {
	mock := &bimiFallbackMockDNS{
		records: map[string][]string{},
		status: map[string]dnsclient.LookupStatus{
			"default._bimi.sub.example.com": dnsclient.LookupAbsent,
			"default._bimi.example.com":     dnsclient.LookupError,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeBIMI(context.Background(), "sub.example.com")

	if res[mapKeyBimiState] != triStateIndeterminate {
		t.Fatalf("bimi_state = %v, want %v (org lookup unreadable)", res[mapKeyBimiState], triStateIndeterminate)
	}
}

// The org domain itself: own record present → no fallback artifacts.
func TestAnalyzeBIMI_ApexOwnRecordNoFallbackArtifacts(t *testing.T) {
	mock := &bimiFallbackMockDNS{
		records: map[string][]string{
			"default._bimi.example.com": {"v=BIMI1;"},
		},
		status: map[string]dnsclient.LookupStatus{
			"default._bimi.example.com": dnsclient.LookupResolved,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeBIMI(context.Background(), "example.com")

	if res[mapKeyBimiState] != triStatePresent {
		t.Fatalf("bimi_state = %v, want present", res[mapKeyBimiState])
	}
	if _, has := res["bimi_source"]; has {
		t.Error("apex with own record must not carry bimi_source")
	}
	if _, has := res["inherited"]; has {
		t.Error("apex with own record must not carry inherited")
	}
}

// Confirmed absence at BOTH the subdomain and the org domain stays an honest
// absent — the fallback changes the verdict only when the org HOLDS a record.
func TestAnalyzeBIMI_TrueAbsenceStaysAbsent(t *testing.T) {
	mock := &bimiFallbackMockDNS{
		records: map[string][]string{},
		status: map[string]dnsclient.LookupStatus{
			"default._bimi.sub.example.com": dnsclient.LookupAbsent,
			"default._bimi.example.com":     dnsclient.LookupAbsent,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeBIMI(context.Background(), "sub.example.com")

	if res[mapKeyBimiState] != triStateAbsentConf {
		t.Fatalf("bimi_state = %v, want %v (both levels confirmed absent)", res[mapKeyBimiState], triStateAbsentConf)
	}
}
