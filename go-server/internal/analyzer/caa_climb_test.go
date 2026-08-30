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

// caaClimbMockDNS drives AnalyzeCAA's RFC 8659 §3 tree climb without the
// network: per-name CAA records and per-name lookup status.
type caaClimbMockDNS struct {
	MockDNSClient
	records map[string][]string
	status  map[string]dnsclient.LookupStatus
}

func (m *caaClimbMockDNS) QueryDNS(_ context.Context, _, domain string) []string {
	return m.records[domain]
}

func (m *caaClimbMockDNS) QueryDNSWithStatus(_ context.Context, _, domain string) ([]string, dnsclient.LookupStatus) {
	st, ok := m.status[domain]
	if !ok {
		st = dnsclient.LookupAbsent
	}
	return m.records[domain], st
}

// A subdomain with no CAA of its own MUST inherit the parent zone's policy
// (RFC 8659 §3 tree climb) — the pq.resolutionscope.com case that surfaced
// the Replit-era exact-name-only defect.
func TestAnalyzeCAA_ClimbFindsParentPolicy(t *testing.T) {
	mock := &caaClimbMockDNS{
		records: map[string][]string{
			"resolutionscope.com": {`0 issue "amazon.com"`, `0 issuewild ";"`},
		},
		status: map[string]dnsclient.LookupStatus{
			"pq.resolutionscope.com": dnsclient.LookupAbsent,
			"resolutionscope.com":    dnsclient.LookupResolved,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeCAA(context.Background(), "pq.resolutionscope.com")

	if res[mapKeyCaaState] != triStatePresent {
		t.Fatalf("caa_state = %v, want %v (parent policy applies)", res[mapKeyCaaState], triStatePresent)
	}
	if res["caa_source"] != "resolutionscope.com" {
		t.Errorf("caa_source = %v, want resolutionscope.com", res["caa_source"])
	}
	if res["inherited"] != true {
		t.Errorf("inherited = %v, want true", res["inherited"])
	}
	msg, _ := res["message"].(string)
	if !strings.Contains(msg, "RFC 8659") || !strings.Contains(msg, "resolutionscope.com") {
		t.Errorf("message must name the tree climb and the source zone, got: %q", msg)
	}
}

// A deeper name climbs through multiple labels until the org domain.
func TestAnalyzeCAA_ClimbWalksMultipleLabels(t *testing.T) {
	mock := &caaClimbMockDNS{
		records: map[string][]string{
			"example.com": {`0 issue "letsencrypt.org"`},
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeCAA(context.Background(), "a.b.example.com")

	if res[mapKeyCaaState] != triStatePresent {
		t.Fatalf("caa_state = %v, want present via two-label climb", res[mapKeyCaaState])
	}
	if res["caa_source"] != "example.com" {
		t.Errorf("caa_source = %v, want example.com", res["caa_source"])
	}
}

// An indeterminate lookup mid-climb means the policy CANNOT be determined —
// never report "any CA can issue" when a skipped label might hold the policy.
func TestAnalyzeCAA_ClimbIndeterminateStopsHonestly(t *testing.T) {
	mock := &caaClimbMockDNS{
		records: map[string][]string{},
		status: map[string]dnsclient.LookupStatus{
			"pq.resolutionscope.com": dnsclient.LookupAbsent,
			"resolutionscope.com":    dnsclient.LookupError,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeCAA(context.Background(), "pq.resolutionscope.com")

	if res[mapKeyCaaState] != triStateIndeterminate {
		t.Fatalf("caa_state = %v, want %v (climb blocked → indeterminate, never absent)", res[mapKeyCaaState], triStateIndeterminate)
	}
}

// The apex path is unchanged: own CAA present → no climb, no inherited flag.
func TestAnalyzeCAA_ApexOwnPolicyNoClimbArtifacts(t *testing.T) {
	mock := &caaClimbMockDNS{
		records: map[string][]string{
			"resolutionscope.com": {`0 issue "amazon.com"`},
		},
		status: map[string]dnsclient.LookupStatus{
			"resolutionscope.com": dnsclient.LookupResolved,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeCAA(context.Background(), "resolutionscope.com")

	if res[mapKeyCaaState] != triStatePresent {
		t.Fatalf("caa_state = %v, want present", res[mapKeyCaaState])
	}
	if _, has := res["caa_source"]; has {
		t.Error("apex with own policy must not carry caa_source")
	}
	if _, has := res["inherited"]; has {
		t.Error("apex with own policy must not carry inherited")
	}
	msg, _ := res["message"].(string)
	if strings.Contains(msg, "tree climb") {
		t.Errorf("apex message must not mention the climb, got: %q", msg)
	}
}

// Confirmed absence at every label down to the org domain is still an honest
// absent — the climb changes the verdict only when a parent HOLDS a policy.
func TestAnalyzeCAA_TrueAbsenceStaysAbsent(t *testing.T) {
	mock := &caaClimbMockDNS{
		records: map[string][]string{},
		status: map[string]dnsclient.LookupStatus{
			"sub.example.com": dnsclient.LookupAbsent,
			"example.com":     dnsclient.LookupAbsent,
		},
	}
	a := &Analyzer{DNS: mock}
	res := a.AnalyzeCAA(context.Background(), "sub.example.com")

	if res[mapKeyCaaState] != triStateAbsentConf {
		t.Fatalf("caa_state = %v, want %v (whole chain confirmed absent)", res[mapKeyCaaState], triStateAbsentConf)
	}
}
