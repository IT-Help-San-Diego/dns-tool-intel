// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"context"
	"strings"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

// 360 base64 chars decode to ~270 key bytes — a 2048-bit-class key, so a
// found selector yields the plain "success" verdict.
var tristateTestKey = "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 360)

// All selector probes authoritatively answer "no record": the census is
// complete, so absence is confirmed and the honest "not discoverable" verdict
// stands.
func TestAnalyzeDKIM_CensusAbsentConfirmed(t *testing.T) {
	mock := NewMockDNSClient()
	a := &Analyzer{DNS: mock}

	result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"10 mail.example.com."}, nil)

	if got := result[mapKeyDkimState]; got != triStateAbsentConf {
		t.Errorf("dkim_state = %v, want %q", got, triStateAbsentConf)
	}
	if got := result["status"]; got != "info" {
		t.Errorf("status = %v, want info", got)
	}
	msg, _ := result["message"].(string)
	if !strings.Contains(msg, "not discoverable") {
		t.Errorf("message = %q, want the 'not discoverable' verdict for a completed census", msg)
	}
}

func TestAnalyzeDKIM_CensusPresent(t *testing.T) {
	mock := NewMockDNSClient()
	mock.AddResponse("TXT", "selector1._domainkey.example.com", []string{tristateTestKey})
	a := &Analyzer{DNS: mock}

	result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"10 mail.example.com."}, nil)

	if got := result[mapKeyDkimState]; got != triStatePresent {
		t.Errorf("dkim_state = %v, want %q", got, triStatePresent)
	}
}

// Every selector probe fails transiently. The old flat-QueryDNS path read this
// as "DKIM not discoverable" — indistinguishable from confirmed absence — so a
// scan through a network blip flipped the status (and posture hash) against
// the previous scan's "success" and fabricated drift. The census must come
// back indeterminate with a message that admits the probes never completed.
func TestAnalyzeDKIM_CensusIndeterminateOnFullProbeFailure(t *testing.T) {
	mock := NewMockDNSClient()
	for _, sel := range defaultDKIMSelectors {
		mock.AddStatusResponse("TXT", sel+".example.com", nil, dnsclient.LookupError)
	}
	a := &Analyzer{DNS: mock}

	result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"10 mail.example.com."}, nil)

	if got := result[mapKeyDkimState]; got != triStateIndeterminate {
		t.Errorf("dkim_state = %v, want %q", got, triStateIndeterminate)
	}
	if got := result["status"]; got != "info" {
		t.Errorf("status = %v, want info", got)
	}
	msg, _ := result["message"].(string)
	if !strings.Contains(msg, "did not complete") || !strings.Contains(msg, "not evidence") {
		t.Errorf("message = %q, want an honest could-not-verify message", msg)
	}
	if strings.Contains(msg, "not discoverable") {
		t.Errorf("message = %q asserts non-discovery from probes that never ran", msg)
	}
}

// One probe fails while another finds a key: the found key is real (status
// stays a records-derived verdict) but the census is incomplete, so the state
// is indeterminate — the failed probe could be hiding a selector the previous
// scan saw, and selector-set drift must not be computed from it.
func TestAnalyzeDKIM_CensusIndeterminateOutranksPresent(t *testing.T) {
	mock := NewMockDNSClient()
	mock.AddResponse("TXT", "selector1._domainkey.example.com", []string{tristateTestKey})
	mock.AddStatusResponse("TXT", "default._domainkey.example.com", nil, dnsclient.LookupError)
	a := &Analyzer{DNS: mock}

	result := a.AnalyzeDKIM(context.Background(), "example.com", []string{"10 mail.example.com."}, nil)

	if got := result[mapKeyDkimState]; got != triStateIndeterminate {
		t.Errorf("dkim_state = %v, want %q", got, triStateIndeterminate)
	}
	if got := result["status"]; got != "success" {
		t.Errorf("status = %v, want success — a found key is a real finding", got)
	}
}

func TestComputePostureDiff_DKIMIndeterminateSuppressesStatusAndSelectors(t *testing.T) {
	prev := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "success",
			mapKeyDkimState: triStatePresent,
			"selectors": map[string]any{
				"selector1._domainkey": map[string]any{"records": []any{tristateTestKey}},
			},
		},
	}
	curr := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "info",
			mapKeyDkimState: triStateIndeterminate,
			"selectors":     map[string]any{},
		},
	}
	diffs := ComputePostureDiff(prev, curr)
	for _, d := range diffs {
		if d.Label == "DKIM Status" || d.Label == "DKIM Selectors" {
			t.Errorf("got %s diff %q -> %q from an indeterminate census", d.Label, d.Previous, d.Current)
		}
	}
	// And symmetrically when the PREVIOUS scan was the indeterminate one.
	diffs = ComputePostureDiff(curr, prev)
	for _, d := range diffs {
		if d.Label == "DKIM Status" || d.Label == "DKIM Selectors" {
			t.Errorf("got %s diff %q -> %q from an indeterminate previous census", d.Label, d.Previous, d.Current)
		}
	}
}

// A completed census that finds nothing is an authoritative absence — the keys
// really are gone. That is real drift and must never be suppressed.
func TestComputePostureDiff_DKIMAuthoritativeAbsenceStillReports(t *testing.T) {
	prev := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "success",
			mapKeyDkimState: triStatePresent,
			"selectors": map[string]any{
				"selector1._domainkey": map[string]any{"records": []any{tristateTestKey}},
			},
		},
	}
	curr := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "info",
			mapKeyDkimState: triStateAbsentConf,
			"selectors":     map[string]any{},
		},
	}
	diffs := ComputePostureDiff(prev, curr)
	var gotStatus, gotSelectors bool
	for _, d := range diffs {
		switch d.Label {
		case "DKIM Status":
			gotStatus = true
		case "DKIM Selectors":
			gotSelectors = true
		}
	}
	if !gotStatus {
		t.Error("expected DKIM Status diff for an authoritative disappearance")
	}
	if !gotSelectors {
		t.Error("expected DKIM Selectors diff for an authoritative disappearance")
	}
}

func TestExtractSortedSelectors_MapShape(t *testing.T) {
	results := map[string]any{
		"dkim_analysis": map[string]any{
			"selectors": map[string]any{
				"Selector2._domainkey": map[string]any{},
				"selector1._domainkey": map[string]any{},
			},
		},
	}
	got := extractSortedSelectors(results)
	want := "selector1._domainkey,selector2._domainkey"
	if got != want {
		t.Errorf("extractSortedSelectors = %q, want %q", got, want)
	}
}

// A real selector addition between two determinate censuses (a new provider
// starting to sign) must fire the DKIM Selectors row — the row that could
// never fire while the extractor ignored the map shape.
func TestComputePostureDiff_DKIMSelectorAdditionFires(t *testing.T) {
	prev := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "success",
			mapKeyDkimState: triStatePresent,
			"selectors": map[string]any{
				"selector1._domainkey": map[string]any{"records": []any{tristateTestKey}},
			},
		},
	}
	curr := map[string]any{
		"dkim_analysis": map[string]any{
			"status":        "success",
			mapKeyDkimState: triStatePresent,
			"selectors": map[string]any{
				"selector1._domainkey": map[string]any{"records": []any{tristateTestKey}},
				"klaviyo._domainkey":   map[string]any{"records": []any{tristateTestKey}},
			},
		},
	}
	diffs := ComputePostureDiff(prev, curr)
	found := false
	for _, d := range diffs {
		if d.Label == "DKIM Selectors" {
			found = true
			if d.Severity != "warning" {
				t.Errorf("Severity = %q, want warning", d.Severity)
			}
		}
	}
	if !found {
		t.Error("expected DKIM Selectors diff for a real selector addition")
	}
}
