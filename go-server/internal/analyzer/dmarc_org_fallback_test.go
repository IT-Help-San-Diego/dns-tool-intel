// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// RFC 7489 §6.6.3 policy discovery, step 3: when no DMARC record exists at
// the exact (sub)domain name, Mail Receivers query the organizational domain
// and apply its sp= (or p= when sp is absent) to subdomain mail. These tests
// pin the org-domain fallback in AnalyzeDMARC and its propagation through the
// no-mail posture grade so a locked-down subdomain covered by sp=reject is
// never falsely graded "missing DMARC" / High Risk.
package analyzer

import (
	"context"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

func TestAnalyzeDMARC_OrgFallback(t *testing.T) {
	cases := []struct {
		name         string
		domain       string
		orgRecords   []string
		orgStatus    dnsclient.LookupStatus
		wantState    string
		wantStatus   string
		wantPolicy   string
		wantSource   string
		wantFallback bool
		wantPct      int
	}{
		{
			name:         "sp=reject inherited (locked-down subdomain, real-world shape)",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStatePresent,
			wantStatus:   "success",
			wantPolicy:   "reject",
			wantSource:   "sp",
			wantFallback: true,
			wantPct:      100,
		},
		{
			name:         "sp absent falls back to p= (RFC 7489 §6.3 sp default)",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=reject;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStatePresent,
			wantStatus:   "success",
			wantPolicy:   "reject",
			wantSource:   "p",
			wantFallback: true,
			wantPct:      100,
		},
		{
			name:         "p=none sp=reject — sp wins for the subdomain",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=none; sp=reject;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStatePresent,
			wantStatus:   "success",
			wantPolicy:   "reject",
			wantSource:   "sp",
			wantFallback: true,
			wantPct:      100,
		},
		{
			name:         "p=reject sp=none — subdomain is deliberately unprotected",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=reject; sp=none;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStatePresent,
			wantStatus:   "warning",
			wantPolicy:   "none",
			wantSource:   "sp",
			wantFallback: true,
			wantPct:      100,
		},
		{
			name:         "pct<100 flows into partial-enforcement grading",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=reject; pct=50;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStatePresent,
			wantStatus:   "warning",
			wantPolicy:   "reject",
			wantSource:   "p",
			wantFallback: true,
			wantPct:      50,
		},
		{
			name:         "org lookup SERVFAIL — indeterminate, never absent",
			domain:       "local.example.com",
			orgRecords:   nil,
			orgStatus:    dnsclient.LookupError,
			wantState:    dmarcStateIndeterminate,
			wantStatus:   statusIndeterminate,
			wantPolicy:   "",
			wantSource:   "",
			wantFallback: false,
			wantPct:      100,
		},
		{
			name:         "org lookup resolver conflict — indeterminate, never absent",
			domain:       "local.example.com",
			orgRecords:   nil,
			orgStatus:    dnsclient.LookupConflict,
			wantState:    dmarcStateIndeterminate,
			wantStatus:   statusIndeterminate,
			wantPolicy:   "",
			wantSource:   "",
			wantFallback: false,
			wantPct:      100,
		},
		{
			name:         "multiple org records = no DMARC per §6.6.3 — absence stands",
			domain:       "local.example.com",
			orgRecords:   []string{"v=DMARC1; p=reject;", "v=DMARC1; p=none;"},
			orgStatus:    dnsclient.LookupResolved,
			wantState:    dmarcStateAbsentConf,
			wantStatus:   "missing",
			wantPolicy:   "",
			wantSource:   "",
			wantFallback: false,
			wantPct:      100,
		},
		{
			name:         "org has no DMARC either — confirmed absence stands",
			domain:       "local.example.com",
			orgRecords:   nil,
			orgStatus:    dnsclient.LookupAbsent,
			wantState:    dmarcStateAbsentConf,
			wantStatus:   "missing",
			wantPolicy:   "",
			wantSource:   "",
			wantFallback: false,
			wantPct:      100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newMockAnalyzer()
			mock := a.DNS.(*MockDNSClient)
			mock.AddStatusResponse("TXT", "_dmarc."+tc.domain, nil, dnsclient.LookupAbsent)
			mock.AddStatusResponse("TXT", "_dmarc.example.com", tc.orgRecords, tc.orgStatus)

			result := a.AnalyzeDMARC(context.Background(), tc.domain)

			if got := result[mapKeyDmarcState]; got != tc.wantState {
				t.Errorf("dmarc_state = %v, want %v", got, tc.wantState)
			}
			if got := result[mapKeyStatus]; got != tc.wantStatus {
				t.Errorf("status = %v, want %v", got, tc.wantStatus)
			}
			if tc.wantPolicy != "" {
				if got := result["policy"]; got != tc.wantPolicy {
					t.Errorf("policy = %v, want %v", got, tc.wantPolicy)
				}
			}
			if got, _ := result["org_domain_fallback"].(bool); got != tc.wantFallback {
				t.Errorf("org_domain_fallback = %v, want %v", got, tc.wantFallback)
			}
			if tc.wantFallback {
				if got := result["org_domain"]; got != "example.com" {
					t.Errorf("org_domain = %v, want example.com", got)
				}
				if got := result["effective_policy_source"]; got != tc.wantSource {
					t.Errorf("effective_policy_source = %v, want %v", got, tc.wantSource)
				}
				if got := result["pct"]; got != tc.wantPct {
					t.Errorf("pct = %v, want %v", got, tc.wantPct)
				}
				// No fabrication: nothing is published at the subdomain name.
				if recs, _ := result[mapKeyRecords].([]string); len(recs) != 0 {
					t.Errorf("records must stay empty on inherited coverage, got %v", recs)
				}
				if recs, _ := result[mapKeyValidRecords].([]string); len(recs) != 0 {
					t.Errorf("valid_records must stay empty on inherited coverage, got %v", recs)
				}
				if orgValid, _ := result["org_valid_records"].([]string); len(orgValid) != 1 {
					t.Errorf("org_valid_records should carry the org record, got %v", orgValid)
				}
			}
		})
	}
}

func TestAnalyzeDMARC_OrgFallback_NotAppliedAtApex(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddStatusResponse("TXT", "_dmarc.example.com", nil, dnsclient.LookupAbsent)

	result := a.AnalyzeDMARC(context.Background(), "example.com")

	if got := result[mapKeyDmarcState]; got != dmarcStateAbsentConf {
		t.Errorf("apex absence must stay absent_confirmed, got %v", got)
	}
	if got, _ := result["org_domain_fallback"].(bool); got {
		t.Error("org_domain_fallback must not fire for the organizational domain itself")
	}
}

func TestAnalyzeDMARC_OrgFallback_NotAppliedWhenSubdomainHasRecord(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddResponse("TXT", "_dmarc.local.example.com", []string{"v=DMARC1; p=quarantine;"})
	mock.AddStatusResponse("TXT", "_dmarc.example.com", []string{"v=DMARC1; p=reject; sp=reject;"}, dnsclient.LookupResolved)

	result := a.AnalyzeDMARC(context.Background(), "local.example.com")

	if got := result["policy"]; got != "quarantine" {
		t.Errorf("subdomain's own record must win over org fallback, got policy %v", got)
	}
	if got, _ := result["org_domain_fallback"].(bool); got {
		t.Error("org_domain_fallback must not fire when the subdomain publishes its own record")
	}
}

// A locked-down no-mail subdomain (null MX + SPF -all) whose DMARC coverage is
// inherited via §6.6.3 must grade Low Risk, not "missing DMARC" High Risk.
func TestCalculatePosture_NoMailSubdomainWithInheritedDMARCReject(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddStatusResponse("TXT", "_dmarc.local.example.com", nil, dnsclient.LookupAbsent)
	mock.AddStatusResponse("TXT", "_dmarc.example.com", []string{"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"}, dnsclient.LookupResolved)

	dmarc := a.AnalyzeDMARC(context.Background(), "local.example.com")

	results := map[string]any{
		"domain":      "local.example.com",
		"has_null_mx": true,
		"spf_analysis": map[string]any{
			mapKeyStatus:    "success",
			mapKeySpfState:  spfStatePresent,
			"all_mechanism": "-all",
		},
		"dmarc_analysis": dmarc,
	}

	posture := a.CalculatePosture(results)
	grade, _ := posture["grade"].(string)
	if grade != riskLow {
		t.Errorf("locked-down subdomain with inherited sp=reject should grade %q, got %q (message: %v)", riskLow, grade, posture["message"])
	}

	mp := buildMailPosture(results)
	if got := mp["classification"]; got != "no_mail_verified" {
		t.Errorf("mail posture classification = %v, want no_mail_verified", got)
	}
}

// The same subdomain WITHOUT org coverage must keep its High Risk grade — the
// fallback must never soften a genuinely uncovered no-mail subdomain.
func TestCalculatePosture_NoMailSubdomainWithoutAnyDMARC(t *testing.T) {
	a := newMockAnalyzer()
	mock := a.DNS.(*MockDNSClient)
	mock.AddStatusResponse("TXT", "_dmarc.local.example.com", nil, dnsclient.LookupAbsent)
	mock.AddStatusResponse("TXT", "_dmarc.example.com", nil, dnsclient.LookupAbsent)

	dmarc := a.AnalyzeDMARC(context.Background(), "local.example.com")

	results := map[string]any{
		"domain":      "local.example.com",
		"has_null_mx": true,
		"spf_analysis": map[string]any{
			mapKeyStatus:    "success",
			mapKeySpfState:  spfStatePresent,
			"all_mechanism": "-all",
		},
		"dmarc_analysis": dmarc,
	}

	posture := a.CalculatePosture(results)
	grade, _ := posture["grade"].(string)
	if grade != riskHigh {
		t.Errorf("no-mail subdomain with no DMARC anywhere should stay %q, got %q", riskHigh, grade)
	}
}

// RFC 7489 §7.1: when coverage is inherited via §6.6.3, the rua/ruf addresses
// come from the ORG record, so external receivers publish the authorization at
// <org>._report._dmarc.<ext> — checking the subdomain name would fabricate a
// false "unauthorized" finding.
func TestValidateDMARCExternalAuth_OrgFallbackUsesOrgReportingDomain(t *testing.T) {
	const orgAuthName = "example.com._report._dmarc.ext.com"
	dmarcData := map[string]any{
		"rua":                 "mailto:reports@ext.com",
		"org_domain_fallback": true,
		"org_domain":          "example.com",
	}

	a := &Analyzer{DNS: &statusMockDNS{
		records: map[string][]string{orgAuthName: {"v=DMARC1;"}},
		status:  map[string]dnsclient.LookupStatus{orgAuthName: dnsclient.LookupResolved},
	}}

	result := a.ValidateDMARCExternalAuth(context.Background(), "local.example.com", dmarcData)

	if got := result["status"]; got != "success" {
		t.Errorf("status = %v, want success (authorization published for the org domain)", got)
	}
	eds, _ := result["external_domains"].([]map[string]any)
	if len(eds) != 1 {
		t.Fatalf("external_domains = %d, want 1", len(eds))
	}
	if got, _ := eds[0]["authorized"].(bool); !got {
		t.Error("org-domain authorization record must authorize inherited-coverage subdomains")
	}
	if got := eds[0]["auth_domain"]; got != nil && got != orgAuthName {
		t.Errorf("auth_domain = %v, want %v", got, orgAuthName)
	}

	// Without the fallback flag, the same setup must NOT find the org-name
	// record: the subdomain-name lookup is absent → unauthorized.
	plainData := map[string]any{"rua": "mailto:reports@ext.com"}
	a2 := &Analyzer{DNS: &statusMockDNS{
		records: map[string][]string{orgAuthName: {"v=DMARC1;"}},
		status: map[string]dnsclient.LookupStatus{
			orgAuthName: dnsclient.LookupResolved,
			"local.example.com._report._dmarc.ext.com": dnsclient.LookupAbsent,
		},
	}}
	result2 := a2.ValidateDMARCExternalAuth(context.Background(), "local.example.com", plainData)
	if got := result2["status"]; got != "warning" {
		t.Errorf("non-fallback path must keep the subdomain reporting name, got status %v", got)
	}
}
