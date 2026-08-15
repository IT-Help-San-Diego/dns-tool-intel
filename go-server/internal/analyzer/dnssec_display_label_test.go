// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "testing"

// TestDNSSECDisplayLabel pins the single-source display mapping so a signed
// zone can never again be labeled "Unsigned" from its raw status string. A
// zone whose DNSKEY+DS are present but whose validation is broken/unconfirmed/
// unmeasured must render the honest Broken / Unconfirmed / Could Not Verify.
func TestDNSSECDisplayLabel(t *testing.T) {
	cases := []struct {
		state, chain       string
		wantLabel, wantSev string
	}{
		{dnssecStatePresent, "complete", "Signed", "success"},
		{dnssecStatePresent, "broken", "Broken", "danger"},
		{dnssecStatePresent, "unconfirmed", "Unconfirmed", "warning"},
		{dnssecStatePresent, "unknown", "Could Not Verify", "secondary"},
		{dnssecStatePresent, "inherited", "Inherited", "success"},
		{dnssecStateAbsentConf, "none", "Unsigned", "warning"},
		{dnssecStatePartial, "broken", "Partially Signed", "warning"},
		{dnssecStateIndeterminate, "unknown", "Could Not Verify", "secondary"},
		{dnssecStateUnmeasured, "unknown", "Not Measured", "secondary"},
		// Legacy rows (persisted before dnssec_state existed, 2026-06-17):
		// the measured chain decides — a Feb-Apr row with chain=complete is a
		// measured, validated, SIGNED zone and must never backfill "Unsigned".
		{"", "complete", "Signed", "success"},
		{"", "broken", "Broken", "danger"},
		{"", "inherited", "Inherited", "success"},
		{"", "none", "Unsigned", "warning"},
		// Nothing measured at all, or vocabulary we don't recognize: honest
		// could-not-tell, never a fabricated "Unsigned".
		{"", "", "Could Not Verify", "secondary"},
		{"", "unknown", "Could Not Verify", "secondary"},
		{"future_state", "complete", "Could Not Verify", "secondary"},
	}
	for _, tc := range cases {
		t.Run(tc.state+"/"+tc.chain, func(t *testing.T) {
			label, sev := dnssecDisplayLabel(tc.state, tc.chain)
			if label != tc.wantLabel || sev != tc.wantSev {
				t.Errorf("dnssecDisplayLabel(%q,%q) = (%q,%q), want (%q,%q)", tc.state, tc.chain, label, sev, tc.wantLabel, tc.wantSev)
			}
		})
	}
}

// TestRebucketDNSSECDisplayLabel pins the view-time backfill so a row written
// before display_label existed renders the same honest label as a fresh scan,
// and is idempotent (a present field is left untouched).
func TestRebucketDNSSECDisplayLabel(t *testing.T) {
	// Old-shape row: dnssec_state present + chain broken (bogus), no display_label.
	results := map[string]any{
		"dnssec_analysis": map[string]any{
			"dnssec_state":   dnssecStatePresent,
			"chain_of_trust": "broken",
		},
	}
	RebucketDNSSECDisplayLabel(results)
	dnssec := results["dnssec_analysis"].(map[string]any)
	if dnssec["display_label"] != "Broken" || dnssec["display_severity"] != "danger" {
		t.Errorf("backfill = (%v,%v), want (Broken,danger)", dnssec["display_label"], dnssec["display_severity"])
	}

	// Idempotent: a present field is not overwritten.
	results2 := map[string]any{
		"dnssec_analysis": map[string]any{
			"dnssec_state":     dnssecStatePresent,
			"chain_of_trust":   "complete",
			"display_label":    "Signed",
			"display_severity": "success",
		},
	}
	RebucketDNSSECDisplayLabel(results2)
	if results2["dnssec_analysis"].(map[string]any)["display_label"] != "Signed" {
		t.Error("idempotence broken: present display_label was overwritten")
	}

	// Absent dnssec_analysis is a no-op.
	RebucketDNSSECDisplayLabel(map[string]any{})

	// Pre-tri-state row (no dnssec_state at all, chain measured complete —
	// the Feb-Apr slice): must backfill Signed, not Unsigned. Live regression
	// caught on /analysis/1000 (chain=complete rendered "Unsigned").
	legacy := map[string]any{
		"dnssec_analysis": map[string]any{
			"chain_of_trust": "complete",
			"status":         "success",
		},
	}
	RebucketDNSSECDisplayLabel(legacy)
	ld := legacy["dnssec_analysis"].(map[string]any)
	if ld["display_label"] != "Signed" || ld["display_severity"] != "success" {
		t.Errorf("legacy backfill = (%v,%v), want (Signed,success)", ld["display_label"], ld["display_severity"])
	}
}
