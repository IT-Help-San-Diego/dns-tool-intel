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
