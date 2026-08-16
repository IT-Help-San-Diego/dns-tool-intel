// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"testing"
)

// TestPostureProtocolSlicesAligned enforces the same-array requirement
// behind the What's-Wrong click-through: the finding text slices are THE
// arrays (counters len() them, links range over them), and the parallel
// protocol slices must stay index-aligned with them by construction —
// via the recommend/monitor helpers, never a bare append. If a new
// classifier appends to the text slice directly, this fails.
func TestPostureProtocolSlicesAligned(t *testing.T) {
	a := newMockAnalyzer()

	// Missing SPF+DMARC yields the paired critical issue plus
	// recommendations; an unconfirmed DNSSEC chain yields monitoring.
	results := map[string]any{
		"domain": "example.com",
		"dnssec_analysis": map[string]any{
			mapKeyStatus:       "warning",
			mapKeyDnssecState:  dnssecStatePresent,
			mapKeyChainOfTrust: "unconfirmed",
			mapKeyHasDnskey:    true,
			mapKeyHasDs:        true,
		},
	}

	posture := a.CalculatePosture(results)

	pairs := []struct {
		textKey, protoKey string
	}{
		{"critical_issues", "critical_issue_protocols"},
		{"recommendations", "recommendation_protocols"},
		{"monitoring", "monitoring_protocols"},
	}
	for _, pr := range pairs {
		texts, _ := posture[pr.textKey].([]string)
		protos, _ := posture[pr.protoKey].([]string)
		if len(texts) != len(protos) {
			t.Errorf("%s has %d items but %s has %d — the slices must be index-aligned",
				pr.textKey, len(texts), pr.protoKey, len(protos))
		}
		for i, p := range protos {
			if p == "" {
				t.Errorf("%s[%d] is empty — every finding names its protocol (or a section token)", pr.protoKey, i)
			}
		}
	}

	recs, _ := posture["recommendations"].([]string)
	if len(recs) == 0 {
		t.Fatal("fixture produced no recommendations — the alignment assertions above tested nothing")
	}
	mon, _ := posture["monitoring"].([]string)
	if len(mon) == 0 {
		t.Fatal("fixture produced no monitoring items — extend the fixture; an empty bucket is an assertion that cannot fail")
	}
}
