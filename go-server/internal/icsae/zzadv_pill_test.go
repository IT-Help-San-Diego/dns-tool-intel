package icsae

import "testing"

// TestAdvQuarantinePill: at p=quarantine with everything else strong, does
// DMARC_ENFORCEMENT still land in RealFixes and drive the history pill?
func TestAdvQuarantinePill(t *testing.T) {
	fr := map[string]any{
		"dmarc_analysis": map[string]any{
			"status": "success", "policy": "quarantine", "pct": float64(100),
			"rua": "mailto:r@example.gov", "ruf": "mailto:f@example.gov",
		},
		"spf_analysis":    map[string]any{"status": "success", "all_mechanism": "-all"},
		"caa_analysis":    map[string]any{"status": "success", "records": []any{"0 issue \"x\""}},
		"dnssec_analysis": map[string]any{"status": "success", "ad_flag": true, "chain_of_trust": "complete"},
		"dkim_analysis":   map[string]any{"status": "success", "primary_has_dkim": true},
	}
	obs := Normalize(fr)
	t.Logf("DMARC_REJECT=%v DMARC_ENFORCING=%v", obs["DMARC_REJECT"], obs["DMARC_ENFORCING"])

	fc := ClassifyFixes(
		[]string{"DMARC_ENFORCEMENT"}, nil, nil,
		[]string{"SPF_EFFECTIVE_POLICY", "CAA_RESTRICTION_PRESENT", "DNSSEC_AUTHENTICATED"},
		false, obs["DMARC_REJECT"], false, nil,
	)
	t.Logf("RealFixes=%v RealFixCount=%d Color=%q ByDesign=%v Hygiene=%v",
		fc.RealFixes, fc.RealFixCount, fc.Color, fc.ByDesign, fc.Hygiene)
	if fc.RealFixCount == 0 {
		t.Errorf("expected DMARC_ENFORCEMENT to count as a real fix at p=quarantine")
	}
}
