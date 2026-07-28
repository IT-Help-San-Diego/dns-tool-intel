package icsae

import "testing"

func TestZZAdvEnterpriseFixture(t *testing.T) {
	fr := map[string]any{
		"posture":                 map[string]any{"provider_limited": []interface{}{}},
		"dmarc_analysis":          map[string]any{"policy": "reject"},
		"dnssec_analysis":         map[string]any{"dnssec_state": "absent_confirmed"},
		"ns_delegation_analysis":  map[string]any{"enterprise_pattern": "dedicated"},
		"dns_infrastructure":      map[string]any{},
		"icsae_evaluation": map[string]any{
			"passed":          []interface{}{"SPF_EFFECTIVE_POLICY", "CAA_RESTRICTION_PRESENT", "DMARC_ENFORCED", "MAIL_POLICY_SIGNALING"},
			"high_failures":   []interface{}{"DNSSEC_AUTHENTICATED"},
			"medium_failures": []interface{}{"DNSSEC_CHAIN_TRUSTED", "DANE_DEPLOYED"},
			"low_failures":    []interface{}{"BIMI_CONFIGURED"},
		},
	}
	fc, ok := ClassifyFromResults(fr)
	if !ok {
		t.Fatal("ok=false")
	}
	t.Logf("RealFixCount=%d real=%v byDesign=%v platformLimited=%v hygiene=%v color=%q",
		fc.RealFixCount, fc.RealFixes, fc.ByDesign, fc.PlatformLimited, fc.Hygiene, fc.Color)

	// Same scan, but DANE genuinely unsupported by the mail platform.
	fr2 := map[string]any{}
	for k, v := range fr {
		fr2[k] = v
	}
	fr2["posture"] = map[string]any{"provider_limited": []interface{}{"DANE"}}
	fc2, _ := ClassifyFromResults(fr2)
	t.Logf("provider-limited DANE: RealFixCount=%d platformLimited=%v hygiene=%v", fc2.RealFixCount, fc2.PlatformLimited, fc2.Hygiene)
}
