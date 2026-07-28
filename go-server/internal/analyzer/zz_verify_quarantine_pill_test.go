package analyzer

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/icsae"
)

func fixtureQuarantinePerfect(policy string) map[string]any {
	return map[string]any{
		"domain":            "example-deliberate.test",
		"is_tld":            false,
		"has_null_mx":       false,
		"is_no_mail_domain": false,
		"basic_records": map[string]any{
			"MX": []string{"mx1.example-deliberate.test"},
		},
		"mail_posture": map[string]any{"verdict": "mail", "is_no_mail": false},
		"spf_analysis": map[string]any{
			"status":        "success",
			"spf_state":     "present",
			"all_mechanism": "-all",
			"lookup_count":  5,
		},
		"dmarc_analysis": map[string]any{
			"status":      "success",
			"dmarc_state": "present",
			"policy":      policy,
			"pct":         100,
			"rua":         "mailto:dmarc@example-deliberate.test",
			"ruf":         "mailto:forensics@example-deliberate.test",
			"sp":          policy,
			"adkim":       "s",
			"aspf":        "s",
		},
		"dkim_analysis": map[string]any{
			"status":            "success",
			"primary_has_dkim":  true,
			"primary_provider":  "Google Workspace",
			"selectors_checked": []string{"google"},
		},
		"dnssec_analysis": map[string]any{
			"status":         "success",
			"dnssec_state":   "signed",
			"ad_flag":        true,
			"chain_of_trust": "complete",
			"algorithm_observation": map[string]any{
				"strength": "strong",
			},
		},
		"cds_cdnskey": map[string]any{
			"has_cds":     true,
			"has_cdnskey": true,
			"automation":  "active",
		},
		"dane_analysis": map[string]any{
			"status":            "success",
			"dane_state":        "present",
			"has_dane":          true,
			"dane_deployable":   true,
			"tlsa_record_count": 2,
		},
		"mta_sts_analysis": map[string]any{"status": "success", "mta_sts_state": "present", "mode": "enforce"},
		"tlsrpt_analysis":  map[string]any{"status": "success", "tlsrpt_state": "present"},
		"caa_analysis": map[string]any{
			"status":    "success",
			"caa_state": "present",
			"records":   []string{"0 issue \"letsencrypt.org\""},
		},
		"bimi_analysis": map[string]any{
			"status":     "success",
			"bimi_state": "present",
			"logo_valid": true,
		},
		"security_txt":           map[string]any{"found": true, "expired": false},
		"dangling_dns":           map[string]any{"status": "success", "dangling_count": 0},
		"delegation_consistency": map[string]any{"status": "success"},
		"secret_exposure":        map[string]any{"status": "clear", "finding_count": 0},
		"https_svcb":             map[string]any{"has_https": true, "has_svcb": true},
		"ns_delegation_analysis": map[string]any{"enterprise_pattern": "dedicated"},
		"dns_infrastructure":     map[string]any{"explains_no_dnssec": false},
	}
}

func TestVerifyQuarantineDeliberateVsPill(t *testing.T) {
	for _, policy := range []string{"quarantine", "reject"} {
		results := fixtureQuarantinePerfect(policy)
		a := &Analyzer{}
		posture := a.CalculatePosture(results)
		results["posture"] = posture
		ev := icsae.Evaluate(results)
		fc := icsae.ClassifyFromEval(ev, results)

		b, _ := json.Marshal(map[string]any{
			"policy":           policy,
			"state":            posture["state"],
			"color":            posture["color"],
			"deliberate":       posture["deliberate_monitoring"],
			"deliberate_note":  posture["deliberate_monitoring_note"],
			"critical_issues":  posture["critical_issues"],
			"recommendations":  posture["recommendations"],
			"issues":           posture["issues"],
			"configured":       posture["configured"],
			"monitoring":       posture["monitoring"],
			"high_failures":    ev.HighFailures,
			"medium_failures":  ev.MediumFailures,
			"low_failures":     ev.LowFailures,
			"real_fix_count":   fc.RealFixCount,
			"fix_color":        fc.Color,
			"real_fixes":       fc.RealFixes,
			"by_design":        fc.ByDesign,
			"hygiene":          fc.Hygiene,
			"couldnt_verify":   fc.CouldntVerify,
			"platform_limited": fc.PlatformLimited,
		})
		t.Logf("RESULT %s: %s", policy, string(b))

		// Round-trip through the persisted full_results form, which is exactly
		// what /history re-reads (icsaeFixSummary -> ClassifyFromResults).
		results["icsae_evaluation"] = ev
		blob, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var fr map[string]any
		if err := json.Unmarshal(blob, &fr); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		fc2, ok := icsae.ClassifyFromResults(fr)
		posture2, _ := fr["posture"].(map[string]any)
		t.Logf("ROUNDTRIP %s: ok=%v real_fix_count=%d color=%q real_fixes=%v | history badge: state=%v color=%v deliberate=%v",
			policy, ok, fc2.RealFixCount, fc2.Color, fc2.RealFixes,
			posture2["state"], posture2["color"], posture2["deliberate_monitoring"])
	}
}
