package handlers

import (
	"encoding/json"
	"testing"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icsae"
)

// fixture: quarantine@100 with an otherwise strong posture (the owner's worked example)
func auditFixture(policy string) map[string]any {
	return map[string]any{
		"domain":            "audit-example.test",
		"is_tld":            false,
		"has_null_mx":       false,
		"is_no_mail_domain": false,
		"basic_records":     map[string]any{"MX": []string{"mx1.audit-example.test"}},
		"mail_posture":      map[string]any{"verdict": "mail", "is_no_mail": false},
		"spf_analysis": map[string]any{
			"status": "success", "spf_state": "present",
			"all_mechanism": "-all", "lookup_count": 5,
		},
		"dmarc_analysis": map[string]any{
			"status": "success", "dmarc_state": "present",
			"policy": policy, "pct": 100,
			"rua": "mailto:dmarc@audit-example.test",
			"sp":  policy, "adkim": "s", "aspf": "s",
		},
		"dkim_analysis": map[string]any{
			"status": "success", "primary_has_dkim": true,
			"primary_provider": "Google Workspace", "selectors_checked": []string{"google"},
		},
		"dnssec_analysis": map[string]any{
			"status": "success", "dnssec_state": "signed", "ad_flag": true,
			"chain_of_trust":        "complete",
			"algorithm_observation": map[string]any{"strength": "strong"},
		},
		"cds_cdnskey": map[string]any{"has_cds": true, "has_cdnskey": true, "automation": "active"},
		"dane_analysis": map[string]any{
			"status": "success", "dane_state": "present", "has_dane": true,
			"dane_deployable": true, "tlsa_record_count": 2,
		},
		"mta_sts_analysis":       map[string]any{"status": "success", "mta_sts_state": "present", "mode": "enforce"},
		"tlsrpt_analysis":        map[string]any{"status": "success", "tlsrpt_state": "present"},
		"caa_analysis":           map[string]any{"status": "success", "caa_state": "present", "records": []string{"0 issue \"letsencrypt.org\""}},
		"bimi_analysis":          map[string]any{"status": "success", "bimi_state": "present", "logo_valid": true},
		"security_txt":           map[string]any{"found": true, "expired": false},
		"dangling_dns":           map[string]any{"status": "success", "dangling_count": 0},
		"delegation_consistency": map[string]any{"status": "success"},
		"secret_exposure":        map[string]any{"status": "clear", "finding_count": 0},
		"https_svcb":             map[string]any{"has_https": true, "has_svcb": true},
		"ns_delegation_analysis": map[string]any{"enterprise_pattern": "dedicated"},
		"dns_infrastructure":     map[string]any{"explains_no_dnssec": false},
	}
}

// roundTrip marshals then unmarshals so buildHistoryItem sees exactly what the DB
// column would hand it (all numbers float64, structs flattened to maps).
func roundTrip(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuditHistoryPillBothBranches(t *testing.T) {
	for _, policy := range []string{"quarantine", "reject"} {
		for _, withICSAE := range []bool{true, false} {
			results := auditFixture(policy)
			a := &analyzer.Analyzer{}
			posture := a.CalculatePosture(results)
			results["posture"] = posture

			ev := icsae.Evaluate(results)
			fc := icsae.ClassifyFromEval(ev, results)
			if withICSAE {
				results["icsae_evaluation"] = ev
			}

			item := buildHistoryItem(dbq.DomainAnalysis{
				ID: 1, Domain: "audit-example.test", AsciiDomain: "audit-example.test",
				FullResults: roundTrip(t, results),
			})

			pm, _ := posture["critical_issues"].([]string)
			rm, _ := posture["recommendations"].([]string)
			t.Logf("policy=%-10s icsae=%-5v -> FixCount=%d FixColor=%q | posture.critical=%d posture.recs=%d | icsae.RealFixCount=%d icsae.Color=%q high=%v med=%v low=%v",
				policy, withICSAE, item.FixCount, item.FixColor,
				len(pm), len(rm), fc.RealFixCount, fc.Color,
				ev.HighFailures, ev.MediumFailures, ev.LowFailures)
			if len(rm) > 0 {
				t.Logf("    recommendations: %v", rm)
			}
			t.Logf("    icsae real_fixes=%v by_design=%v hygiene=%v couldnt_verify=%v", fc.RealFixes, fc.ByDesign, fc.Hygiene, fc.CouldntVerify)
		}
	}
}
