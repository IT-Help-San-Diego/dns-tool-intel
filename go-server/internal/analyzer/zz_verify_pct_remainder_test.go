package analyzer

import (
	"testing"
)

// Verification-only: for p=quarantine with pct<100, what status does the DMARC
// analyzer assign, and can posture.go:505 and posture.go:779 fire together?
func TestVerifyPctRemainder(t *testing.T) {
	st, msg, iss := classifyDMARCPolicyVerdict("quarantine", 20)
	t.Logf("classifyDMARCPolicyVerdict(quarantine,20) -> status=%q msg=%q issues=%v", st, msg, iss)
	st2, msg2, iss2 := classifyDMARCPolicyVerdict("quarantine", 100)
	t.Logf("classifyDMARCPolicyVerdict(quarantine,100) -> status=%q msg=%q issues=%v", st2, msg2, iss2)

	for _, status := range []string{"warning", "success"} {
		results := map[string]any{
			"domain": "verify-pct.example",
			"spf_analysis": map[string]any{
				"status":        "success",
				"all_mechanism": "~all",
				"record":        "v=spf1 include:_spf.example.com ~all",
			},
			"dmarc_analysis": map[string]any{
				"status": status,
				"policy": "quarantine",
				"pct":    20,
				"rua":    "mailto:dmarc@verify-pct.example",
				"record": "v=DMARC1; p=quarantine; pct=20; rua=mailto:dmarc@verify-pct.example",
			},
			"dkim_analysis": map[string]any{
				"status": "success",
			},
			"mx_records": []string{"10 mx.example.com."},
		}

		a := &Analyzer{}
		posture := a.CalculatePosture(results)
		rem := a.GenerateRemediation(results)

		t.Logf("=== dmarc status fixture = %q ===", status)
		t.Logf("deliberate=%v", posture["deliberate_monitoring"])
		t.Logf("note=%q", posture["deliberate_monitoring_note"])
		if c, ok := posture["configured"].([]string); ok {
			t.Logf("configured=%v (n=%d)", c, len(c))
		}
		if m, ok := posture["monitoring"].([]string); ok {
			for _, s := range m {
				t.Logf("MON: %s", s)
			}
		}
		if r, ok := posture["recommendations"].([]string); ok {
			for _, s := range r {
				t.Logf("REC: %s", s)
			}
		}
		if i, ok := posture["issues"].([]string); ok {
			for _, s := range i {
				t.Logf("ISSUE: %s", s)
			}
		}
		t.Logf("state=%v message=%v", posture["state"], posture["message"])
		if af, ok := rem["all_fixes"].([]map[string]any); ok {
			for _, f := range af {
				t.Logf("ALLFIX: %v | sev=%v | %v", f["title"], f["severity"], f["description"])
			}
		}
		t.Logf("fix_count=%v", rem["fix_count"])
	}
}
