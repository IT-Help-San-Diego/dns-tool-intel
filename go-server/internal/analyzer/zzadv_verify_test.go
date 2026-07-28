package analyzer

import (
	"strings"
	"testing"
)

// TestAdversarialSimultaneity checks whether the working-tree ruf-note branch and
// the three "raise the policy" paths can fire for one and the same domain.
func TestAdversarialSimultaneity(t *testing.T) {
	// cia.gov-shaped record: p=quarantine, rua + ruf, no explicit pct (default 100).
	rec := "v=DMARC1; p=quarantine; rua=mailto:rua@example.gov; ruf=mailto:ruf@example.gov; fo=1"
	_, _, issues, tags := evaluateDMARCRecordSet([]string{rec})
	t.Logf("policy=%v pct=%d rua=%v ruf=%v issues=%v", derefStr(tags.policy), tags.pct, derefStr(tags.rua), derefStr(tags.ruf), issues)

	note := buildRUFNote(tags)
	detail, _ := note["detail"].(string)
	posture, hasPosture := note["posture"]
	t.Logf("RUF note posture key present=%v value=%v", hasPosture, posture)
	if !strings.Contains(detail, "does not recommend removing ruf= or raising the policy from the record alone") {
		t.Errorf("RUF NOTE: promise sentence NOT present. detail=%q", detail)
	} else {
		t.Logf("RUF NOTE: promise sentence PRESENT")
	}

	// Build a results map with a strong surrounding config so configuredCount >= 2.
	results := map[string]any{
		"domain": "example.gov",
		"dmarc_analysis": map[string]any{
			"status":      "success",
			"policy":      "quarantine",
			"pct":         100,
			"rua":         "mailto:rua@example.gov",
			"ruf":         "mailto:ruf@example.gov",
			"dmarc_state": "present",
			"issues":      []string{},
			"ruf_note":    note,
		},
		"spf_analysis": map[string]any{
			"status":    "success",
			"record":    "v=spf1 -all",
			"all_mechanism": "-all",
			"spf_state": "present",
			"issues":    []string{},
		},
		"dkim_analysis": map[string]any{
			"status":  "success",
			"issues":  []string{},
			"selectors_found": []string{"default"},
		},
		"caa_analysis":    map[string]any{"status": "success", "caa_state": "present"},
		"dnssec_analysis": map[string]any{"status": "success", "enabled": true},
	}

	ps := evaluateProtocolStates(results)
	t.Logf("ps.dmarcOK=%v dmarcWarning=%v dmarcPolicy=%q dmarcPct=%d dmarcHasRua=%v spfOK=%v",
		ps.dmarcOK, ps.dmarcWarning, ps.dmarcPolicy, ps.dmarcPct, ps.dmarcHasRua, ps.spfOK)

	a := &Analyzer{}
	p := a.CalculatePosture(results)
	recs, _ := p["recommendations"].([]string)
	foundUpgrade := false
	for _, r := range recs {
		if strings.Contains(r, "Upgrade DMARC policy from quarantine to reject") {
			foundUpgrade = true
		}
	}
	t.Logf("POSTURE recommendations = %v", recs)
	t.Logf("POSTURE upgrade-to-reject recommendation present = %v", foundUpgrade)
	t.Logf("POSTURE deliberate_monitoring=%v", p["deliberate_monitoring"])
	t.Logf("POSTURE deliberate_monitoring_note=%v", p["deliberate_monitoring_note"])
	t.Logf("POSTURE configured=%v", p["configured"])

	// Remediation fixes
	fixes := appendDMARCFixes(nil, ps, results, "example.gov")
	foundFix := false
	for _, f := range fixes {
		t.Logf("FIX: %q severity=%v", f.Title, f.SeverityLevel)
		if f.Title == "Upgrade DMARC to Reject" {
			foundFix = true
		}
	}
	t.Logf("REMEDIATION upgrade-to-reject fix present = %v", foundFix)

	if foundUpgrade && foundFix && strings.Contains(detail, "does not recommend") {
		t.Logf("SIMULTANEOUS: all three fire on the same domain in the same run")
	} else {
		t.Errorf("NOT simultaneous: rufPromise=%v posture=%v fix=%v", strings.Contains(detail, "does not recommend"), foundUpgrade, foundFix)
	}
}
