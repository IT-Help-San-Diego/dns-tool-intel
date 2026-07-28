package analyzer

import (
	"encoding/json"
	"os"
	"testing"

	"dnstool/go-server/internal/icsae"
)

func loadFR(t *testing.T, p string) map[string]any {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		FullResults map[string]any `json:"full_results"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return w.FullResults
}

func report(t *testing.T, name string, fr map[string]any) {
	a := &Analyzer{}
	rem := a.GenerateRemediation(fr)
	titles := []string{}
	for _, f := range rem["all_fixes"].([]map[string]any) {
		titles = append(titles, f["title"].(string)+"["+f["severity_label"].(string)+"]")
	}
	ev := icsae.Evaluate(fr)
	fr["icsae_evaluation"] = ev
	b, _ := json.Marshal(fr)
	var rt map[string]any
	_ = json.Unmarshal(b, &rt)
	fc, ok := icsae.ClassifyFromResults(rt)
	t.Logf("%s:\n   analyzer fix_count=%v titles=%v\n   icsae ok=%v RealFixCount=%d color=%q realfixes=%v byDesign=%v hygiene=%v",
		name, rem["fix_count"], titles, ok, fc.RealFixCount, fc.Color, fc.RealFixes, fc.ByDesign, fc.Hygiene)
}

func TestZZQXrefProbe(t *testing.T) {
	// A: quarantine@100 derived from a real mail domain fixture
	fr := loadFR(t, "../icsae/testdata/dns-intelligence-dnstool.it-help.tech.input.json")
	dm, _ := fr["dmarc_analysis"].(map[string]any)
	dm["policy"] = "quarantine"
	dm["pct"] = float64(100)
	if raw, ok := dm["record"].(string); ok {
		_ = raw
		dm["record"] = "v=DMARC1; p=quarantine; rua=mailto:x@dnstool.it-help.tech"
	}
	report(t, "MUTATED quarantine@100 (dnstool.it-help.tech)", fr)

	// B: enterprise reject + authoritatively-unsigned DNSSEC
	fr2 := loadFR(t, "../icsae/testdata/dns-intelligence-dnstool.it-help.tech.input.json")
	if d, ok := fr2["dnssec_analysis"].(map[string]any); ok {
		d["dnssec_state"] = "absent_confirmed"
		d["status"] = "insecure"
		d["enabled"] = false
		d["valid"] = false
		d["chain_valid"] = false
	}
	if ns, ok := fr2["ns_delegation_analysis"].(map[string]any); ok {
		ns["enterprise_pattern"] = "dedicated"
	} else {
		fr2["ns_delegation_analysis"] = map[string]any{"enterprise_pattern": "dedicated"}
	}
	report(t, "MUTATED enterprise reject + unsigned DNSSEC", fr2)
}
