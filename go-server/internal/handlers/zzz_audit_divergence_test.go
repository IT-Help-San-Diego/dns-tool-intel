package handlers

import (
	"testing"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icsae"
)

// Each scenario mutates the strong baseline to hit one of the ICSAE "honest
// context" buckets — the cases ICSAE removes from the headline but the legacy
// posture fallback still counts.
func TestAuditCountDivergence(t *testing.T) {
	scenarios := map[string]func(map[string]any){
		"baseline-reject-perfect": func(fr map[string]any) {},
		"quarantine@100": func(fr map[string]any) {
			d := fr["dmarc_analysis"].(map[string]any)
			d["policy"] = "quarantine"
			d["sp"] = "quarantine"
		},
		"enterprise-unsigned-dnssec": func(fr map[string]any) {
			fr["dnssec_analysis"] = map[string]any{
				"status": "success", "dnssec_state": "absent_confirmed", "ad_flag": false,
			}
			fr["ns_delegation_analysis"] = map[string]any{"enterprise_pattern": "dedicated"}
			fr["cds_cdnskey"] = map[string]any{"has_cds": false, "has_cdnskey": false}
		},
		"dane-absent-provider-limited": func(fr map[string]any) {
			fr["dane_analysis"] = map[string]any{
				"status": "success", "dane_state": "absent", "has_dane": false,
				"dane_deployable": false, "tlsa_record_count": 0,
				"provider_limitation": true,
			}
		},
		"dkim-selector-not-found": func(fr map[string]any) {
			fr["dkim_analysis"] = map[string]any{
				"status": "success", "primary_has_dkim": false,
				"selectors_checked": []string{"default", "google", "selector1"},
			}
		},
		"no-dnssec-small-operator": func(fr map[string]any) {
			fr["dnssec_analysis"] = map[string]any{
				"status": "success", "dnssec_state": "absent_confirmed", "ad_flag": false,
			}
			fr["ns_delegation_analysis"] = map[string]any{"enterprise_pattern": "managed"}
			fr["cds_cdnskey"] = map[string]any{"has_cds": false, "has_cdnskey": false}
		},
	}

	names := []string{
		"baseline-reject-perfect", "quarantine@100", "enterprise-unsigned-dnssec",
		"dane-absent-provider-limited", "dkim-selector-not-found", "no-dnssec-small-operator",
	}

	t.Logf("%-30s | %-16s | %-16s | diverges?", "scenario", "ICSAE pill", "legacy pill")
	for _, name := range names {
		mut := scenarios[name]
		var icsaeItem, legacyItem struct {
			count int
			color string
		}
		for _, withICSAE := range []bool{true, false} {
			fr := auditFixture("reject")
			mut(fr)
			a := &analyzer.Analyzer{}
			fr["posture"] = a.CalculatePosture(fr)
			ev := icsae.Evaluate(fr)
			if withICSAE {
				fr["icsae_evaluation"] = ev
			}
			item := buildHistoryItem(dbq.DomainAnalysis{
				ID: 1, Domain: "audit-example.test", AsciiDomain: "audit-example.test",
				FullResults: roundTrip(t, fr),
			})
			if withICSAE {
				icsaeItem.count, icsaeItem.color = item.FixCount, item.FixColor
			} else {
				legacyItem.count, legacyItem.color = item.FixCount, item.FixColor
			}
		}
		diverge := ""
		if icsaeItem.count != legacyItem.count {
			diverge = "COUNT DIFFERS"
		} else if icsaeItem.color != legacyItem.color {
			diverge = "colour differs"
		}
		t.Logf("%-30s | %d / %-12q | %d / %-12q | %s",
			name, icsaeItem.count, icsaeItem.color, legacyItem.count, legacyItem.color, diverge)
	}
}
