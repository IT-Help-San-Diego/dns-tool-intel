// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "testing"

// Deliberately UNTAGGED. A guard that only runs under -tags coverage is a guard
// that does not run; this package has been bitten by that before.

func dmarcResult(state, policy, sp, aspf, adkim string, pct int) map[string]any {
	return map[string]any{
		mapKeyDmarcState:   state,
		"policy":           policy,
		"subdomain_policy": sp,
		"aspf":             aspf,
		"adkim":            adkim,
		"pct":              pct,
	}
}

func hasRule(fs []CrossRecordFinding, r CrossRecordRule) bool {
	for _, f := range fs {
		if f.Rule == r {
			return true
		}
	}
	return false
}

// The spec's constraint 2: a lookup that did not complete is not an absence. An
// indeterminate input must produce NO finding — not a passing one, and not a
// finding computed from a zero value. Both directions are asserted on the same
// fixture, so a pass cannot come from a fixture that was never eligible.
func TestCrossRecord_IndeterminateNeverProducesFinding(t *testing.T) {
	eligible := dmarcResult(triStatePresent, "none", "reject", alignStrict, alignStrict, 100)
	if got := EvaluateCrossRecordConsistency(map[string]any{"dmarc": eligible}); !hasRule(got, RuleInvertedRamp) {
		t.Fatalf("fixture is not eligible — the negative case below would prove nothing: %+v", got)
	}

	indet := dmarcResult(triStateIndeterminate, "none", "reject", alignStrict, alignStrict, 100)
	if got := EvaluateCrossRecordConsistency(map[string]any{"dmarc": indet}); len(got) != 0 {
		t.Errorf("indeterminate DMARC lookup produced %d finding(s); absence may only be "+
			"asserted from an authoritative answer: %+v", len(got), got)
	}
}

// R1 fires only when sp is STRICTLY stronger than p. Equal or weaker is the
// conventional ramp and must stay silent.
func TestCrossRecord_InvertedRampStrictlyStronger(t *testing.T) {
	cases := []struct {
		p, sp string
		want  bool
	}{
		{"none", "reject", true},
		{"none", "quarantine", true},
		{"quarantine", "reject", true},
		{"reject", "reject", false},
		{"reject", "none", false},
		{"quarantine", "quarantine", false},
		{"none", "", false},
	}
	for _, c := range cases {
		res := dmarcResult(triStatePresent, c.p, c.sp, alignRelaxedTest, alignRelaxedTest, 100)
		got := hasRule(EvaluateCrossRecordConsistency(map[string]any{"dmarc": res}), RuleInvertedRamp)
		if got != c.want {
			t.Errorf("p=%q sp=%q: inverted-ramp finding = %v, want %v", c.p, c.sp, got, c.want)
		}
	}
}

const alignRelaxedTest = "relaxed"

// R3 reads the words the analyzer stores ("strict"), not the wire values ("s").
// A rule comparing against "s" compiles, passes review, and never fires.
func TestCrossRecord_StrictAlignmentUsesStoredVocabulary(t *testing.T) {
	stored := dmarcResult(triStatePresent, "quarantine", "", alignStrict, alignStrict, 100)
	if !hasRule(EvaluateCrossRecordConsistency(map[string]any{"dmarc": stored}), RuleStrictSoft) {
		t.Error("R3 did not fire on aspf/adkim = \"strict\" — it is reading the wrong vocabulary")
	}
	wire := dmarcResult(triStatePresent, "quarantine", "", "s", "s", 100)
	if hasRule(EvaluateCrossRecordConsistency(map[string]any{"dmarc": wire}), RuleStrictSoft) {
		t.Error("R3 fired on the raw wire value \"s\", which the analyzer never stores")
	}
}

// R6 is a population statistic (68% of domains), deliberately not a per-domain
// finding. Nothing here may emit it.
func TestCrossRecord_NoPopulationStatisticAsFinding(t *testing.T) {
	res := map[string]any{
		"dmarc":   dmarcResult(triStateAbsentConf, "", "", alignRelaxedTest, alignRelaxedTest, 100),
		"mta_sts": map[string]any{mapKeyMtaStsState: triStateAbsentConf},
		"dnssec":  map[string]any{mapKeyDnssecState: triStateAbsentConf},
	}
	for _, f := range EvaluateCrossRecordConsistency(res) {
		if f.Rule == "no_transport_anchor" {
			t.Error("R6 emitted as a per-domain finding; it fires on 68% of domains and is a baseline")
		}
	}
}

// R2, R4 and R5 shipped with no direct coverage. A rule that reads the wrong key
// or the wrong vocabulary compiles, reviews clean, and never fires — which is how
// R3 nearly shipped comparing against the RFC wire value "s" instead of the
// "strict" the analyzer actually stores. Each test below asserts BOTH directions
// on the same fixture, so a pass cannot come from a fixture that was never
// eligible in the first place.

func TestCrossRecord_R2_TransportEnforcedSenderNot(t *testing.T) {
	mtaPresent := map[string]any{mapKeyMtaStsState: triStatePresent}
	mtaAbsent := map[string]any{mapKeyMtaStsState: triStateAbsentConf}
	mtaIndet := map[string]any{mapKeyMtaStsState: triStateIndeterminate}

	cases := []struct {
		name  string
		mta   map[string]any
		dmarc map[string]any
		want  bool
	}{
		{"MTA-STS + p=none fires", mtaPresent,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), true},
		{"MTA-STS + DMARC absent fires", mtaPresent,
			dmarcResult(triStateAbsentConf, "", "", alignRelaxedTest, alignRelaxedTest, 100), true},
		{"MTA-STS + p=reject silent", mtaPresent,
			dmarcResult(triStatePresent, "reject", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"MTA-STS + p=quarantine silent", mtaPresent,
			dmarcResult(triStatePresent, "quarantine", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"no MTA-STS silent", mtaAbsent,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"MTA-STS indeterminate silent", mtaIndet,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), false},
	}
	for _, c := range cases {
		got := hasRule(EvaluateCrossRecordConsistency(
			map[string]any{"dmarc": c.dmarc, "mta_sts": c.mta}), RuleTransportOnly)
		if got != c.want {
			t.Errorf("%s: finding = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCrossRecord_R4_PartialEnforcement(t *testing.T) {
	cases := []struct {
		policy string
		pct    int
		want   bool
	}{
		{"reject", 50, true},
		{"quarantine", 99, true},
		{"reject", 100, false}, // full application — the ordinary case
		{"none", 50, false},    // pct is moot when nothing is enforced
		{"quarantine", 100, false},
	}
	for _, c := range cases {
		res := dmarcResult(triStatePresent, c.policy, "", alignRelaxedTest, alignRelaxedTest, c.pct)
		got := hasRule(EvaluateCrossRecordConsistency(map[string]any{"dmarc": res}), RulePartialEnforce)
		if got != c.want {
			t.Errorf("p=%s pct=%d: finding = %v, want %v", c.policy, c.pct, got, c.want)
		}
	}
}

func TestCrossRecord_R5_BIMIWithoutEnforcement(t *testing.T) {
	bimiPresent := map[string]any{mapKeyBimiState: triStatePresent}
	bimiAbsent := map[string]any{mapKeyBimiState: triStateAbsentConf}
	bimiIndet := map[string]any{mapKeyBimiState: triStateIndeterminate}

	cases := []struct {
		name  string
		bimi  map[string]any
		dmarc map[string]any
		want  bool
	}{
		{"BIMI + p=none fires", bimiPresent,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), true},
		{"BIMI + DMARC absent fires", bimiPresent,
			dmarcResult(triStateAbsentConf, "", "", alignRelaxedTest, alignRelaxedTest, 100), true},
		{"BIMI + p=quarantine silent", bimiPresent,
			dmarcResult(triStatePresent, "quarantine", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"BIMI + p=reject silent", bimiPresent,
			dmarcResult(triStatePresent, "reject", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"no BIMI silent", bimiAbsent,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), false},
		{"BIMI indeterminate silent", bimiIndet,
			dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100), false},
	}
	for _, c := range cases {
		got := hasRule(EvaluateCrossRecordConsistency(
			map[string]any{"dmarc": c.dmarc, "bimi": c.bimi}), RuleBIMIWithoutEnforce)
		if got != c.want {
			t.Errorf("%s: finding = %v, want %v", c.name, got, c.want)
		}
	}
}

// Every rule must be reachable. This fails if a rule is added without a fixture
// that fires it — the "three rules, zero tests" state this file shipped in.
func TestCrossRecord_EveryRuleHasAFiringFixture(t *testing.T) {
	fired := map[CrossRecordRule]bool{}
	fixtures := []map[string]any{
		{"dmarc": dmarcResult(triStatePresent, "none", "reject", alignRelaxedTest, alignRelaxedTest, 100)},
		{"dmarc": dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100),
			"mta_sts": map[string]any{mapKeyMtaStsState: triStatePresent}},
		{"dmarc": dmarcResult(triStatePresent, "quarantine", "", alignStrict, alignStrict, 100)},
		{"dmarc": dmarcResult(triStatePresent, "reject", "", alignRelaxedTest, alignRelaxedTest, 50)},
		{"dmarc": dmarcResult(triStatePresent, "none", "", alignRelaxedTest, alignRelaxedTest, 100),
			"bimi": map[string]any{mapKeyBimiState: triStatePresent}},
	}
	for _, f := range fixtures {
		for _, found := range EvaluateCrossRecordConsistency(f) {
			fired[found.Rule] = true
		}
	}
	for _, r := range []CrossRecordRule{
		RuleInvertedRamp, RuleTransportOnly, RuleStrictSoft,
		RulePartialEnforce, RuleBIMIWithoutEnforce,
	} {
		if !fired[r] {
			t.Errorf("rule %q never fired on any fixture — it may be unreachable "+
				"(wrong key, wrong vocabulary, or a condition that cannot hold)", r)
		}
	}
}
