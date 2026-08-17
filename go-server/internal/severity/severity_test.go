// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package severity

import (
	"encoding/json"
	"testing"
)

// TestRankExactMatches pins every entry of the corrected map. The
// sign-off corrections (2026-08-15) are the load-bearing rows: a
// regression that moves indeterminate back to WARN or drops broken from
// FAIL re-opens the four-way template drift this package closed.
func TestRankExactMatches(t *testing.T) {
	cases := map[string]Tier{
		// FAIL
		"not configured": TierFail, "not_configured": TierFail,
		"missing": TierFail, "failed": TierFail, "fail": TierFail,
		"error": TierFail, "none": TierFail, "absent": TierFail,
		"no record": TierFail, "unsigned": TierFail,
		"broken": TierFail, "bogus": TierFail, "vulnerable": TierFail,
		"mismatch": TierFail,
		// WARN
		"basic": TierWarn, "partial": TierWarn, "partially signed": TierWarn,
		"warning": TierWarn, "warn": TierWarn, "incomplete": TierWarn,
		"soft fail": TierWarn, "softfail": TierWarn, "neutral": TierWarn,
		"degraded": TierWarn, "cert_invalid": TierWarn,
		// INFO
		"unavailable on provider": TierInfo, "unavailable_on_provider": TierInfo,
		"provider unsupported": TierInfo, "not applicable": TierInfo,
		"n/a": TierInfo, "could not be verified": TierInfo,
		"could not verify": TierInfo, "indeterminate": TierInfo,
		"unmeasured": TierInfo, "not measured": TierInfo,
		"unconfirmed": TierInfo, "inconclusive": TierInfo, "not deployed": TierInfo,
		"not_verifiable": TierInfo, "unreachable": TierInfo, "no_tlsa": TierInfo,
		// PASS
		"configured": TierPass, "enabled": TierPass, "protected": TierPass,
		"strongly protected": TierPass, "enterprise": TierPass,
		"pass": TierPass, "valid": TierPass, "verified": TierPass,
		"active": TierPass, "present": TierPass, "inherited": TierPass,
		"signed": TierPass,
	}
	if len(cases) != len(statusTier) {
		t.Errorf("test table has %d entries, map has %d — pin every entry", len(cases), len(statusTier))
	}
	for status, want := range cases {
		if got := Rank(status); got != want {
			t.Errorf("Rank(%q) = %v, want %v", status, got, want)
		}
	}
}

// TestRankDNSSECDisplayLabels pins the tier of every label
// dnssecDisplayLabel can emit (analyzer/dnssec.go), since display labels
// are one of the string families this map will rank in practice. If the
// analyzer grows a label this table doesn't know, add it BOTH there and
// here.
func TestRankDNSSECDisplayLabels(t *testing.T) {
	cases := map[string]Tier{
		"Signed":           TierPass,
		"Inherited":        TierPass,
		"Broken":           TierFail,
		"Unsigned":         TierFail,
		"Partially Signed": TierWarn,
		"Unconfirmed":      TierInfo,
		"Could Not Verify": TierInfo,
		"Not Measured":     TierInfo,
	}
	for label, want := range cases {
		if got := Rank(label); got != want {
			t.Errorf("Rank(%q) = %v, want %v", label, got, want)
		}
	}
}

// TestRankScorecardLabels pins the tier of every label the Engineer
// Report's Executive Scorecard can render (results_v2.html L0 band),
// since the scorecard's visual order is stamped from this map. "Not
// Setup" and "Open" deliberately ride the WARN fallback — neutral
// confirmed absences that should surface before INFO/PASS without a
// dedicated entry.
func TestRankScorecardLabels(t *testing.T) {
	cases := map[string]Tier{
		"Protected":      TierPass,
		"Enterprise":     TierPass,
		"Configured":     TierPass,
		"Monitoring":     TierWarn,
		"Partial":        TierWarn,
		"Basic":          TierWarn,
		"Not Setup":      TierWarn,
		"Open":           TierWarn,
		"Inconclusive":   TierInfo,
		"N/A — Registry": TierInfo,
		"Vulnerable":     TierFail,
		// c2b six-card strip additions (2026-08-16): the DANE card's
		// namespace-mapped labels + the protocol-dependent absence word.
		"Not Deployed":     TierInfo,
		"Verified":         TierPass,
		"Broken":           TierFail,
		"Could Not Verify": TierInfo,
		"Unconfirmed":      TierInfo,
	}
	for label, want := range cases {
		if got := Rank(label); got != want {
			t.Errorf("Rank(%q) = %v, want %v", label, got, want)
		}
	}
}

// TestRankFallback pins the substring fallback: longest fragment wins,
// matching is case- and whitespace-insensitive, and unknown strings
// surface as WARN rather than hiding in PASS.
func TestRankFallback(t *testing.T) {
	cases := map[string]Tier{
		// Longest fragment wins across tiers: "could not be verified"
		// (21) beats "unsigned" (8) inside the same string.
		"unsigned — could not be verified": TierInfo,
		// "unsigned" (8) beats its own substring "signed" (6).
		"zone unsigned": TierFail,
		// "partially signed" (16) beats "signed" (6).
		"DNSSEC partially signed at parent": TierWarn,
		// Case and surrounding whitespace are ignored.
		"  BROKEN  ":     TierFail,
		"Indeterminate":  TierInfo,
		"NOT CONFIGURED": TierFail,
		// Unknown → WARN, surface don't hide.
		"quantum flux reversal": TierWarn,
		"":                      TierWarn,
	}
	for status, want := range cases {
		if got := Rank(status); got != want {
			t.Errorf("Rank(%q) = %v, want %v", status, got, want)
		}
	}
}

// TestRankFragmentDeterminism freezes the tiebreak for equal-length
// fragments of different tiers: lexicographic ascending, so a string
// containing both "softfail" (WARN) and "unsigned" (FAIL) — both 8
// chars, neither an exact match — resolves via "softfail". Go map
// iteration order must never decide a rank.
func TestRankFragmentDeterminism(t *testing.T) {
	for i := 0; i < 100; i++ {
		if got := Rank("softfail/unsigned"); got != TierWarn {
			t.Fatalf("iteration %d: Rank(\"softfail/unsigned\") = %v, want TierWarn (lexicographic tiebreak)", i, got)
		}
	}
}

// TestTierOrdering pins the rank arithmetic the sign-off relies on: an
// unmeasurable state at INFO sorts above every PASS in ascending order.
func TestTierOrdering(t *testing.T) {
	if !(TierFail < TierWarn && TierWarn < TierInfo && TierInfo < TierPass) {
		t.Fatalf("tier ordering broken: FAIL=%d WARN=%d INFO=%d PASS=%d", TierFail, TierWarn, TierInfo, TierPass)
	}
	if Rank("unmeasured") >= Rank("configured") {
		t.Error("unmeasured must sort above (before) configured")
	}
}

// TestTierName pins the CSS/JSON names, including the out-of-range
// fallback.
func TestTierName(t *testing.T) {
	cases := map[Tier]string{TierFail: "fail", TierWarn: "warn", TierInfo: "info", TierPass: "pass", Tier(9): "warn"}
	for tier, want := range cases {
		if got := tier.Name(); got != want {
			t.Errorf("Tier(%d).Name() = %q, want %q", tier, got, want)
		}
	}
}

// TestRankJSON verifies the client-injection document round-trips and
// carries the corrections, so the window-global bridge serves the same
// vocabulary Rank uses.
func TestRankJSON(t *testing.T) {
	var doc struct {
		Rank    map[string]int `json:"rank"`
		Unknown int            `json:"unknown"`
	}
	if err := json.Unmarshal([]byte(RankJSON()), &doc); err != nil {
		t.Fatalf("RankJSON did not round-trip: %v", err)
	}
	if len(doc.Rank) != len(statusTier) {
		t.Errorf("RankJSON carries %d entries, map has %d", len(doc.Rank), len(statusTier))
	}
	for status, want := range map[string]int{"indeterminate": 2, "broken": 0, "inherited": 3, "unmeasured": 2} {
		if got, ok := doc.Rank[status]; !ok || got != want {
			t.Errorf("RankJSON rank[%q] = %d (present=%v), want %d", status, got, ok, want)
		}
	}
	if doc.Unknown != int(TierWarn) {
		t.Errorf("RankJSON unknown = %d, want %d", doc.Unknown, TierWarn)
	}
}
