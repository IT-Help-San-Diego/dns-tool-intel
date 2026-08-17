// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science

// Package severity is the single source of truth for ranking analyzer
// status strings into display tiers. Both report surfaces (the Engineer
// Report card sort and the topology page) consume this map — never a
// local copy. The four-way template drift of 2026-08 happened because
// each consumer ranked statuses independently; this package exists so
// that can't recur.
//
// Tier semantics (ascending rank renders first):
//
//	FAIL 0 — measured adverse result
//	WARN 1 — measured qualified result; also the unknown-status fallback
//	INFO 2 — could not be measured (unmeasurable is not a defect)
//	PASS 3 — measured affirmative result
//
// The rank arithmetic is deliberate: an unmeasurable state at INFO sorts
// above every PASS, so it stays visible and ranked ahead of things that
// are fine, while no longer sitting beside softfail as though the domain
// did something wrong (the denominator doctrine expressed in reading
// order). Sorting tier is not the same thing as badge color: a confirmed
// unsigned zone ranks FAIL for ordering even where its badge severity is
// "warning" — position claims urgency, the badge claims a verdict.
//
// Unknown statuses rank WARN — surface, don't hide. Note the asymmetry
// with ring styling on the topology page, where an unknown state must
// draw dashed (could-not-measure): rank is about where a state appears,
// the ring is about what we claim to know. An unknown state appears
// early AND claims nothing.
package severity

import (
	"encoding/json"
	"sort"
	"strings"
)

// Tier is a display rank; ascending order renders first.
type Tier int

// Ascending display tiers. The zero value is TierFail on purpose: a
// status that somehow bypasses Rank should surface at the top, not
// vanish into PASS.
const (
	TierFail Tier = 0
	TierWarn Tier = 1
	TierInfo Tier = 2
	TierPass Tier = 3
)

// Name returns the lowercase tier name used in CSS classes and JSON.
func (t Tier) Name() string {
	switch t {
	case TierFail:
		return "fail"
	case TierWarn:
		return "warn"
	case TierInfo:
		return "info"
	case TierPass:
		return "pass"
	}
	return "warn"
}

// statusTier is the corrected port of the severity_sort.js STATUS_RANK
// map (design handoff, Engineer Report v2.1), with the 2026-08-15
// sign-off corrections applied: could-not-verify/indeterminate moved
// WARN→INFO; unmeasured/not measured/unconfirmed/inconclusive added at
// INFO; broken/bogus added at FAIL; inherited/signed added at PASS.
// "partially signed" is an explicit WARN entry because the substring
// fallback would otherwise match "signed" and rank a broken chain PASS.
var statusTier = map[string]Tier{
	// FAIL — measured adverse
	"not configured": TierFail,
	"not_configured": TierFail,
	"missing":        TierFail,
	"failed":         TierFail,
	"fail":           TierFail,
	"error":          TierFail,
	"none":           TierFail,
	"absent":         TierFail,
	"no record":      TierFail,
	"unsigned":       TierFail,
	"broken":         TierFail,
	"bogus":          TierFail,
	"vulnerable":     TierFail,
	"mismatch":       TierFail,

	// WARN — measured qualified
	"basic":            TierWarn,
	"partial":          TierWarn,
	"partially signed": TierWarn,
	"warning":          TierWarn,
	"warn":             TierWarn,
	"incomplete":       TierWarn,
	"soft fail":        TierWarn,
	"softfail":         TierWarn,
	"neutral":          TierWarn,
	"degraded":         TierWarn,
	"cert_invalid":     TierWarn,

	// INFO — could not be measured
	"unavailable on provider": TierInfo,
	"unavailable_on_provider": TierInfo,
	"provider unsupported":    TierInfo,
	"not applicable":          TierInfo,
	"n/a":                     TierInfo,
	"could not be verified":   TierInfo,
	"could not verify":        TierInfo,
	"indeterminate":           TierInfo,
	"unmeasured":              TierInfo,
	"not measured":            TierInfo,
	"unconfirmed":             TierInfo,
	"inconclusive":            TierInfo,
	// DANE's absence label: absence-severity is protocol-dependent and DANE
	// absence is unremarkable (most of the internet). Every pre-existing
	// absence word ("absent", "missing", "none") ranks FAIL because for
	// SPF/DMARC absence IS the finding — DANE needs its own word at INFO.
	"not deployed":   TierInfo,
	"not_verifiable": TierInfo,
	"unreachable":    TierInfo,
	"no_tlsa":        TierInfo,

	// PASS — measured affirmative
	"configured":         TierPass,
	"enabled":            TierPass,
	"protected":          TierPass,
	"strongly protected": TierPass,
	"enterprise":         TierPass,
	"pass":               TierPass,
	"valid":              TierPass,
	"verified":           TierPass,
	"active":             TierPass,
	"present":            TierPass,
	"inherited":          TierPass,
	"signed":             TierPass,
}

// fragment is one substring-fallback candidate.
type fragment struct {
	s    string
	tier Tier
}

// fragments holds every map key sorted by length descending, then
// lexicographically ascending, so the most specific phrase wins over a
// short token embedded in a longer string ("could not be verified"
// beats "unsigned"; "unsigned" beats "signed") and iteration order is
// deterministic — Go map order is randomized and must never decide a
// rank (the unique_asns lesson).
var fragments = func() []fragment {
	out := make([]fragment, 0, len(statusTier))
	for s, t := range statusTier {
		out = append(out, fragment{s, t})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].s) != len(out[j].s) {
			return len(out[i].s) > len(out[j].s)
		}
		return out[i].s < out[j].s
	})
	return out
}()

// Rank maps a status string to its display tier. Matching is
// case-insensitive: exact match first, then longest-fragment substring,
// then TierWarn for anything unrecognised (surface, don't hide).
func Rank(status string) Tier {
	key := strings.ToLower(strings.TrimSpace(status))
	if t, ok := statusTier[key]; ok {
		return t
	}
	for _, f := range fragments {
		if strings.Contains(key, f.s) {
			return f.tier
		}
	}
	return TierWarn
}

// RankJSON serialises the map for injection into client pages as a
// window global (the fixturecorpus pattern), so client-side sorts rank
// from the same source instead of a local copy. Shape:
//
//	{"rank":{"<status>":<tier>,...},"unknown":1}
//
// Client consumers must mirror Rank's algorithm: exact match, then
// longest-fragment substring (length desc, lexicographic tiebreak),
// then the "unknown" fallback.
func RankJSON() string {
	doc := struct {
		Rank    map[string]Tier `json:"rank"`
		Unknown Tier            `json:"unknown"`
	}{Rank: statusTier, Unknown: TierWarn}
	b, err := json.Marshal(doc)
	if err != nil {
		// Marshaling a map[string]int cannot fail; keep the contract
		// total anyway.
		return `{"rank":{},"unknown":1}`
	}
	return string(b)
}
