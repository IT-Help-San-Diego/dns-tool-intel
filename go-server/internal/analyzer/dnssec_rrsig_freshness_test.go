// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"testing"
	"time"
)

// The old rule was `remaining < 7 days`, which cannot read Inception and so
// cannot distinguish a healthy short-lifetime signature from a long-lifetime
// one running late. Row 1 is measured, not hypothetical: cia.gov on Akamai Edge
// DNS, 3.04-day lifetime re-signed roughly daily, every RRSIG tripping the old
// rule at 68% of life remaining.
func TestClassifyRRSIGFreshness(t *testing.T) {
	const day = 24 * time.Hour

	cases := []struct {
		name        string
		remaining   time.Duration
		lifetime    time.Duration
		origTTL     uint32
		wantLate    bool
		wantAtRisk  bool
		oldRuleFlag bool // what `remaining < 7d` would have said
	}{
		{
			name:        "measured: cia.gov Akamai 3-day signature, freshly re-signed",
			remaining:   time.Duration(2.07 * float64(day)),
			lifetime:    time.Duration(3.04 * float64(day)),
			origTTL:     3600,
			wantLate:    false,
			wantAtRisk:  false,
			oldRuleFlag: true, // the false positive this change removes
		},
		{
			name:        "short lifetime, re-signing overdue",
			remaining:   7 * time.Hour,
			lifetime:    time.Duration(3.04 * float64(day)),
			origTTL:     3600,
			wantLate:    true,
			wantAtRisk:  false,
			oldRuleFlag: true,
		},
		{
			name:        "30-day signature with 5 days left",
			remaining:   5 * day,
			lifetime:    30 * day,
			origTTL:     3600,
			wantLate:    true,
			wantAtRisk:  false,
			oldRuleFlag: true,
		},
		{
			name:        "90-day signature with 6 days left — 93% elapsed",
			remaining:   6 * day,
			lifetime:    90 * day,
			origTTL:     3600,
			wantLate:    true,
			wantAtRisk:  false,
			oldRuleFlag: true,
		},
		{
			name:        "90-day signature at half life is healthy",
			remaining:   45 * day,
			lifetime:    90 * day,
			origTTL:     3600,
			wantLate:    false,
			wantAtRisk:  false,
			oldRuleFlag: false,
		},
		{
			name:        "about to break: less than the cache TTL window",
			remaining:   30 * time.Minute,
			lifetime:    3 * day,
			origTTL:     3600, // 3xTTL = 3h floor
			wantLate:    true,
			wantAtRisk:  true,
			oldRuleFlag: true,
		},
		{
			name:        "long TTL raises the cache floor",
			remaining:   2 * time.Hour,
			lifetime:    30 * day,
			origTTL:     86400, // 3xTTL = 72h floor
			wantLate:    true,
			wantAtRisk:  true,
			oldRuleFlag: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			late, atRisk := classifyRRSIGFreshness(tc.remaining, tc.lifetime, tc.origTTL)
			if late != tc.wantLate {
				t.Errorf("late = %v, want %v (remaining %s of %s)", late, tc.wantLate, tc.remaining, tc.lifetime)
			}
			if atRisk != tc.wantAtRisk {
				t.Errorf("atRisk = %v, want %v (remaining %s, ttl %ds)", atRisk, tc.wantAtRisk, tc.remaining, tc.origTTL)
			}
		})
	}
}

// The defect in one assertion: the old rule gave the same verdict to a healthy
// signature and to one 93% through its life, because it never read Inception.
func TestOldAbsoluteRuleCannotDistinguishLifetimes(t *testing.T) {
	const day = 24 * time.Hour
	oldRule := func(remaining time.Duration) bool { return remaining > 0 && remaining < 7*day }

	healthy := time.Duration(2.07 * float64(day)) // 68% of a 3.04-day life left
	overdue := 6 * day                            // 7% of a 90-day life left

	if oldRule(healthy) != oldRule(overdue) {
		t.Fatal("precondition failed: the old rule was expected to treat both identically")
	}

	healthyLate, _ := classifyRRSIGFreshness(healthy, time.Duration(3.04*float64(day)), 3600)
	overdueLate, _ := classifyRRSIGFreshness(overdue, 90*day, 3600)

	if healthyLate {
		t.Error("healthy short-lifetime signature must not be flagged")
	}
	if !overdueLate {
		t.Error("90-day signature with 6 days left must be flagged")
	}
}

// Expired signatures are reported on their own path; the freshness classifier
// must not double-report them.
func TestClassifyRRSIGFreshnessIgnoresExpired(t *testing.T) {
	late, atRisk := classifyRRSIGFreshness(-time.Hour, 72*time.Hour, 3600)
	if late || atRisk {
		t.Errorf("expired signature should yield no freshness finding, got late=%v atRisk=%v", late, atRisk)
	}
}
