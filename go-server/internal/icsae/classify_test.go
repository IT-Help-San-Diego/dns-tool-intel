// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icsae

import "testing"

func TestClassifyFixesProviderWithStrongPostureHasNoRealFixes(t *testing.T) {
        // Google-like: unsigned DNSSEC by deliberate choice at the top posture we can
        // measure (DMARC p=reject + effective SPF + CAA restriction), DKIM selector
        // not discoverable, delegation check unverified, DANE impossible on the
        // platform, BIMI optional. None of these is a real fix.
        fc := ClassifyFixes(
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED"},
                []string{"DKIM_PRESENT", "DELEGATION_CONSISTENT"},
                []string{"DANE_DEPLOYED", "BIMI_CONFIGURED"},
                []string{"SPF_EFFECTIVE_POLICY", "DMARC_ENFORCEMENT", "CAA_RESTRICTION_PRESENT", "MAIL_POLICY_SIGNALING"},
                true, // providerLimitedDANE
                true, // dmarcReject (p=reject)
        )
        if fc.RealFixCount != 0 {
                t.Errorf("RealFixCount = %d, want 0 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if fc.Color != "" {
                t.Errorf("Color = %q, want empty", fc.Color)
        }
        if !containsString(fc.ByDesign, "DNSSEC_AUTHENTICATED") || !containsString(fc.ByDesign, "DNSSEC_CHAIN_TRUSTED") {
                t.Errorf("DNSSEC controls not in by_design: %v", fc.ByDesign)
        }
        if !containsString(fc.CouldntVerify, "DKIM_PRESENT") || !containsString(fc.CouldntVerify, "DELEGATION_CONSISTENT") {
                t.Errorf("DKIM/DELEGATION not in couldnt_verify: %v", fc.CouldntVerify)
        }
        if !containsString(fc.PlatformLimited, "DANE_DEPLOYED") {
                t.Errorf("DANE not in platform_limited: %v", fc.PlatformLimited)
        }
        if !containsString(fc.Hygiene, "BIMI_CONFIGURED") {
                t.Errorf("BIMI not in hygiene: %v", fc.Hygiene)
        }
}

func TestClassifyFixesQuarantineDoesNotEarnDNSSECByDesign(t *testing.T) {
        // Quarantine (not reject) is below the top posture, so we do NOT grant the
        // unsigned-DNSSEC "by design" pass — DNSSEC integrity is a different plane
        // from mail auth. Both DMARC enforcement AND DNSSEC are honest real fixes.
        // Rigor cuts both ways: no DNSSEC pass until you reach p=reject + SPF + CAA.
        fc := ClassifyFixes(
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED", "DMARC_ENFORCEMENT"},
                []string{"DKIM_PRESENT", "DELEGATION_CONSISTENT"},
                []string{"HTTPS_SVCB_MODERN"},
                []string{"SPF_EFFECTIVE_POLICY", "CAA_RESTRICTION_PRESENT", "MAIL_POLICY_SIGNALING"},
                false, // providerLimitedDANE
                false, // dmarcReject (domain is at quarantine, not reject)
        )
        // DNSSEC group (counts once) + DMARC enforcement = 2 real fixes.
        if fc.RealFixCount != 2 {
                t.Errorf("RealFixCount = %d, want 2 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if !containsString(fc.RealFixes, "DMARC_ENFORCEMENT") {
                t.Errorf("DMARC_ENFORCEMENT not in real_fixes: %v", fc.RealFixes)
        }
        if !containsString(fc.RealFixes, "DNSSEC_AUTHENTICATED") {
                t.Errorf("DNSSEC should be a real fix below p=reject posture: %v", fc.RealFixes)
        }
        if containsString(fc.ByDesign, "DNSSEC_AUTHENTICATED") {
                t.Errorf("DNSSEC must NOT be by_design at quarantine: %v", fc.ByDesign)
        }
        if fc.Color != "danger" {
                t.Errorf("Color = %q, want danger", fc.Color)
        }
}

func TestClassifyFixesRejectPostureEarnsDNSSECByDesign(t *testing.T) {
        // At the top posture (DMARC p=reject + effective SPF + CAA), unsigned DNSSEC
        // is a defensible deliberate choice — by_design, not a real fix.
        fc := ClassifyFixes(
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED"},
                nil,
                []string{"HTTPS_SVCB_MODERN"},
                []string{"SPF_EFFECTIVE_POLICY", "DMARC_ENFORCEMENT", "CAA_RESTRICTION_PRESENT"},
                false, // providerLimitedDANE
                true,  // dmarcReject (p=reject)
        )
        if fc.RealFixCount != 0 {
                t.Errorf("RealFixCount = %d, want 0 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if !containsString(fc.ByDesign, "DNSSEC_AUTHENTICATED") {
                t.Errorf("DNSSEC not by_design under p=reject posture: %v", fc.ByDesign)
        }
}

func TestClassifyFixesUnprotectedOperatorEarnsRealFixes(t *testing.T) {
        // No compensating posture: DNSSEC, DMARC enforcement and SPF are all real.
        fc := ClassifyFixes(
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED", "DMARC_ENFORCEMENT"},
                []string{"SPF_EFFECTIVE_POLICY", "DKIM_PRESENT", "DELEGATION_CONSISTENT"},
                []string{"DANE_DEPLOYED"},
                nil,
                false, // providerLimitedDANE
                false, // dmarcReject
        )
        // DNSSEC_AUTHENTICATED + DNSSEC_CHAIN_TRUSTED collapse to one fix.
        if fc.RealFixCount != 3 {
                t.Errorf("RealFixCount = %d, want 3 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if fc.Color != "danger" {
                t.Errorf("Color = %q, want danger", fc.Color)
        }
        if !containsString(fc.Hygiene, "DANE_DEPLOYED") {
                t.Errorf("DANE not in hygiene when platform-capable: %v", fc.Hygiene)
        }
}

func TestClassifyFixesLiveDNSSECRolloverIsHygiene(t *testing.T) {
        // it-help-like: DNSSEC is live, so rollover automation is hardening not a gap;
        // everything else is verified or platform-limited. Zero real fixes.
        fc := ClassifyFixes(
                nil,
                []string{"DNSSEC_KEY_ROLLOVER", "DELEGATION_CONSISTENT"},
                []string{"DANE_DEPLOYED", "HTTPS_SVCB_MODERN"},
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED", "SPF_EFFECTIVE_POLICY", "DMARC_ENFORCEMENT", "CAA_RESTRICTION_PRESENT"},
                true, // providerLimitedDANE
                true, // dmarcReject
        )
        if fc.RealFixCount != 0 {
                t.Errorf("RealFixCount = %d, want 0 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if !containsString(fc.Hygiene, "DNSSEC_KEY_ROLLOVER") {
                t.Errorf("KEY_ROLLOVER not hygiene when DNSSEC deployed: %v", fc.Hygiene)
        }
}

func TestClassifyFixesDNSSECCountsOnce(t *testing.T) {
        fc := ClassifyFixes(
                []string{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED"},
                []string{"DNSSEC_KEY_ROLLOVER"},
                nil,
                nil,
                false,
                false,
        )
        if fc.RealFixCount != 1 {
                t.Errorf("RealFixCount = %d, want 1 (DNSSEC group counts once); real_fixes=%v", fc.RealFixCount, fc.RealFixes)
        }
}

func TestClassifyFixesDANEPlatformLimited(t *testing.T) {
        limited := ClassifyFixes(nil, nil, []string{"DANE_DEPLOYED"}, nil, true, false)
        if limited.RealFixCount != 0 || !containsString(limited.PlatformLimited, "DANE_DEPLOYED") {
                t.Errorf("provider-limited DANE: count=%d platform_limited=%v", limited.RealFixCount, limited.PlatformLimited)
        }
        capable := ClassifyFixes(nil, nil, []string{"DANE_DEPLOYED"}, nil, false, false)
        if capable.RealFixCount != 0 || !containsString(capable.Hygiene, "DANE_DEPLOYED") {
                t.Errorf("platform-capable DANE: count=%d hygiene=%v", capable.RealFixCount, capable.Hygiene)
        }
}

func TestClassifyFixesUnknownControlIsRealFix(t *testing.T) {
        fc := ClassifyFixes([]string{"SOME_NEW_HIGH_CONTROL"}, nil, nil, nil, false, false)
        if fc.RealFixCount != 1 || !containsString(fc.RealFixes, "SOME_NEW_HIGH_CONTROL") {
                t.Errorf("unknown control should default to real_fix: %+v", fc)
        }
        if fc.Color != "danger" {
                t.Errorf("Color = %q, want danger", fc.Color)
        }
}

func TestClassifyFromResultsRehydratesJSONTypes(t *testing.T) {
        // Mirrors a persisted scan: []interface{} slices and decoded JSON maps.
        fr := map[string]any{
                "icsae_evaluation": map[string]any{
                        "high_failures":   []interface{}{"DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED"},
                        "medium_failures": []interface{}{"DKIM_PRESENT"},
                        "low_failures":    []interface{}{"DANE_DEPLOYED"},
                        "passed":          []interface{}{"SPF_EFFECTIVE_POLICY", "CAA_RESTRICTION_PRESENT"},
                },
                "posture":        map[string]any{"provider_limited": []interface{}{"DANE"}},
                "dmarc_analysis": map[string]any{"policy": "reject"},
        }
        fc, ok := ClassifyFromResults(fr)
        if !ok {
                t.Fatal("ClassifyFromResults ok=false, want true")
        }
        if fc.RealFixCount != 0 {
                t.Errorf("RealFixCount = %d, want 0 (real_fixes=%v)", fc.RealFixCount, fc.RealFixes)
        }
        if !containsString(fc.ByDesign, "DNSSEC_AUTHENTICATED") {
                t.Errorf("strong posture should make DNSSEC by_design: %v", fc.ByDesign)
        }
        if !containsString(fc.PlatformLimited, "DANE_DEPLOYED") {
                t.Errorf("DANE should be platform_limited: %v", fc.PlatformLimited)
        }
}

func TestClassifyFromResultsAbsentEvaluation(t *testing.T) {
        if _, ok := ClassifyFromResults(map[string]any{"posture": map[string]any{}}); ok {
                t.Error("ClassifyFromResults ok=true with no icsae_evaluation, want false")
        }
}
