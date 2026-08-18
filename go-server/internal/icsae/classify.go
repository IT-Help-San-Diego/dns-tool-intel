// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icsae

// FixBucket classifies a failed control by what it means in operational
// reality, separating genuinely actionable fixes from deliberate posture,
// platform limitations, detection limits, and optional hardening.
type FixBucket string

const (
        // BucketRealFix is a failed control with a real, RFC-grounded
        // operational-security consequence for THIS operator — something we can
        // and should tell them to fix, and cite why.
        BucketRealFix FixBucket = "real_fix"
        // BucketByDesign is a control absent by deliberate enterprise choice,
        // granted only to operators who have reached the top of every posture we can
        // measure (the deliberate unsigned-DNSSEC pattern at a strict-DMARC operator).
        BucketByDesign FixBucket = "by_design"
        // BucketPlatformLimited is a control the operator's mail platform makes
        // impossible (e.g. DANE on a provider that does not support it). Kept for
        // information; never counted against them.
        BucketPlatformLimited FixBucket = "platform_limited"
        // BucketCouldntVerify is a control we cannot positively confirm (e.g. DKIM
        // selectors are not enumerable). We never assert "missing" — only
        // "could not verify".
        BucketCouldntVerify FixBucket = "couldnt_verify"
        // BucketHygiene is optional defense-in-depth: failing it is not an
        // operational exposure, just hardening a mature operator may add.
        BucketHygiene FixBucket = "hygiene"
)

// FixClassification is the reality-matched view layered on top of the raw ICSAE
// verdicts. RealFixCount is the headline number: failed controls that carry a
// real operational-security consequence for THIS operator. Everything else is
// sorted into honest context buckets so we never cry wolf on a deliberate
// enterprise posture or a control the platform cannot support, and never assert
// a control is missing when we merely could not verify it. This is the
// differentiator made trustworthy in both directions — if we say there is a fix,
// there is a citable reason; if we do not, we say plainly why.
type FixClassification struct {
        RealFixCount    int      `json:"real_fix_count"`
        Color           string   `json:"color"`
        RealFixes       []string `json:"real_fixes"`
        ByDesign        []string `json:"by_design"`
        PlatformLimited []string `json:"platform_limited"`
        CouldntVerify   []string `json:"couldnt_verify"`
        Hygiene         []string `json:"hygiene"`
}

// optionalControls are low-value hardening: failing them is not an operational
// exposure, just defense-in-depth.
var optionalControls = map[string]bool{
        "BIMI_CONFIGURED":       true,
        "HTTPS_SVCB_MODERN":     true,
        "MAIL_POLICY_SIGNALING": true,
        "SECURITY_TXT_PRESENT":  true,
}

// dnssecGroupID collapses the DNSSEC controls that together represent a single
// remediation ("deploy / maintain DNSSEC") so they are counted once, not thrice.
const dnssecGroupID = "DNSSEC"

func containsString(ss []string, target string) bool {
        for _, s := range ss {
                if s == target {
                        return true
                }
        }
        return false
}

// asStringSlice tolerates both the native []string produced at scan time and the
// []interface{} produced by a JSON round-trip, so callers may pass either the
// live results map or a rehydrated persisted scan.
func asStringSlice(v any) []string {
        switch s := v.(type) {
        case []string:
                return s
        case []interface{}:
                out := make([]string, 0, len(s))
                for _, e := range s {
                        if str, ok := e.(string); ok {
                                out = append(out, str)
                        }
                }
                return out
        }
        return nil
}

// ClassifyFixes layers the reality-matched classification over raw ICSAE
// verdicts. strongCompensating is the signal that an absent DNSSEC is a
// deliberate, sophisticated enterprise choice rather than an exposure: it
// requires the strongest mail posture (DMARC p=reject) PLUS effective SPF PLUS a
// CAA issuance restriction. Quarantine, or low-severity mail-policy hygiene
// signals, are deliberately NOT enough — DNSSEC protects DNS-response integrity,
// a different plane from mail authentication, so we only treat unsigned DNSSEC
// as "by design" for operators who have demonstrably reached the top of every
// posture we can measure. providerLimitedDANE means the mail platform cannot
// support DANE at all.
func ClassifyFixes(high, medium, low, passed []string, providerLimitedDANE, dmarcReject, enterpriseDeliberateDNSSEC bool, couldntVerify map[string]bool) FixClassification {
        spfOK := containsString(passed, "SPF_EFFECTIVE_POLICY")
        caaOK := containsString(passed, "CAA_RESTRICTION_PRESENT")
        strongCompensating := dmarcReject && spfOK && caaOK
        dnssecDeployed := containsString(passed, "DNSSEC_AUTHENTICATED")

        var fc FixClassification
        // realFixGroups dedupes grouped controls (DNSSEC) so a single conceptual
        // remediation is counted once even when several of its controls fail.
        realFixGroups := map[string]bool{}
        hasHigh, hasMedium, hasLow := false, false, false

        classify := func(id, severity string) {
                bucket, group := bucketFor(id, strongCompensating, dnssecDeployed, providerLimitedDANE, enterpriseDeliberateDNSSEC, couldntVerify)
                switch bucket {
                case BucketRealFix:
                        fc.RealFixes = append(fc.RealFixes, id)
                        key := group
                        if key == "" {
                                key = id
                        }
                        if !realFixGroups[key] {
                                realFixGroups[key] = true
                                switch severity {
                                case "high":
                                        hasHigh = true
                                case "medium":
                                        hasMedium = true
                                default:
                                        hasLow = true
                                }
                        }
                case BucketByDesign:
                        fc.ByDesign = append(fc.ByDesign, id)
                case BucketPlatformLimited:
                        fc.PlatformLimited = append(fc.PlatformLimited, id)
                case BucketCouldntVerify:
                        fc.CouldntVerify = append(fc.CouldntVerify, id)
                case BucketHygiene:
                        fc.Hygiene = append(fc.Hygiene, id)
                }
        }

        for _, id := range high {
                classify(id, "high")
        }
        for _, id := range medium {
                classify(id, "medium")
        }
        for _, id := range low {
                classify(id, "low")
        }

        fc.RealFixCount = len(realFixGroups)
        switch {
        case hasHigh:
                fc.Color = "danger"
        case hasMedium:
                fc.Color = "warning"
        case hasLow:
                fc.Color = "info"
        }
        return fc
}

// bucketFor returns the reality-matched bucket for a single failed control and,
// when the control belongs to a counted-once group, that group's key.
func bucketFor(id string, strongCompensating, dnssecDeployed, providerLimitedDANE, enterpriseDeliberateDNSSEC bool, couldntVerify map[string]bool) (FixBucket, string) {
        // A control whose underlying protocol measurement was transient/indeterminate
        // (SERVFAIL/timeout/no-majority) can be neither confirmed present nor proven
        // absent, so it is routed to could-not-verify before any absence-based
        // bucketing. We never assert a control is missing from a failed measurement
        // (Zero Fabrication) — an authoritative absence is required for a real fix.
        if couldntVerify[id] {
                return BucketCouldntVerify, ""
        }
        switch id {
        case "DANE_DEPLOYED":
                if providerLimitedDANE {
                        return BucketPlatformLimited, ""
                }
                return BucketHygiene, ""
        case "DKIM_PRESENT":
                // DKIM selectors are not enumerable, so a failure means "selector not
                // discoverable", never "DKIM is missing".
                return BucketCouldntVerify, ""
        case "DELEGATION_CONSISTENT":
                // The delegation-consistency check currently fires even on operators
                // we know are correctly delegated (incl. Google/Apple); until it is
                // hardened we do not assert it as a real fix.
                return BucketCouldntVerify, ""
        case "DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED":
                if strongCompensating || enterpriseDeliberateDNSSEC {
                        return BucketByDesign, dnssecGroupID
                }
                return BucketRealFix, dnssecGroupID
        case "DNSSEC_KEY_ROLLOVER":
                if dnssecDeployed {
                        // DNSSEC is live; automating rollover is hardening, not a gap.
                        return BucketHygiene, ""
                }
                if strongCompensating || enterpriseDeliberateDNSSEC {
                        return BucketByDesign, dnssecGroupID
                }
                return BucketRealFix, dnssecGroupID
        }
        if optionalControls[id] {
                return BucketHygiene, ""
        }
        return BucketRealFix, ""
}

// ClassifyFromResults builds the classification from a full results map (the
// same object stored as full_results) where icsae_evaluation is a decoded JSON
// map — i.e. a rehydrated persisted scan. Returns ok=false when ICSAE was not
// evaluated for this scan, so callers can fall back to a legacy count.
func ClassifyFromResults(fr map[string]any) (FixClassification, bool) {
        ev := getMap(fr, "icsae_evaluation")
        if len(ev) == 0 {
                return FixClassification{}, false
        }
        // Guard against a malformed/partial icsae_evaluation: a genuine ICSAE verdict
        // always carries the verdict arrays (an all-clear scan still emits empty
        // arrays, so the keys are present). If none are present the map is not a real
        // evaluation, so fall back rather than silently reporting zero real fixes.
        _, hasPassed := ev["passed"]
        _, hasHigh := ev["high_failures"]
        _, hasMedium := ev["medium_failures"]
        _, hasLow := ev["low_failures"]
        if !hasPassed && !hasHigh && !hasMedium && !hasLow {
                return FixClassification{}, false
        }
        return classifyFromParts(
                asStringSlice(ev["high_failures"]),
                asStringSlice(ev["medium_failures"]),
                asStringSlice(ev["low_failures"]),
                asStringSlice(ev["passed"]),
                fr,
        ), true
}

// ClassifyFromEval builds the classification at scan time, where the ICSAE
// verdict is still the strongly-typed Result rather than a decoded JSON map.
func ClassifyFromEval(ev Result, fr map[string]any) FixClassification {
        return classifyFromParts(ev.HighFailures, ev.MediumFailures, ev.LowFailures, ev.Passed, fr)
}

// enterpriseDeliberateUnsignedDNSSEC reports whether an absent DNSSEC chain is a
// deliberate enterprise posture rather than an operational gap. It reuses the
// SAME two-signal enterprise-DNS recognition the user-facing verdict note uses,
// so the headline "to Fix" count never contradicts what the rest of the report
// tells the operator. It is true ONLY when:
//
//  1. DNSSEC is AUTHORITATIVELY absent — dnssec_state == "absent_confirmed" (an
//     unsigned zone proven by an authoritative NOERROR/NODATA answer). A broken
//     chain (records present but invalid) or an indeterminate/transient lookup is
//     NEVER forgiven: broken DNSSEC stays a real fix, and we never assert a
//     deliberate choice from a failed measurement (Zero Fabrication). RFC 4035 §5.
//  2. The operator is recognised as enterprise infrastructure by EITHER signal:
//     dns_infrastructure.enterprise_dns_recognized (recognised third-party enterprise
//     provider) OR ns_delegation_analysis.enterprise_pattern ∈ {dedicated, mixed,
//     multi-provider} (self-hosted / multi-provider enterprise NS, e.g. Apple).
//     "managed" is excluded: a small operator fully on one managed DNS host that
//     itself offers one-click DNSSEC has no excuse not to sign. This mirrors the
//     top-level verdict-note gate exactly (top ⊆ deep invariant).
func enterpriseDeliberateUnsignedDNSSEC(fr map[string]any) bool {
        if getString(getMap(fr, "dnssec_analysis"), "dnssec_state") != "absent_confirmed" {
                return false
        }
        if getBoolDefault(getMap(fr, "dns_infrastructure"), "enterprise_dns_recognized", false) || getBoolDefault(getMap(fr, "dns_infrastructure"), "explains_no_dnssec", false) {
                return true
        }
        switch getString(getMap(fr, "ns_delegation_analysis"), "enterprise_pattern") {
        case "dedicated", "mixed", "multi-provider":
                return true
        }
        return false
}

func classifyFromParts(high, medium, low, passed []string, fr map[string]any) FixClassification {
        providerLimitedDANE := containsString(asStringSlice(getMap(fr, "posture")["provider_limited"]), "DANE")
        dmarcReject := getString(getMap(fr, "dmarc_analysis"), "policy") == "reject"
        enterpriseDeliberateDNSSEC := enterpriseDeliberateUnsignedDNSSEC(fr)
        return ClassifyFixes(high, medium, low, passed, providerLimitedDANE, dmarcReject, enterpriseDeliberateDNSSEC, indeterminateAuxControls(fr))
}

// indeterminateAuxControls maps a transient/indeterminate protocol measurement to
// the control ID(s) that must therefore be reported as could-not-verify rather
// than asserted as absent. Absence is read ONLY from an authoritative answer
// (Zero Fabrication): a *_state of "indeterminate" is a SERVFAIL/timeout/conflict,
// never proof the record is unconfigured. CAA -> CAA_RESTRICTION_PRESENT (RFC 8659
// §4.2), MTA-STS/TLS-RPT -> MAIL_POLICY_SIGNALING (RFC 8461, RFC 8460), BIMI ->
// BIMI_CONFIGURED. The transport control requires_any(MTA-STS, TLS-RPT), so it can
// only reach a failed bucket when both signals are down; if EITHER was merely
// indeterminate the "both absent" conclusion is not authoritative.
func indeterminateAuxControls(fr map[string]any) map[string]bool {
        indet := func(section, key string) bool {
                return getString(getMap(fr, section), key) == "indeterminate"
        }
        out := map[string]bool{}
        if indet("caa_analysis", "caa_state") {
                out["CAA_RESTRICTION_PRESENT"] = true
        }
        if indet("bimi_analysis", "bimi_state") {
                out["BIMI_CONFIGURED"] = true
        }
        if indet("mta_sts_analysis", "mta_sts_state") || indet("tlsrpt_analysis", "tlsrpt_state") {
                out["MAIL_POLICY_SIGNALING"] = true
        }
        // DNSSEC (Zero Fabrication): an ambiguous or failed measurement is never
        // absence. dnssec_state indeterminate/unmeasured means the zone's signing
        // status could not be determined; chain_of_trust unconfirmed/unknown means
        // the AD flag/chain could not be verified even when DNSKEY+DS are present.
        // All three DNSSEC controls then route to could-not-verify, never a real
        // "deploy/maintain DNSSEC" fix — the scan-18393 false-verdict class.
        dnssecState := getString(getMap(fr, "dnssec_analysis"), "dnssec_state")
        chainOfTrust := getString(getMap(fr, "dnssec_analysis"), "chain_of_trust")
        dnssecIndet := dnssecState == "indeterminate" || dnssecState == "unmeasured" ||
                chainOfTrust == "unconfirmed" || chainOfTrust == "unknown"
        if dnssecIndet {
                out["DNSSEC_AUTHENTICATED"] = true
                out["DNSSEC_CHAIN_TRUSTED"] = true
                out["DNSSEC_KEY_ROLLOVER"] = true
        }
        return out
}
