// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package icsae

import "sort"

// ConfidenceLevel is the ICD 203 qualitative analytic-confidence band. ICD 203
// ("Analytic Standards") deliberately keeps confidence QUALITATIVE — it states
// how much weight an assessment can bear given source quality, corroboration and
// information gaps, and explicitly forbids conflating that with a probability of
// the event. We mirror that: a level always travels with an explicit basis, and
// we never emit a fabricated precise percentage.
type ConfidenceLevel string

const (
        ConfidenceHigh     ConfidenceLevel = "high"
        ConfidenceModerate ConfidenceLevel = "moderate"
        ConfidenceLow      ConfidenceLevel = "low"
)

// Exploit classes describe how much an attacker has to do before the failed
// control becomes a working attack. They are derived ONLY from the verified
// CWE/CAPEC/VRT lineage already attached to a control — never asserted beyond
// what the mapping supports.
const (
        // ExploitNow: no privileged network position required. An attacker forges
        // identity, spoofs mail, or claims unclaimed infrastructure with
        // off-the-shelf tooling, today.
        ExploitNow = "exploitable_now"
        // ExploitConditional: exploitation needs an on-path or cache-poisoning
        // position against the resolution path.
        ExploitConditional = "conditional"
        // ExploitUnproven: the control has no verified weakness mapping that
        // asserts immediate exploitation, so we do not claim one.
        ExploitUnproven = "unproven"
)

// Blast-radius classes describe who is harmed when the control fails.
const (
        // BlastExternal: the operator's customers, partners and brand — third
        // parties are deceived using the operator's identity or namespace.
        BlastExternal = "external"
        // BlastResolution: everyone resolving the domain through an affected path.
        BlastResolution = "resolution_path"
        // BlastSelf: scope is limited to the operator's own posture.
        BlastSelf = "self"
)

// RemediationItem is one ordered, citation-backed Real Fix. Every field that
// asserts risk (exploit class, blast radius, attacker action, weakness refs)
// is grounded in the catalog + verified weakness lineage, so the item's rank is
// defensible to a skeptic. The rationale strings exist precisely so the ordering
// is explainable rather than a black-box score.
type RemediationItem struct {
        Rank            int             `json:"rank"`
        ControlID       string          `json:"control_id"`
        Title           string          `json:"title"`
        Severity        string          `json:"severity"`
        ExploitClass    string          `json:"exploit_class"`
        ExploitBasis    string          `json:"exploit_basis"`
        BlastRadius     string          `json:"blast_radius"`
        BlastBasis      string          `json:"blast_basis"`
        Confidence      ConfidenceLevel `json:"confidence"`
        ConfidenceBasis string          `json:"confidence_basis"`
        RFCs            []string        `json:"rfcs,omitempty"`
        WeaknessRefs    *WeaknessRefs   `json:"weakness_refs,omitempty"`
        // AttackerAction is the concrete "what could really happen" — the control's
        // fail_explanation, which already carries the RFC requirement level and the
        // attacker's move. Per the Zero-Fabrication rule a Real Fix is only asserted
        // when this is present.
        AttackerAction string `json:"attacker_action,omitempty"`
        // PriorityScore is the transparent triage score the rank is derived from.
        PriorityScore int `json:"priority_score"`
}

// RemediationQueue is the prioritized triage output: the Real Fixes from the
// reality-matched classification, ordered by triage rank so the refs DRIVE the
// order rather than sitting as garnish. RealFixCount mirrors the classification's
// counted-once headline; MappedCount is how many queued items carry a verified
// weakness-taxonomy mapping (coverage stays honest, not implied complete).
type RemediationQueue struct {
        Items        []RemediationItem `json:"items"`
        RealFixCount int               `json:"real_fix_count"`
        MappedCount  int               `json:"mapped_count"`
}

// triage scoring weights. Exploitability dominates (stop active bleeding first),
// severity is the backbone, blast radius and analytic confidence are nudges.
// Confidence is a positive nudge so we surface what we are sure about higher,
// but it can never outweigh severity or exploitability.
var (
        exploitScore = map[string]int{
                ExploitNow:         100,
                ExploitConditional: 55,
                ExploitUnproven:    25,
        }
        severityScore = map[string]int{
                "high":   40,
                "medium": 20,
                "low":    6,
        }
        blastScore = map[string]int{
                BlastExternal:   18,
                BlastResolution: 12,
                BlastSelf:       4,
        }
        confidenceScore = map[ConfidenceLevel]int{
                ConfidenceHigh:     8,
                ConfidenceModerate: 4,
                ConfidenceLow:      1,
        }
        severityRank = map[string]int{"high": 0, "medium": 1, "low": 2}
)

// BuildRemediationQueue turns the reality-matched Real Fixes into an ordered,
// citation-backed triage queue. It is a SEPARATE layer over the parity-guarded
// verdict engine — it reads ControlResults but never mutates a verdict. stale is
// the recency-decay signal: false at scan time (data was just observed live),
// true when replaying a persisted finding past its freshness window (S4).
func BuildRemediationQueue(res Result, fc FixClassification, stale bool) RemediationQueue {
        byID := make(map[string]ControlResult, len(res.Results))
        for _, cr := range res.Results {
                byID[cr.ID] = cr
        }

        // Collapse grouped controls (DNSSEC) to a single conceptual remediation so
        // the queue length matches the counted-once RealFixCount. For a group, the
        // representative is the highest-severity member that carries weakness refs.
        seenGroup := map[string]bool{}
        var items []RemediationItem
        for _, id := range fc.RealFixes {
                key := remediationGroupKey(id)
                if seenGroup[key] {
                        continue
                }
                cr, ok := byID[id]
                if !ok {
                        continue
                }
                if key != id {
                        cr = groupRepresentative(key, fc.RealFixes, byID, cr)
                }
                seenGroup[key] = true
                items = append(items, buildItem(key, cr, stale))
        }

        sort.SliceStable(items, func(i, j int) bool {
                if items[i].PriorityScore != items[j].PriorityScore {
                        return items[i].PriorityScore > items[j].PriorityScore
                }
                if severityRank[items[i].Severity] != severityRank[items[j].Severity] {
                        return severityRank[items[i].Severity] < severityRank[items[j].Severity]
                }
                return items[i].ControlID < items[j].ControlID
        })

        q := RemediationQueue{RealFixCount: fc.RealFixCount}
        for i := range items {
                items[i].Rank = i + 1
                if items[i].WeaknessRefs != nil {
                        q.MappedCount++
                }
        }
        q.Items = items
        return q
}

// groupRepresentative picks the member of a counted-once group that best
// describes the remediation: prefer a member that carries weakness refs (so the
// item stays citation-backed), otherwise keep the first-seen member.
func groupRepresentative(key string, realFixes []string, byID map[string]ControlResult, fallback ControlResult) ControlResult {
        best := fallback
        bestHasRefs := fallback.WeaknessRefs != nil
        for _, id := range realFixes {
                if remediationGroupKey(id) != key {
                        continue
                }
                cr, ok := byID[id]
                if !ok {
                        continue
                }
                if cr.WeaknessRefs != nil && !bestHasRefs {
                        best = cr
                        bestHasRefs = true
                }
        }
        return best
}

func buildItem(controlID string, cr ControlResult, stale bool) RemediationItem {
        exploit, exploitBasis := exploitClass(cr.WeaknessRefs)
        blast, blastBasis := blastRadius(cr.WeaknessRefs)
        conf, confBasis := icd203Confidence(cr.WeaknessRefs, stale)

        title := cr.Title
        if controlID == dnssecGroupID {
                title = "Deploy / Maintain DNSSEC"
        }

        item := RemediationItem{
                ControlID:       controlID,
                Title:           title,
                Severity:        cr.Severity,
                ExploitClass:    exploit,
                ExploitBasis:    exploitBasis,
                BlastRadius:     blast,
                BlastBasis:      blastBasis,
                Confidence:      conf,
                ConfidenceBasis: confBasis,
                RFCs:            cr.RFCs,
                WeaknessRefs:    cr.WeaknessRefs,
                AttackerAction:  cr.FailExplanation,
        }
        item.PriorityScore = exploitScore[exploit] + severityScore[cr.Severity] + blastScore[blast] + confidenceScore[conf]
        return item
}

// remediationGroupKey mirrors the classifier's counted-once grouping so the queue
// stays consistent with RealFixCount.
func remediationGroupKey(id string) string {
        switch id {
        case "DNSSEC_AUTHENTICATED", "DNSSEC_CHAIN_TRUSTED", "DNSSEC_KEY_ROLLOVER":
                return dnssecGroupID
        }
        return id
}

// exploitClass derives how much attacker effort the failure requires, grounded
// strictly in the verified CWE/CAPEC/VRT lineage. With no mapping we assert
// nothing (ExploitUnproven) rather than inventing exploitability.
func exploitClass(refs *WeaknessRefs) (string, string) {
        if refs == nil {
                return ExploitUnproven, "No verified weakness mapping yet — exploitability is not asserted."
        }
        if isSpoofing(refs) {
                return ExploitNow, "Sender / identity spoofing requires no privileged position: an attacker forges mail or impersonates the domain with off-the-shelf tooling (CWE-290 / CAPEC identity-spoofing patterns)."
        }
        if isTakeover(refs) {
                return ExploitNow, "A dangling record lets an attacker claim the unclaimed target and serve content from the domain's own namespace (Bugcrowd VRT subdomain takeover) — no privileged position required."
        }
        if isOnPath(refs) {
                return ExploitConditional, "Exploitation requires an on-path or cache-poisoning position against the resolution path (CWE-300/345, CAPEC DNS cache poisoning)."
        }
        return ExploitUnproven, "The mapped weakness carries no offensive pattern indicating immediate exploitation."
}

// blastRadius derives who is harmed, grounded in the same lineage.
func blastRadius(refs *WeaknessRefs) (string, string) {
        if refs == nil {
                return BlastSelf, "Scope limited to the operator's own posture until a weakness mapping is verified."
        }
        if isSpoofing(refs) {
                return BlastExternal, "Customers, partners and brand: recipients are phished using the domain's identity."
        }
        if isTakeover(refs) {
                return BlastExternal, "Users of the domain: attacker-controlled content is served from the domain's own namespace."
        }
        if isOnPath(refs) {
                return BlastResolution, "Everyone resolving the domain through an affected resolution path."
        }
        return BlastSelf, "Scope limited to the operator's own posture."
}

// icd203Confidence computes the qualitative ICD 203 analytic-confidence band for
// a Real Fix, with an explicit basis. Every queue item is a determinate verdict
// observed directly in live DNS records (ICIE Tier 1 evidence), so the baseline
// is high; the weakness-mapping confidence and recency decay can only lower it.
func icd203Confidence(refs *WeaknessRefs, stale bool) (ConfidenceLevel, string) {
        level := ConfidenceHigh
        basis := "Directly observed DNS records (ICIE Tier 1 evidence); verdict determinate."

        switch {
        case refs == nil:
                level = ConfidenceModerate
                basis += " Standards gap is certain, but the weakness/exploit lineage is not yet verified."
        case refs.MappingConfidence == "medium":
                level = ConfidenceModerate
                basis += " Weakness mapping verified at medium confidence (contributory control)."
        default:
                basis += " Weakness mapping verified at high confidence (CWE/CAPEC/VRT)."
        }

        if stale {
                level = demote(level)
                basis += " Evidence currency reduced — data age is beyond the freshness window."
        }
        return level, basis
}

func demote(l ConfidenceLevel) ConfidenceLevel {
        switch l {
        case ConfidenceHigh:
                return ConfidenceModerate
        case ConfidenceModerate:
                return ConfidenceLow
        }
        return ConfidenceLow
}

func isSpoofing(refs *WeaknessRefs) bool {
        return containsString(refs.CWE, "CWE-290") ||
                containsAny(refs.CAPEC, "CAPEC-151", "CAPEC-194", "CAPEC-163") ||
                containsString(refs.VRT, "VRT:email_spoofing_to_inbox_due_to_missing_or_misconfigured_dmarc_on_email_domain")
}

func isTakeover(refs *WeaknessRefs) bool {
        return containsString(refs.VRT, "VRT:subdomain_takeover")
}

func isOnPath(refs *WeaknessRefs) bool {
        return containsAny(refs.CWE, "CWE-300", "CWE-345") ||
                containsAny(refs.CAPEC, "CAPEC-141", "CAPEC-142") ||
                containsString(refs.VRT, "VRT:missing_dnssec")
}

func containsAny(ss []string, targets ...string) bool {
        for _, t := range targets {
                if containsString(ss, t) {
                        return true
                }
        }
        return false
}
