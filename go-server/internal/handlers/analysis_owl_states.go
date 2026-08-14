// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// analysis_owl_states.go — Four-owl epistemic semaphore for the
// /api/analysis/:id payload ("owl_semaphore" key). Pure presentation-layer
// bucketing of signals ALREADY computed and stored in full_results — no new
// analysis is performed and nothing is fabricated:
//
//	normative     — protocol sections whose stored status is "success"
//	                (RFC-conformance evaluation completed, passing status).
//	non_normative — advisory signal: posture recommendations / monitoring
//	                entries and protocol sections with status "info".
//	critical      — posture critical_issues, protocol sections with status
//	                "error", Critical-severity remediation fixes, and a stored
//	                posture spoof_door of "open" (the analyzer's
//	                operational-consequence axis: spoofed mail is delivered
//	                with nothing blocking it).
//	metacognitive — DOUBT only, never severity: protocol sections with
//	                status "indeterminate", stored tri-state fields reading
//	                "indeterminate" under a non-indeterminate status (the
//	                lookup did not complete), and protocols WITHOUT a
//	                confirmed outcome whose calibrated confidence falls
//	                below the moderate threshold (unified.ThresholdModerate
//	                = 50.0, i.e. 0.50 on the 0-1 calibrated scale).
//	                Confirmed failures/absences are excluded from the
//	                confidence input: the raw scale is outcome-valenced, so
//	                their low score restates the verdict — certainty, which
//	                belongs to the critical owl, not this one.
//
// Claims rule: reasons never assert RFC requirement levels (MUST/SHOULD/MAY)
// because per-finding requirement metadata does not exist in stored results.
// Owls without an honest signal stay dark with an explicit "not triggered"
// reason. Results lacking every signal source return nil — honestly absent,
// never dark-by-guess.
package handlers

import (
	"fmt"
	"strings"
)

// owlProtocolOrder fixes a deterministic display order for owl reasons.
// Name mirrors the UI spelling; Key is the full_results section key;
// ConfKey is the calibrated_confidence map key (underscore spellings);
// StateKey is the section's stored tri-state field ("" where the analyzer
// records none) — "indeterminate" there means the lookup did not complete,
// a doubt signal that can coexist with a non-indeterminate top-level status.
var owlProtocolOrder = []struct {
	Name     string
	Key      string
	ConfKey  string
	StateKey string
}{
	{"SPF", mapKeySpfAnalysis, "SPF", "spf_state"},
	{"DKIM", mapKeyDkimAnalysis, "DKIM", ""},
	{"DMARC", mapKeyDmarcAnalysis, "DMARC", "dmarc_state"},
	{"DNSSEC", "dnssec_analysis", "DNSSEC", "dnssec_state"},
	{"DANE", "dane_analysis", "DANE", "dane_state"},
	{"MTA-STS", "mta_sts_analysis", "MTA_STS", "mta_sts_state"},
	{"TLS-RPT", "tlsrpt_analysis", "TLS_RPT", "tlsrpt_state"},
	{"BIMI", "bimi_analysis", "BIMI", "bimi_state"},
	{"CAA", "caa_analysis", "CAA", "caa_state"},
}

// owlLowConfidenceThreshold mirrors unified.ThresholdModerate (50.0) on the
// 0-1 calibrated_confidence scale. Below it, the evidence for a protocol did
// not reach moderate confidence — a metacognitive (know-what-we-don't-know)
// signal from the calibrated-confidence pipeline.
const owlLowConfidenceThreshold = 0.50

// owlSliceLen tolerates live []string values and JSON round-tripped []any —
// the same dual-shape reality handled by calibratedConfidenceMap.
func owlSliceLen(v any) int {
	switch s := v.(type) {
	case []string:
		return len(s)
	case []any:
		return len(s)
	}
	return 0
}

func owlPlural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func owlState(lit bool, count int, reason string) map[string]any {
	return map[string]any{
		"lit":    lit,
		"count":  count,
		"reason": reason,
	}
}

// owlSectionBuckets classifies protocol sections by stored status into the
// four status buckets the owls read. seen counts sections present at all.
// stateIndeterminate lists protocols whose stored TRI-STATE field reads
// indeterminate while the top-level status says something else — the cia.gov
// shape (dane_state=indeterminate under a non-indeterminate section) that the
// status bucket alone cannot see. confirmedOutcome marks protocols whose
// status is a measured verdict (failure/error/absence): certainty, not doubt.
type owlSectionBuckets struct {
	passed             []string
	infos              []string
	errored            []string
	indeterminate      []string
	stateIndeterminate []string
	confirmedOutcome   map[string]bool
	seen               int
}

func owlCollectSections(results map[string]any) owlSectionBuckets {
	b := owlSectionBuckets{confirmedOutcome: map[string]bool{}}
	for _, p := range owlProtocolOrder {
		section, sOk := results[p.Key].(map[string]any)
		if !sOk {
			continue
		}
		b.seen++
		status, _ := section[mapKeyStatus].(string) //nolint:errcheck // zero-value fallback is intentional
		switch status {
		case "success":
			b.passed = append(b.passed, p.Name)
		case "info":
			b.infos = append(b.infos, p.Name)
		case "error":
			b.errored = append(b.errored, p.Name)
			b.confirmedOutcome[p.ConfKey] = true
		case "indeterminate":
			b.indeterminate = append(b.indeterminate, p.Name)
		case "fail", "danger", "critical", "missing", "n/a", "":
			// A measured failure or absence (or a section with no status at
			// all) is a confirmed outcome — the confidence pipeline scores
			// these low on its outcome-valenced raw scale, and that low score
			// must not be read back as epistemic doubt.
			b.confirmedOutcome[p.ConfKey] = true
		}
		if status != "indeterminate" && p.StateKey != "" {
			if st, _ := section[p.StateKey].(string); st == "indeterminate" { //nolint:errcheck // zero-value fallback is intentional
				b.stateIndeterminate = append(b.stateIndeterminate, p.Name)
			}
		}
	}
	return b
}

// owlPostureCounts reads the stored posture block's advisory and critical
// slice lengths. seen reports whether a posture block exists at all.
func owlPostureCounts(results map[string]any) (rec, mon, crit int, seen bool) {
	posture, pOk := results[mapKeyPosture].(map[string]any)
	if !pOk {
		return 0, 0, 0, false
	}
	return owlSliceLen(posture["recommendations"]),
		owlSliceLen(posture["monitoring"]),
		owlSliceLen(posture["critical_issues"]),
		true
}

// owlSpoofDoorOpen reads the stored posture spoof_door axis — the
// operational-consequence producer written by the analyzer since the
// consequence-derived grade colour landed. "open" means the stored posture
// records that a spoofed message claiming this domain is delivered with
// nothing blocking it. Older scans lack the key and return false — honestly
// absent, never inferred from record presence (the re-derivation this
// producer exists to prevent).
func owlSpoofDoorOpen(results map[string]any) bool {
	posture, pOk := results[mapKeyPosture].(map[string]any)
	if !pOk {
		return false
	}
	door, _ := posture["spoof_door"].(string) //nolint:errcheck // zero-value fallback is intentional
	return door == "open"
}

// owlCriticalFixCount counts remediation fixes stored with severity_label
// "Critical".
func owlCriticalFixCount(results map[string]any) int {
	rem, rOk := results["remediation"].(map[string]any)
	if !rOk {
		return 0
	}
	fixes, fOk := rem["all_fixes"].([]any)
	if !fOk {
		return 0
	}
	n := 0
	for _, f := range fixes {
		fm, mOk := f.(map[string]any)
		if !mOk {
			continue
		}
		if label, _ := fm["severity_label"].(string); label == "Critical" { //nolint:errcheck // zero-value fallback is intentional
			n++
		}
	}
	return n
}

// owlLowConfidence lists protocols whose reliability-weighted severity sits
// below the moderate threshold, plus the total weighted-protocol count.
// Protocols whose stored status is a confirmed outcome are excluded: the
// pipeline's raw scale is outcome-valenced (a corroborated failure scores
// 0.3, a confirmed absence 0.0), so a low weighted value there restates
// the verdict — certainty, not doubt. What remains genuinely is doubt: a
// passing or advisory status whose reliability-weighted severity was
// dragged below moderate (e.g. by resolver disagreement).
func owlLowConfidence(results map[string]any, confirmedOutcome map[string]bool) (low []string, calibratedTotal int) {
	calibrated := calibratedConfidenceMap(results)
	for _, p := range owlProtocolOrder {
		if confirmedOutcome[p.ConfKey] {
			continue
		}
		if cc, cOk := calibrated[p.ConfKey]; cOk && cc < owlLowConfidenceThreshold {
			low = append(low, fmt.Sprintf("%s (%.2f)", p.Name, cc))
		}
	}
	return low, len(calibrated)
}

func owlNormativeState(passed []string) map[string]any {
	if len(passed) == 0 {
		return owlState(false, 0, "Not triggered — no protocol section completed evaluation with passing status.")
	}
	return owlState(true, len(passed),
		owlPlural(len(passed), "protocol check", "protocol checks")+
			" completed RFC-conformance evaluation with passing status: "+strings.Join(passed, ", ")+".")
}

func owlNonNormativeState(recCount, monCount int, infos []string) map[string]any {
	total := recCount + monCount + len(infos)
	if total == 0 {
		return owlState(false, 0, "Not triggered — no advisory recommendations, monitoring notes, or informational statuses recorded.")
	}
	var parts []string
	if recCount > 0 {
		parts = append(parts, owlPlural(recCount, "advisory recommendation", "advisory recommendations"))
	}
	if monCount > 0 {
		parts = append(parts, owlPlural(monCount, "monitoring note", "monitoring notes"))
	}
	if len(infos) > 0 {
		parts = append(parts, "informational status: "+strings.Join(infos, ", "))
	}
	return owlState(true, total, "Advisory findings recorded — "+strings.Join(parts, "; ")+".")
}

func owlCriticalState(critIssueCount int, errored []string, critFixCount int, spoofDoorOpen bool) map[string]any {
	total := critIssueCount + len(errored) + critFixCount
	if spoofDoorOpen {
		total++
	}
	if total == 0 {
		return owlState(false, 0, "Not triggered — no critical issues, failed evaluation statuses, Critical-severity fixes, or open email-spoofing door recorded.")
	}
	var parts []string
	if critIssueCount > 0 {
		parts = append(parts, owlPlural(critIssueCount, "critical issue", "critical issues")+" flagged in security posture")
	}
	if len(errored) > 0 {
		parts = append(parts, "failed evaluation status: "+strings.Join(errored, ", "))
	}
	if critFixCount > 0 {
		parts = append(parts, owlPlural(critFixCount, "Critical-severity remediation fix", "Critical-severity remediation fixes"))
	}
	if spoofDoorOpen {
		parts = append(parts, "the stored posture records the email-spoofing door as open — a spoofed message claiming this domain is delivered with nothing blocking it")
	}
	return owlState(true, total, "Critical signal recorded — "+strings.Join(parts, "; ")+".")
}

func owlMetacognitiveState(indeterminate, stateIndeterminate, lowConf []string) map[string]any {
	total := len(indeterminate) + len(stateIndeterminate) + len(lowConf)
	if total == 0 {
		return owlState(false, 0, "Not triggered — no indeterminate statuses or tri-states; reliability-weighted severity at or above the moderate threshold (0.50) for all weighted protocols without a confirmed outcome.")
	}
	var parts []string
	if len(indeterminate) > 0 {
		parts = append(parts, "indeterminate status (evidence insufficient to conclude): "+strings.Join(indeterminate, ", "))
	}
	if len(stateIndeterminate) > 0 {
		parts = append(parts, "recorded tri-state is indeterminate — the lookup did not complete, so the finding could not be verified: "+strings.Join(stateIndeterminate, ", "))
	}
	if len(lowConf) > 0 {
		parts = append(parts, "reliability-weighted severity below the moderate threshold (0.50): "+strings.Join(lowConf, ", "))
	}
	return owlState(true, total, "Uncertainty acknowledged — "+strings.Join(parts, "; ")+".")
}

// computeOwlSemaphore derives the four owl states from a completed
// analysis's full_results. Returns nil when the results carry none of the
// signal sources (old or malformed scans).
func computeOwlSemaphore(fullResults any) map[string]any {
	results, ok := fullResults.(map[string]any)
	if !ok || len(results) == 0 {
		return nil
	}

	sections := owlCollectSections(results)
	recCount, monCount, critIssueCount, postureSeen := owlPostureCounts(results)
	critFixCount := owlCriticalFixCount(results)
	lowConf, calibratedTotal := owlLowConfidence(results, sections.confirmedOutcome)

	if sections.seen == 0 && !postureSeen && calibratedTotal == 0 {
		return nil
	}

	return map[string]any{
		"version":       1,
		"normative":     owlNormativeState(sections.passed),
		"non_normative": owlNonNormativeState(recCount, monCount, sections.infos),
		"critical":      owlCriticalState(critIssueCount, sections.errored, critFixCount, owlSpoofDoorOpen(results)),
		"metacognitive": owlMetacognitiveState(sections.indeterminate, sections.stateIndeterminate, lowConf),
	}
}
