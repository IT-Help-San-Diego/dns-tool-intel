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
//	metacognitive — protocol sections with status "indeterminate" and
//	                protocols whose calibrated confidence falls below the
//	                moderate threshold (unified.ThresholdModerate = 50.0,
//	                i.e. 0.50 on the 0-1 calibrated scale).
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
// ConfKey is the calibrated_confidence map key (underscore spellings).
var owlProtocolOrder = []struct {
	Name    string
	Key     string
	ConfKey string
}{
	{"SPF", mapKeySpfAnalysis, "SPF"},
	{"DKIM", mapKeyDkimAnalysis, "DKIM"},
	{"DMARC", mapKeyDmarcAnalysis, "DMARC"},
	{"DNSSEC", "dnssec_analysis", "DNSSEC"},
	{"DANE", "dane_analysis", "DANE"},
	{"MTA-STS", "mta_sts_analysis", "MTA_STS"},
	{"TLS-RPT", "tlsrpt_analysis", "TLS_RPT"},
	{"BIMI", "bimi_analysis", "BIMI"},
	{"CAA", "caa_analysis", "CAA"},
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
type owlSectionBuckets struct {
	passed        []string
	infos         []string
	errored       []string
	indeterminate []string
	seen          int
}

func owlCollectSections(results map[string]any) owlSectionBuckets {
	var b owlSectionBuckets
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
		case "indeterminate":
			b.indeterminate = append(b.indeterminate, p.Name)
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

// owlLowConfidence lists protocols whose calibrated confidence sits below
// the moderate threshold, plus the total calibrated-protocol count.
func owlLowConfidence(results map[string]any) (low []string, calibratedTotal int) {
	calibrated := calibratedConfidenceMap(results)
	for _, p := range owlProtocolOrder {
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

func owlMetacognitiveState(indeterminate, lowConf []string) map[string]any {
	total := len(indeterminate) + len(lowConf)
	if total == 0 {
		return owlState(false, 0, "Not triggered — no indeterminate statuses; calibrated confidence at or above the moderate threshold (0.50) for all calibrated protocols.")
	}
	var parts []string
	if len(indeterminate) > 0 {
		parts = append(parts, "indeterminate status (evidence insufficient to conclude): "+strings.Join(indeterminate, ", "))
	}
	if len(lowConf) > 0 {
		parts = append(parts, "calibrated confidence below the moderate threshold (0.50): "+strings.Join(lowConf, ", "))
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
	lowConf, calibratedTotal := owlLowConfidence(results)

	if sections.seen == 0 && !postureSeen && calibratedTotal == 0 {
		return nil
	}

	return map[string]any{
		"version":       1,
		"normative":     owlNormativeState(sections.passed),
		"non_normative": owlNonNormativeState(recCount, monCount, sections.infos),
		"critical":      owlCriticalState(critIssueCount, sections.errored, critFixCount, owlSpoofDoorOpen(results)),
		"metacognitive": owlMetacognitiveState(sections.indeterminate, lowConf),
	}
}
