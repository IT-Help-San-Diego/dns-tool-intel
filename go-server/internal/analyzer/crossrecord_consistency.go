// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "strconv"

// Cross-record consistency: findings that arise only from reading two records
// together, where each record passes its own conformance check.
//
// Specification: docs/research/cross-record-consistency-spec.md (PR #247), which
// carries the RFC entailment for each rule and the measured hit rate from a
// 339-domain survey. Hit rates are why R6 is absent here: it fires on 68% of
// domains, which is a population statistic rather than a per-domain signal.
//
// THREE HARD CONSTRAINTS, all from the spec:
//
//  1. A finding names a TENSION BETWEEN TWO RECORDS. It never asserts the
//     operator was wrong. A configuration is evidence of a choice, not proof of
//     a reason — see R3, where the "tension" is plausibly a deliberate
//     intelligence posture and the finding must not rank it.
//
//  2. A rule fires only when BOTH of its facts are KNOWN. The analyzers publish
//     a tri-state (triStatePresent / triStateAbsentConf / triStateIndeterminate)
//     precisely so that a lookup which did not complete is never read as an
//     absence. An indeterminate input yields no finding — not a passing one.
//
//  3. Vocabulary guard. Three consistency concepts now exist in this package and
//     they are NOT interchangeable:
//     - delegation_consistency.go — intra-DNSSEC coherence (DS vs DNSKEY, glue, SOA)
//     - verdict_entailment_test.go — verdict vs the evidence that produced it
//     - this file — record vs record, via a cited RFC entailment
type CrossRecordRule string

const (
	RuleInvertedRamp       CrossRecordRule = "inverted_enforcement_ramp"
	RuleTransportOnly      CrossRecordRule = "transport_enforced_sender_not"
	RuleStrictSoft         CrossRecordRule = "strict_alignment_soft_disposition"
	RulePartialEnforce     CrossRecordRule = "partial_enforcement"
	RuleBIMIWithoutEnforce CrossRecordRule = "bimi_without_enforcement"
)

// CrossRecordFinding is one tension between two records. Both source records are
// named so a reader can check the claim, and RFCSection cites the entailment
// rather than asserting authority.
type CrossRecordFinding struct {
	Rule       CrossRecordRule `json:"rule"`
	Records    [2]string       `json:"records"`
	RFCSection string          `json:"rfc_section"`
	Tension    string          `json:"tension"`
	Observed   string          `json:"observed"`
}

// dmarcFacts is the subset of DMARC state the rules read. Known is false when the
// DMARC lookup did not complete: constraint 2 — an indeterminate probe is not an
// absence, and a rule reading it produces nothing rather than a false negative.
type dmarcFacts struct {
	Known   bool
	Present bool
	Policy  string // "none" | "quarantine" | "reject" | "" when absent
	// SubPol is "" when sp is unset. derefStr stores nil (not "") for an absent
	// tag, so the type assertion fails and leaves the zero value. RFC 7489 §6.3:
	// an unset sp means p applies to subdomains, so no ramp inversion exists.
	SubPol string
	Pct    int
	Aspf   string
	Adkim  string
}

// Alignment tag values as the DMARC analyzer stores them. parseDMARCTags maps the
// wire values "s"/"r" (RFC 7489 §6.3) to these words before they reach the result
// map — reading the wire values here would produce a rule that can never fire.
const alignStrict = "strict"

// policyRank orders DMARC dispositions by strictness so R1 can ask whether sp is
// STRICTLY stronger than p. Unknown values rank -1 and never compare as stronger,
// so an unparsed tag cannot manufacture a finding.
func policyRank(p string) int {
	switch p {
	case "none":
		return 0
	case "quarantine":
		return 1
	case "reject":
		return 2
	default:
		return -1
	}
}

// recordKnown reports whether a protocol result carries a definitive presence
// answer. The tri-state lives in lookup_status.go and exists so that absence is
// asserted only from an authoritative answer.
func recordKnown(res map[string]any, stateKey string) (known, present bool) {
	s, _ := res[stateKey].(string)
	switch s {
	case triStatePresent:
		return true, true
	case triStateAbsentConf:
		return true, false
	default: // triStateIndeterminate, missing, or unrecognized
		return false, false
	}
}

// extractDMARCFacts reads the DMARC analyzer's result map. It returns Known=false
// on an indeterminate lookup so every downstream rule short-circuits.
func extractDMARCFacts(dmarc map[string]any) dmarcFacts {
	known, present := recordKnown(dmarc, mapKeyDmarcState)
	f := dmarcFacts{Known: known, Present: present, Pct: 100}
	if !known || !present {
		return f
	}
	if p, ok := dmarc["policy"].(string); ok {
		f.Policy = p
	}
	if sp, ok := dmarc["subdomain_policy"].(string); ok {
		f.SubPol = sp
	}
	if pct, ok := dmarc["pct"].(int); ok {
		f.Pct = pct
	}
	if v, ok := dmarc["aspf"].(string); ok {
		f.Aspf = v
	}
	if v, ok := dmarc["adkim"].(string); ok {
		f.Adkim = v
	}
	return f
}

// EvaluateCrossRecordConsistency returns the tensions visible only when two
// records are read together. results is the orchestrator's collected per-protocol
// map, keyed "dmarc", "mta_sts", "bimi".
//
// R6 from the spec is deliberately NOT implemented: at 232/339 (68%) it is a
// population statistic, and a per-domain finding that fires on two thirds of
// domains conveys almost nothing. It belongs on the education surface.
func EvaluateCrossRecordConsistency(results map[string]any) []CrossRecordFinding {
	dmarcRes, _ := results["dmarc"].(map[string]any)
	mtaRes, _ := results["mta_sts"].(map[string]any)
	bimiRes, _ := results["bimi"].(map[string]any)

	d := extractDMARCFacts(dmarcRes)
	var out []CrossRecordFinding

	// R1 — inverted enforcement ramp. Fires when sp is STRICTLY stronger than p.
	// The conventional ramp tightens the apex first, because the organizational
	// domain is the most impersonated identity. 13/339 observed.
	if d.Known && d.Present && d.SubPol != "" {
		if pr, sr := policyRank(d.Policy), policyRank(d.SubPol); pr >= 0 && sr > pr {
			out = append(out, CrossRecordFinding{
				Rule:       RuleInvertedRamp,
				Records:    [2]string{"DMARC p", "DMARC sp"},
				RFCSection: "RFC 7489 §6.3",
				Tension:    "subdomains are held to a stricter policy than the organizational domain",
				Observed:   "p=" + d.Policy + ", sp=" + d.SubPol,
			})
		}
	}

	// R2 — transport enforced, sender identity not. Publishing MTA-STS asserts
	// transport for this domain is worth protecting against downgrade
	// (RFC 8461 §2); p=none requests no disposition for a message that fails
	// authentication. The pipe is guaranteed; the sender is not. 11/339.
	if mKnown, mPresent := recordKnown(mtaRes, mapKeyMtaStsState); mKnown && mPresent && d.Known {
		if !d.Present || d.Policy == "none" {
			observed := "MTA-STS present, DMARC absent"
			if d.Present {
				observed = "MTA-STS present, DMARC p=none"
			}
			out = append(out, CrossRecordFinding{
				Rule:       RuleTransportOnly,
				Records:    [2]string{"MTA-STS policy", "DMARC p"},
				RFCSection: "RFC 8461 §2; RFC 7489 §6.3",
				Tension:    "message transport is protected against downgrade while sender authentication failures receive no disposition",
				Observed:   observed,
			})
		}
	}

	// R3 — strict alignment with soft disposition. Strict alignment
	// (RFC 7489 §3.1) narrows what counts as a pass, increasing the failure
	// rate; a soft disposition then declines to act on those additional
	// failures. 10/339.
	//
	// PER THE SPEC, THIS MUST NOT BE REPORTED AS A WEAKNESS. Strict alignment
	// with quarantine is a stricter matching rule with a retention-friendly
	// disposition — a quarantined message is evidence still held, where a
	// rejected one is gone. Plausibly an intelligence posture, not a gap. The
	// wording below states the tension and ranks nothing.
	if d.Known && d.Present && d.Aspf == alignStrict && d.Adkim == alignStrict && d.Policy != "reject" {
		out = append(out, CrossRecordFinding{
			Rule:       RuleStrictSoft,
			Records:    [2]string{"DMARC aspf/adkim", "DMARC p"},
			RFCSection: "RFC 7489 §3.1, §6.3",
			Tension:    "strict alignment widens what fails authentication while the disposition stops short of rejection",
			Observed:   "aspf=s, adkim=s, p=" + d.Policy,
		})
	}

	// R4 — partial enforcement. RFC 7489 §6.3 defines pct as the percentage of
	// messages the policy is applied to; below 100 a proportion of failing mail
	// receives no disposition. Usually mid-rollout, which is legitimate — the
	// finding is informational. 3/339.
	if d.Known && d.Present && d.Pct < 100 && d.Policy != "none" {
		out = append(out, CrossRecordFinding{
			Rule:       RulePartialEnforce,
			Records:    [2]string{"DMARC pct", "DMARC p"},
			RFCSection: "RFC 7489 §6.3",
			Tension:    "the stated policy is applied to only a fraction of failing messages",
			Observed:   "pct=" + strconv.Itoa(d.Pct) + ", p=" + d.Policy,
		})
	}

	// R5 — BIMI without enforcement. BIMI requires the domain to be at DMARC
	// enforcement; a BIMI record on a non-enforcing domain asserts a
	// precondition the DMARC policy does not provide. 1/339 — rare, which makes
	// it high-signal when it fires.
	if bKnown, bPresent := recordKnown(bimiRes, mapKeyBimiState); bKnown && bPresent && d.Known {
		enforcing := d.Present && (d.Policy == "quarantine" || d.Policy == "reject")
		if !enforcing {
			observed := "BIMI present, DMARC absent"
			if d.Present {
				observed = "BIMI present, DMARC p=" + d.Policy
			}
			out = append(out, CrossRecordFinding{
				Rule:       RuleBIMIWithoutEnforce,
				Records:    [2]string{"BIMI record", "DMARC p/sp"},
				RFCSection: "RFC 7489 §6.3",
				Tension:    "a BIMI record asserts DMARC enforcement as a precondition that the published policy does not provide",
				Observed:   observed,
			})
		}
	}

	return out
}
