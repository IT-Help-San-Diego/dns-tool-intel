// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"strings"
)

func identifyCAIssuer(record string) string {
	lower := strings.ToLower(record)
	switch {
	case strings.Contains(lower, "letsencrypt"):
		return "Let's Encrypt"
	case strings.Contains(lower, "digicert"):
		return "DigiCert"
	case strings.Contains(lower, "sectigo") || strings.Contains(lower, "comodo"):
		return "Sectigo"
	case strings.Contains(lower, "globalsign"):
		return "GlobalSign"
	case strings.Contains(lower, "amazon"):
		return "Amazon"
	case strings.Contains(lower, "google"):
		return "Google Trust Services"
	default:
		parts := strings.Fields(record)
		if len(parts) >= 3 {
			// RFC 8659 §4.2/§4.3: an empty issuer-domain-name is written as a
			// lone `;`. That is the "no CA may issue" / "no wildcard cert"
			// sentinel, NOT a CA literally named `;`. Return empty so the caller
			// records "restricted, no issuer" instead of inventing an issuer.
			issuer := strings.Trim(parts[len(parts)-1], "\"")
			if issuer == ";" {
				return ""
			}
			return issuer
		}
		return ""
	}
}

type caaParsedRecords struct {
	issueSet     map[string]bool
	issuewildSet map[string]bool
	hasWildcard  bool
	hasIodef     bool
	// fullyRestricted: an `issue ";"` — RFC 8659 §4.2 "no CA may issue".
	// Distinct from "no issue records at all" (which is default-permissive):
	// this is an affirmative prohibition.
	fullyRestricted bool
	// wildcardFullyRestricted: an `issuewild ";"` — RFC 8659 §4.3 "no wildcard".
	wildcardFullyRestricted bool
}

func parseCAARecords(records []string) caaParsedRecords {
	parsed := caaParsedRecords{
		issueSet:     make(map[string]bool),
		issuewildSet: make(map[string]bool),
	}
	for _, record := range records {
		parseSingleCAARecord(record, &parsed)
	}
	return parsed
}

func parseSingleCAARecord(record string, parsed *caaParsedRecords) {
	lower := strings.ToLower(record)

	if strings.Contains(lower, "issuewild") {
		parsed.hasWildcard = true
		if issuer := identifyCAIssuer(record); issuer != "" {
			parsed.issuewildSet[issuer] = true
		} else {
			// `issuewild ";"` — no wildcard certificate may be issued.
			parsed.wildcardFullyRestricted = true
		}
	} else if strings.Contains(lower, "issue ") || strings.Contains(lower, "issue\"") {
		if issuer := identifyCAIssuer(record); issuer != "" {
			parsed.issueSet[issuer] = true
		} else {
			// `issue ";"` — no CA may issue any certificate (RFC 8659 §4.2).
			parsed.fullyRestricted = true
		}
	}

	if strings.Contains(lower, "iodef") {
		parsed.hasIodef = true
	}
}

func collectMapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func buildCAAMessage(issuers, wildcardIssuers []string, hasWildcard bool, fullyRestricted, wildcardFullyRestricted bool) string {
	messageParts := []string{"CAA configured"}
	if fullyRestricted {
		// RFC 8659 §4.2 `issue ";"` — no CA may issue any certificate. The
		// strongest CAA state; must not read as "specific CAs authorized".
		messageParts = append(messageParts, "- no CA may issue any certificate (RFC 8659 §4.2)")
	} else if len(issuers) > 0 {
		messageParts = append(messageParts, "- only "+strings.Join(issuers, ", ")+" can issue certificates")
	} else {
		messageParts = append(messageParts, "- specific CAs authorized")
	}

	if wildcardFullyRestricted {
		messageParts = append(messageParts, "(no wildcard certificate issuance: RFC 8659 §4.3)")
	} else if hasWildcard {
		if len(wildcardIssuers) > 0 {
			messageParts = append(messageParts, fmt.Sprintf("(wildcard issuance: %s per RFC 8659 §4.3)", strings.Join(wildcardIssuers, ", ")))
		} else {
			messageParts = append(messageParts, "(wildcard issuance restricted)")
		}
	}

	return strings.Join(messageParts, " ")
}

func (a *Analyzer) AnalyzeCAA(ctx context.Context, domain string) map[string]any {
	records, lookupStatus := a.resolveWithStatus(ctx, "CAA", domain)
	caaSource := domain

	// RFC 8659 §3: "The search for a CAA RRset climbs the DNS name tree from
	// the specified label up to, but not including, the DNS root '.' until a
	// CAA RRset is found." A CA checking pq.example.com with no CAA there
	// MUST consult example.com (then com) before concluding issuance is
	// unrestricted. An exact-name-only lookup therefore reports "no CAA -
	// any CA can issue" on a subdomain whose parent DOES restrict issuance -
	// a false negative about the real issuance policy (Replit-era defect,
	// exact-name lookup only since c84dc95f9; same inheritance class as the
	// DMARC org-domain fallback one protocol over, RFC 7489 §6.6.3).
	//
	// Climb only on CONFIRMED absence at each label: an indeterminate lookup
	// anywhere in the chain means the climb's conclusion cannot be trusted
	// (the skipped label might hold the policy), so we stop and report
	// indeterminate rather than fabricate an "unrestricted" verdict.
	// The climb stops below the public suffix: a CAA RRset published inside
	// the registry's suffix zone is the registry's policy, not the
	// domain's; measuring it as the domain's issuance policy would
	// misattribute. (CAs do climb through it per RFC 8659; for THIS
	// instrument the domain-operator boundary is the honest scope.)
	if len(records) == 0 && !isIndeterminateLookup(lookupStatus) {
		org, orgIndeterminate := orgDomain(domain)
		if !orgIndeterminate && org != strings.ToLower(strings.TrimRight(domain, ".")) {
			labels := strings.Split(strings.TrimRight(strings.ToLower(domain), "."), ".")
			orgLabels := strings.Split(org, ".")
			// walk parents from one label above the query name down to org
			for i := 1; i <= len(labels)-len(orgLabels); i++ {
				parent := strings.Join(labels[i:], ".")
				pRecords, pStatus := a.resolveWithStatus(ctx, "CAA", parent)
				if isIndeterminateLookup(pStatus) {
					return map[string]any{
						"status":       statusIndeterminate,
						"message":      fmt.Sprintf("No CAA at %s; the RFC 8659 §3 tree climb could not be completed (%s lookup indeterminate) — issuance policy cannot be determined.", domain, parent),
						"records":      []string{},
						"issuers":      []string{},
						"has_wildcard": false,
						"has_iodef":    false,
						mapKeyCaaState: triStateIndeterminate,
					}
				}
				if len(pRecords) > 0 {
					records = pRecords
					caaSource = parent
					break
				}
			}
		}
	}

	if len(records) == 0 {
		if isIndeterminateLookup(lookupStatus) {
			return map[string]any{
				"status":       statusIndeterminate,
				"message":      indeterminateLookupMessage("CAA", lookupStatus),
				"records":      []string{},
				"issuers":      []string{},
				"has_wildcard": false,
				"has_iodef":    false,
				mapKeyCaaState: triStateIndeterminate,
			}
		}
		return map[string]any{
			"status":       "warning",
			"message":      "No CAA records found - any CA can issue certificates",
			"records":      []string{},
			"issuers":      []string{},
			"has_wildcard": false,
			"has_iodef":    false,
			mapKeyCaaState: triStateAbsentConf,
		}
	}

	parsed := parseCAARecords(records)
	issuers := collectMapKeys(parsed.issueSet)
	wildcardIssuers := collectMapKeys(parsed.issuewildSet)
	message := buildCAAMessage(issuers, wildcardIssuers, parsed.hasWildcard, parsed.fullyRestricted, parsed.wildcardFullyRestricted)
	if caaSource != domain {
		message = fmt.Sprintf("Covered by parent-zone CAA (RFC 8659 §3 tree climb): %s publishes the issuance policy applying to %s. %s", caaSource, domain, message)
	}

	result := map[string]any{
		mapKeyCaaState:     triStatePresent,
		"status":           "success",
		"message":          message,
		"records":          records,
		"issuers":          issuers,
		"wildcard_issuers": wildcardIssuers,
		"has_wildcard":     parsed.hasWildcard,
		"has_iodef":        parsed.hasIodef,
		"mpic_note":        "Since September 2025, all public CAs must verify domain control from multiple geographic locations (Multi-Perspective Issuance Corroboration, CA/B Forum Ballot SC-067). CAA records are now checked from multiple network perspectives before certificate issuance.",
	}
	if caaSource != domain {
		result["caa_source"] = caaSource
		result["inherited"] = true
	}
	return result
}
