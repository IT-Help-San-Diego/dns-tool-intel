// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Package fixturecorpus centralizes disclosure metadata for domains that
// participate in the tool's own validation corpora. Two corpora exist and
// they demand different wording:
//
//   - baseline: domains whose whole-scan snapshots (tests/golden_fixtures/
//     manifest.json) are the regression baseline. A scan of one of these
//     reproducing its snapshot is the baseline returning its own value —
//     expected agreement, not independent validation.
//   - icae-case: domains hardcoded in ICAE development cases. Exactly one
//     named check is circular for them; every other finding is a live
//     measurement.
//
// dns-tool:scrutiny science
package fixturecorpus

import (
	"encoding/json"
	"sort"
	"strings"

	"dnstool/go-server/internal/icae"
	goldenfixtures "dnstool/tests/golden_fixtures"
)

// Disclosure is the user-facing statement attached to scans of corpus domains.
type Disclosure struct {
	Corpus string `json:"corpus"` // "baseline" or "icae-case"
	Badge  string `json:"badge"`  // short chip text
	Note   string `json:"note"`   // full disclosure sentence
}

func normalize(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// Lookup returns the disclosure for a corpus domain, or nil for everything
// else. Baseline membership wins if a domain ever appears in both corpora.
func Lookup(domain string) *Disclosure {
	d := normalize(domain)
	if d == "" {
		return nil
	}
	if goldenfixtures.IsBaselineDomain(d) {
		return &Disclosure{
			Corpus: "baseline",
			Badge:  "Golden-fixture baseline domain",
			Note: "This domain is part of the golden-fixture corpus: its recorded scan snapshot is the tool's regression baseline. " +
				"A scan of it reproducing the snapshot is the baseline returning its own value — expected agreement, not independent validation.",
		}
	}
	if check, ok := icae.FixtureCaseDomains[d]; ok {
		return &Disclosure{
			Corpus: "icae-case",
			Badge:  "ICAE development-case domain",
			Note: "This domain appears in hardcoded ICAE development cases for one check — " + check + ". " +
				"That single check is circular for this domain; all other findings are live measurements.",
		}
	}
	return nil
}

// CorpusJSON returns a {domain: disclosure} object as JSON, for client-side
// lighting of fixture-domain scans (topology scan console).
func CorpusJSON() string {
	all := map[string]*Disclosure{}
	for _, d := range goldenfixtures.Domains() {
		all[d] = Lookup(d)
	}
	icaeDomains := make([]string, 0, len(icae.FixtureCaseDomains))
	for d := range icae.FixtureCaseDomains {
		icaeDomains = append(icaeDomains, d)
	}
	sort.Strings(icaeDomains)
	for _, d := range icaeDomains {
		if _, exists := all[d]; !exists {
			all[d] = Lookup(d)
		}
	}
	b, err := json.Marshal(all)
	if err != nil {
		return "{}"
	}
	return string(b)
}
