// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"strings"
	"sync"
)

// "Did you mean?" correction for a domain that returned an authoritative
// NXDOMAIN (domain_status "undelegated"). A single-character typo is the most
// common reason a user reaches a non-existent domain, so we generate the
// edit-distance-1 neighbourhood of the second-level label (TLD held fixed)
// plus a small set of common TLD swaps, and return the candidates that
// actually resolve. It is deliberately BEST-EFFORT: it catches the common
// single-character error, not every conceivable misspelling, and it is
// bounded so an NXDOMAIN submission cannot multiply into unbounded resolver
// traffic (the same good-net-citizen discipline as the existence probe).

// suggestionTLDs are the common extensions swapped in when the label is right
// but the user typed the wrong one. Kept short and curated — a hint, not a
// catalogue.
var suggestionTLDs = []string{"com", "net", "org", "io", "co", "dev", "ai", "app", "us", "info"}

const (
	// maxSuggestionSLDLength bounds the candidate explosion: the
	// edit-distance-1 space of an N-character label is O(26·N), so labels
	// longer than this get no suggestion rather than a few thousand lookups of
	// garbage input.
	maxSuggestionSLDLength = 18

	// maxSuggestionChecks caps the total existence lookups one suggestion pass
	// may issue. It is large enough to cover the full edit-distance-1 space of
	// an 18-character label and no more.
	maxSuggestionChecks = 1024

	// suggestionWorkerCount bounds concurrent resolver lookups during the pass.
	suggestionWorkerCount = 16
)

// candidateCorrections returns the ordered, de-duplicated edit-distance-1
// neighbourhood of `domain`: every single-character insertion, deletion,
// substitution, and transposition of the second-level label (the TLD is held
// fixed), followed by the common-TLD swaps. Pure and deterministic — no
// network — so it is unit-tested independently of the resolver.
func candidateCorrections(domain string) []string {
	dot := strings.LastIndexByte(domain, '.')
	if dot <= 0 || dot == len(domain)-1 {
		// No second-level label (single label, or a trailing dot): nothing
		// meaningful to correct.
		return nil
	}
	sld, tld := strings.ToLower(domain[:dot]), strings.ToLower(domain[dot+1:])
	if len(sld) > maxSuggestionSLDLength {
		return nil
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// TLD swaps first: cheapest, highest-confidence, catches "right label,
	// wrong extension" outright.
	for _, t := range suggestionTLDs {
		if t != tld {
			add(sld + "." + t)
		}
	}

	// Insertions (a missing character — the single most common typo).
	for i := 0; i <= len(sld); i++ {
		for c := byte('a'); c <= 'z'; c++ {
			add(sld[:i] + string(c) + sld[i:] + "." + tld)
		}
	}
	// Deletions (a stray extra character).
	for i := range sld {
		add(sld[:i] + sld[i+1:] + "." + tld)
	}
	// Substitutions (one wrong character).
	for i := range sld {
		for c := byte('a'); c <= 'z'; c++ {
			if c == sld[i] {
				continue
			}
			add(sld[:i] + string(c) + sld[i+1:] + "." + tld)
		}
	}
	// Transpositions (two adjacent characters swapped).
	for i := 0; i+1 < len(sld); i++ {
		b := []byte(sld)
		b[i], b[i+1] = b[i+1], b[i]
		add(string(b) + "." + tld)
	}

	return out
}

// SuggestDomainCorrections returns up to `limit` candidate domains from the
// edit-distance-1 neighbourhood of `domain` that actually resolve (have an A
// record, via the querier's existence probe). The pass is bounded by
// maxSuggestionChecks lookups, run in parallel, and returns nil on a nil
// querier or a zero/negative limit. The queried domain itself is never
// suggested — it resolved to NXDOMAIN by the time this is called.
func SuggestDomainCorrections(ctx context.Context, q DNSQuerier, domain string, limit int) []string {
	if q == nil || limit <= 0 {
		return nil
	}
	candidates := candidateCorrections(domain)
	if len(candidates) > maxSuggestionChecks {
		candidates = candidates[:maxSuggestionChecks]
	}

	var (
		mu   sync.Mutex
		hits []string
		wg   sync.WaitGroup
		sem  = make(chan struct{}, suggestionWorkerCount)
	)
	for _, cand := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(c string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if exists, _ := q.ProbeExists(ctx, c); exists {
				mu.Lock()
				hits = append(hits, c)
				mu.Unlock()
			}
		}(cand)
	}
	wg.Wait()

	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}
