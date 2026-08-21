// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"testing"
)

// candidateCorrections must generate the exact single-character edit that
// turns a real misspelling back into the intended domain. This pins the
// reported case (reissacupunture.com → reissacupuncture.com) so the suggestion
// can never regress silently.
func TestCandidateCorrections_ContainsSingleInsertion(t *testing.T) {
	cands := candidateCorrections("reissacupunture.com")
	seen := map[string]bool{}
	for _, c := range cands {
		seen[c] = true
	}
	if !seen["reissacupuncture.com"] {
		t.Fatalf("insertion correction 'reissacupuncture.com' missing from %d candidates", len(cands))
	}
}

// The TLD is held fixed during SLD edits: no candidate should change the TLD
// of a typo in the label, and the common-TLD swaps should be present.
func TestCandidateCorrections_HoldsTLDAndAddsSwaps(t *testing.T) {
	cands := candidateCorrections("example.cmo")
	seen := map[string]bool{}
	for _, c := range cands {
		seen[c] = true
	}
	// Common-TLD swap: the correct .com.
	if !seen["example.com"] {
		t.Fatalf("expected TLD swap example.com in candidates")
	}
	// SLD edits must keep the input TLD (cmo), so they are not valid
	// corrections and should still carry .cmo — verify a sample deletion.
	if !seen["xample.cmo"] {
		t.Fatalf("expected deletion xample.cmo in candidates")
	}
}

// The neighbourhood of a typo must never contain the typo itself.
func TestCandidateCorrections_NeverSuggestsInput(t *testing.T) {
	for _, c := range candidateCorrections("example.com") {
		if c == "example.com" {
			t.Fatalf("input domain appears in its own candidates")
		}
	}
}

// De-duplication: the neighbourhood is a set, not a multiset.
func TestCandidateCorrections_Deduplicated(t *testing.T) {
	cands := candidateCorrections("abc.com")
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c] {
			t.Fatalf("duplicate candidate %q", c)
		}
		seen[c] = true
	}
}

// Labels longer than the cap get no suggestion (the candidate space explodes),
// and a TLD-less input has no label to correct.
func TestCandidateCorrections_Bounded(t *testing.T) {
	long := make([]byte, maxSuggestionSLDLength+1)
	for i := range long {
		long[i] = 'a'
	}
	if got := candidateCorrections(string(long) + ".com"); got != nil {
		t.Fatalf("expected nil for over-long SLD, got %d candidates", len(got))
	}
	if got := candidateCorrections("com"); got != nil {
		t.Fatalf("expected nil for TLD-less input, got %d candidates", len(got))
	}
}
