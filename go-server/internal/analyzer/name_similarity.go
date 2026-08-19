// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "strings"

// EditDistance returns the Levenshtein edit distance between two strings — the
// minimum number of single-character insertions, deletions, or substitutions
// needed to turn a into b. It is the measurement behind the impersonation
// name-similarity signal: a typosquatted domain sits a short edit distance from
// the established domain it imitates. It is a pure, database-independent
// function so it can run against any reference corpus without a query.
func EditDistance(a, b string) int {
	// Degenerate cases: one empty string costs the other's full length.
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	// Bound the two-row DP by the shorter string.
	if len(a) < len(b) {
		a, b = b, a
	}
	prev := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr := make([]int, len(b)+1)
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(b)]
}

// DomainEditDistance returns the edit distance between two domain names after
// lowercasing. DNS names are case-insensitive, so "Google.com" and "google.com"
// are distance 0 — the normalization keeps the comparison about the labels
// rather than the case.
func DomainEditDistance(a, b string) int {
	return EditDistance(strings.ToLower(a), strings.ToLower(b))
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
