// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import "testing"

func TestEditDistance(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"both empty", "", "", 0},
		{"a empty", "", "abc", 3},
		{"b empty", "abc", "", 3},
		{"identical", "google", "google", 0},
		{"substitution", "google", "go0gle", 1},
		{"insertion", "gogle", "google", 1},
		{"deletion", "google", "gogle", 1},
		{"transposition (Levenshtein = 2 swaps)", "google", "goolge", 2},
		{"classic kitten->sitting", "kitten", "sitting", 3},
	}
	for _, tc := range cases {
		if got := EditDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: EditDistance(%q, %q) = %d, want %d", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDomainEditDistance(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"case-insensitive", "Google.com", "google.com", 0},
		{"homoglyph substitution", "google.com", "go0gle.com", 1},
		{"missing letter", "gogle.com", "google.com", 1},
		{"transposition", "hermes-agent.com", "hermes-agnet.com", 2},
	}
	for _, tc := range cases {
		if got := DomainEditDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: DomainEditDistance(%q, %q) = %d, want %d", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}
