// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package fixturecorpus

import (
	"encoding/json"
	"testing"
)

func TestLookup(t *testing.T) {
	cases := []struct {
		domain string
		corpus string // "" = expect nil
	}{
		// Exact corpus members.
		{"apple.com", "icae-case"},
		{"bbc.co.uk", "icae-case"},
		{"google.com", "baseline"},
		{"cloudflare.com", "baseline"},
		// The negative-control fixture is still a corpus member and must
		// disclose like any other baseline domain.
		{"thisdoesnotexist-xz9q.com", "baseline"},
		// Registrable-domain matching: subdomains of corpus domains disclose.
		{"www.apple.com", "icae-case"},
		{"deep.sub.cloudflare.com", "baseline"},
		{"news.bbc.co.uk", "icae-case"},
		// Normalization.
		{"APPLE.COM.", "icae-case"},
		{"  google.com ", "baseline"},
		// Non-members, including suffixes of corpus domains — the walk must
		// never promote a public suffix or an unrelated sibling.
		{"co.uk", ""},
		{"uk", ""},
		{"example.org", ""},
		{"notapple.com", ""},
		{"apple.com.evil.example", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := Lookup(tc.domain)
		switch {
		case tc.corpus == "" && got != nil:
			t.Errorf("Lookup(%q) = %v, want nil", tc.domain, got)
		case tc.corpus != "" && got == nil:
			t.Errorf("Lookup(%q) = nil, want corpus %q", tc.domain, tc.corpus)
		case tc.corpus != "" && got != nil && got.Corpus != tc.corpus:
			t.Errorf("Lookup(%q).Corpus = %q, want %q", tc.domain, got.Corpus, tc.corpus)
		}
	}
}

func TestCorpusJSONIsValidAndComplete(t *testing.T) {
	var m map[string]Disclosure
	if err := json.Unmarshal([]byte(CorpusJSON()), &m); err != nil {
		t.Fatalf("CorpusJSON is not valid JSON: %v", err)
	}
	for _, d := range []string{"apple.com", "bbc.co.uk", "google.com", "thisdoesnotexist-xz9q.com"} {
		if _, ok := m[d]; !ok {
			t.Errorf("CorpusJSON missing %q", d)
		}
	}
	for domain, disc := range m {
		if disc.Badge == "" || disc.Note == "" || disc.Corpus == "" {
			t.Errorf("CorpusJSON[%q] has empty fields: %+v", domain, disc)
		}
	}
}
