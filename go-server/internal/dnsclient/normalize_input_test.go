// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package cover the full product source.
package dnsclient

import "testing"

func TestNormalizeDomainInput(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		// The reason this exists: pasting a URL is the commonest way anyone
		// enters a domain, and it used to be rejected outright.
		{"plain domain untouched", "example.com", "example.com", false},
		{"https + path", "https://example.com/path", "example.com", true},
		{"http + query + fragment", "http://example.com/a?b=1#c", "example.com", true},
		{"scheme case", "HTTPS://Example.com/", "example.com", true},
		{"port stripped", "https://example.com:8443/x", "example.com", true},
		{"scheme-relative", "//example.com/x", "example.com", true},
		{"subdomain preserved", "https://mail.example.com/inbox", "mail.example.com", true},
		{"trailing dot", "example.com.", "example.com", true},
		{"leading dots", "..example.com", "example.com", true},
		{"whitespace", "  example.com  ", "example.com", false},

		// A bare domain has no scheme, so url.Parse puts it in .Path with an
		// EMPTY .Host. Parsing unconditionally would turn every plain domain
		// into "" — the failure mode this branch exists to prevent.
		{"bare domain does not parse to empty", "sub.example.co.uk", "sub.example.co.uk", false},

		// Registry zones must survive normalization and still reach the
		// zone-apex path rather than being rejected as malformed.
		{"bare TLD", "com", "com", false},
		{"TLD with scheme", "https://com", "com", true},
		{"multi-label public suffix with scheme", "https://co.uk/", "co.uk", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, _ := NormalizeDomainInput(tc.in)
			if got != tc.want {
				t.Errorf("NormalizeDomainInput(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if changed != tc.changed {
				t.Errorf("changed = %v, want %v (disclosure depends on this)", changed, tc.changed)
			}
		})
	}
}

// The security case. In "https://evil.com@real.com/" the host is real.com —
// everything before the @ is userinfo. A pattern that took everything between
// the scheme and the first "/" would scan the ATTACKER's domain and report it
// under the victim's name. net/url gets this right; a regex would not.
func TestNormalizeDomainInputUserinfoConfusion(t *testing.T) {
	for _, in := range []string{
		"https://evil.com@real.com/",
		"https://user:pass@real.com/path",
		"https://evil.com%40real.com@real.com/",
	} {
		got, changed, discarded := NormalizeDomainInput(in)
		if got != "real.com" {
			t.Errorf("NormalizeDomainInput(%q) = %q, want real.com — scanning the wrong domain", in, got)
		}
		if !changed {
			t.Errorf("%q must be reported as changed so the substitution is disclosed", in)
		}
		if discarded == "" {
			t.Errorf("%q discarded userinfo with no description to disclose", in)
		}
	}
}

// Whenever the input changed, the caller has something specific to show the
// user. A silent substitution is the defect this whole function is designed
// around: the user believes they scanned what they typed.
func TestNormalizeDomainInputAlwaysDescribesWhatItRemoved(t *testing.T) {
	for _, in := range []string{
		"https://example.com/path",
		"http://example.com:8080/",
		"https://u@example.com/",
		"example.com.",
	} {
		got, changed, discarded := NormalizeDomainInput(in)
		if !changed {
			t.Errorf("%q should be marked changed (got %q)", in, got)
			continue
		}
		if discarded == "" {
			t.Errorf("%q changed the input but described nothing — the disclosure would be empty", in)
		}
	}
	// And the converse: unchanged input must not claim a discard.
	if _, changed, discarded := NormalizeDomainInput("example.com"); changed || discarded != "" {
		t.Errorf("unchanged input reported changed=%v discarded=%q", changed, discarded)
	}
}

// Normalized output must satisfy the validator, or the feature converts one
// rejection into another.
func TestNormalizedInputPassesValidation(t *testing.T) {
	for _, in := range []string{
		"https://example.com/path", "http://mail.example.co.uk:443/x?y=1",
		"https://user@example.org/", "//example.net/a",
	} {
		got, _, _ := NormalizeDomainInput(in)
		if !ValidateDomain(got) {
			t.Errorf("NormalizeDomainInput(%q) = %q which fails ValidateDomain", in, got)
		}
	}
}

func TestNormalizeDomainInputDegradesHonestly(t *testing.T) {
	// Unparseable input is handed back unchanged rather than guessed at —
	// validation downstream rejects it with its own message.
	for _, in := range []string{"://", "https://", "   "} {
		got, changed, _ := NormalizeDomainInput(in)
		if changed {
			t.Errorf("NormalizeDomainInput(%q) = %q claimed a change it cannot justify", in, got)
		}
	}
}
