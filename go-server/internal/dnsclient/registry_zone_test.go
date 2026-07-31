// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package cover the full product source.
package dnsclient

import "testing"

// IsTLDInput only ever recognised a SINGLE label, so "co.uk" fell through and
// received the full domain battery — SPF, DMARC, DKIM and the rest queried
// against a zone apex where they cannot exist, with their absence reported as
// findings about a domain nobody registered. IsRegistryZone asks the public
// suffix list instead of counting labels.
func TestIsRegistryZone(t *testing.T) {
	registryZones := []string{
		"com", "org", "uk", "gov",
		// The whole point: multi-label public suffixes.
		"co.uk", "ac.uk", "org.uk", "com.au", "co.jp", "co.nz", "gov.uk",
	}
	for _, d := range registryZones {
		t.Run("zone/"+d, func(t *testing.T) {
			if !IsRegistryZone(d) {
				t.Errorf("IsRegistryZone(%q) = false — it would receive the full domain battery", d)
			}
		})
	}

	registrable := []string{
		"example.com", "bbc.co.uk", "gov.example.com", "a.b.co.uk",
		"cia.gov", "ietf.org", "example.com.au",
	}
	for _, d := range registrable {
		t.Run("registrable/"+d, func(t *testing.T) {
			if IsRegistryZone(d) {
				t.Errorf("IsRegistryZone(%q) = true — a real domain would lose the checks it needs", d)
			}
		})
	}
}

// Counting dots is the obvious wrong implementation and it fails on exactly
// these two: "co.uk" has one dot and is NOT registrable, "bbc.co.uk" has two
// and IS. The public suffix list is the producer for this question.
func TestIsRegistryZoneIsNotDotCounting(t *testing.T) {
	if !IsRegistryZone("co.uk") {
		t.Error("co.uk (one dot) must be a registry zone")
	}
	if IsRegistryZone("bbc.co.uk") {
		t.Error("bbc.co.uk (two dots) must be registrable")
	}
}

// IsRegistryZone must be a strict widening of IsTLDInput: everything the old
// single-label check accepted still qualifies, so no input that was previously
// treated as a zone apex silently starts receiving domain probes.
func TestIsRegistryZoneWidensIsTLDInput(t *testing.T) {
	for _, d := range []string{"com", "net", "org", "io", "uk", "xn--p1ai"} {
		if IsTLDInput(d) && !IsRegistryZone(d) {
			t.Errorf("%q was a TLD input but is not a registry zone — the widening lost a case", d)
		}
	}
}

func TestIsRegistryZoneEdgeCases(t *testing.T) {
	for _, d := range []string{"", ".", "   ", "..."} {
		if IsRegistryZone(d) {
			t.Errorf("IsRegistryZone(%q) = true for a non-input", d)
		}
	}
	// Trailing dots are legal in DNS presentation form and must not change
	// the answer.
	if !IsRegistryZone("co.uk.") {
		t.Error("trailing dot changed the answer for co.uk.")
	}
	if IsRegistryZone("bbc.co.uk.") {
		t.Error("trailing dot changed the answer for bbc.co.uk.")
	}
}
