// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"strings"
	"testing"
)

// Real captured keys, verified against openssl 2026-08-03. RFC 6376 p= is a
// DER SubjectPublicKeyInfo, so the decoded sizes are 162 bytes for 1024-bit
// RSA and 294 bytes for 2048-bit — NOT ≤140/≤300 as the pre-2026-08 length
// buckets assumed. Under those buckets every real 1024-bit key was reported
// as 2048-bit/adequate and the weak-key warning could never fire (cloudflare
// mandrill sat in the dev DB as key_bits 2048, key_strength adequate).
const (
	// it-help.tech google._domainkey, captured 2026-08-03 via dig: 2048-bit
	// RSA, 294-byte SPKI. Served as two quoted DNS character-strings — the
	// two chunks below reproduce the wire representation.
	itHelpGoogleP1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutPQO7TxVaj58y1IQzHsnCABGG2Vio5MnoDGXrJVwvpArQF2IiB1bu5h3+ZE84VntUoWnnsvODTp24Q8ehFSWjHBybmW9t+87g48HSeC9AOTN77i6e/Sgv3xUhLDTbtRppDjt8Dz/xP1QqLkx3S0+3fHM9p4tc9QWTj1lXoB/eUJzhmS0U55kK0OTN8I0Xw"
	itHelpGoogleP2 = "c/bzC3lF7f14EO56q4ZwPMsQUTRgubswwV3kDP4z3OwqJKZ0cuQg6rfwBYJdvi7GBWRV2Sd+mljLzl0hHS/Z9ExKzgPiAk8ahutXgKpvE5Jo1+tKOt6DUapU8+KTRHnvpG5UgqtyVT6k6FBXdNrtUgQIDAQAB"

	// RFC 8463 §A.2 Ed25519 test vector: the bare 32-byte public key
	// (44 base64 chars), and the same key wrapped as a 44-byte SPKI —
	// some signers publish that form instead.
	ed25519RawP  = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
	ed25519SpkiP = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

// TestDKIMKeyBitsRealCapturedRSA pins key sizing to real published keys.
// The 1024-bit case is the regression guard for the threshold bug: under the
// old buckets it reported 2048/adequate (watched to fail there).
func TestDKIMKeyBitsRealCapturedRSA(t *testing.T) {
	t.Run("cloudflare mandrill 1024-bit is weak", func(t *testing.T) {
		ka := analyzeDKIMKey("v=DKIM1; k=rsa; p=" + mandrillP1 + mandrillP2)
		if got := ka[mapKeyKeyBits]; got != 1024 {
			t.Fatalf("key_bits = %v, want 1024 (162-byte SPKI, openssl-verified)", got)
		}
		if got := ka["key_strength"]; got != "weak" {
			t.Errorf("key_strength = %v, want weak", got)
		}
		issues := ka[mapKeyIssues].([]string)
		found := false
		for _, is := range issues {
			if strings.Contains(is, "1024-bit key (weak") {
				found = true
			}
		}
		if !found {
			t.Errorf("weak-key issue missing for a real 1024-bit key; issues = %v", issues)
		}
	})

	t.Run("it-help.tech google 2048-bit is adequate", func(t *testing.T) {
		// As captured on the wire: two quoted character-strings.
		rec := `"v=DKIM1; k=rsa; p=` + itHelpGoogleP1 + `" "` + itHelpGoogleP2 + `"`
		ka := analyzeDKIMKey(rec)
		if got := ka[mapKeyKeyBits]; got != 2048 {
			t.Fatalf("key_bits = %v, want 2048 (294-byte SPKI, openssl-verified)", got)
		}
		if got := ka["key_strength"]; got != mapKeyAdequate {
			t.Errorf("key_strength = %v, want %s", got, mapKeyAdequate)
		}
		if issues := ka[mapKeyIssues].([]string); len(issues) != 0 {
			t.Errorf("expected no issues for a 2048-bit key, got %v", issues)
		}
	})
}

// TestDKIMKeyBitsEd25519 pins RFC 8463 handling: p= decodes to 32 raw bytes
// (or a 44-byte SPKI), which the old length buckets classified as "1024-bit"
// with a spurious weak-RSA warning. Both forms measure 256-bit/strong, but
// only the raw form is what RFC 8463 §3 specifies — the SPKI wrapper is an
// interop break at strict verifiers and must surface as an issue, never as
// a weak-key warning.
func TestDKIMKeyBitsEd25519(t *testing.T) {
	t.Run("raw-rfc8463", func(t *testing.T) {
		ka := analyzeDKIMKey("v=DKIM1; k=ed25519; p=" + ed25519RawP)
		if got := ka[mapKeyKeyBits]; got != 256 {
			t.Fatalf("key_bits = %v, want 256", got)
		}
		if got := ka["key_strength"]; got != mapKeyStrong {
			t.Errorf("key_strength = %v, want %s", got, mapKeyStrong)
		}
		if issues := ka[mapKeyIssues].([]string); len(issues) != 0 {
			t.Errorf("expected no issues for bare-key Ed25519, got %v", issues)
		}
	})

	t.Run("spki-wrapped", func(t *testing.T) {
		ka := analyzeDKIMKey("v=DKIM1; k=ed25519; p=" + ed25519SpkiP)
		if got := ka[mapKeyKeyBits]; got != 256 {
			t.Fatalf("key_bits = %v, want 256", got)
		}
		if got := ka["key_strength"]; got != mapKeyStrong {
			t.Errorf("key_strength = %v, want %s", got, mapKeyStrong)
		}
		issues := ka[mapKeyIssues].([]string)
		if len(issues) != 1 || !strings.Contains(issues[0], "RFC 8463") {
			t.Fatalf("want exactly one SPKI-wrapping interop issue, got %v", issues)
		}
		if strings.Contains(issues[0], "weak") {
			t.Errorf("SPKI wrapping is an interop break, not key weakness: %v", issues)
		}
	})

	t.Run("malformed ed25519 gets no invented bit count", func(t *testing.T) {
		ka := analyzeDKIMKey("v=DKIM1; k=ed25519; p=AAAA")
		if got := ka[mapKeyKeyBits]; got != nil {
			t.Errorf("key_bits = %v for 3 bytes of non-key material, want nil", got)
		}
		for _, is := range ka[mapKeyIssues].([]string) {
			if strings.Contains(is, "weak") {
				t.Errorf("spurious RSA weak-key issue on ed25519 material: %v", is)
			}
		}
	})
}

// TestBuildDKIMVerdictWeakBelow1024 guards the matcher generalization: exact
// DER parsing can now report sub-1024 sizes, and those must still reach the
// weak-key verdict (the old matcher looked only for the literal "1024-bit").
func TestBuildDKIMVerdictWeakBelow1024(t *testing.T) {
	selectors := map[string]map[string]any{
		"sel._domainkey": {mapKeyProvider: "Custom"},
	}
	status, msg := buildDKIMVerdict(selectors, []string{"768-bit key (weak, upgrade to 2048)"}, nil, "Custom", true, false)
	if status != "warning" {
		t.Fatalf("status = %q for a 768-bit key, want warning (msg %q)", status, msg)
	}
	if !strings.Contains(msg, "weak") {
		t.Errorf("message %q does not name the weak key", msg)
	}
}

// TestPostureDiffSuppressesKeyBitsCorrectionFlip pins the migration
// interaction of the threshold fix: rows scanned before it store key_bits
// 2048/adequate for what is really a 1024-bit key, so the first rescan flips
// the stored DKIM verdict — while the published records are byte-identical.
// The records-identical suppression must keep that flip out of the
// posture-drift banner.
func TestPostureDiffSuppressesKeyBitsCorrectionFlip(t *testing.T) {
	rec := "v=DKIM1; k=rsa; p=" + mandrillP1 + mandrillP2
	prev := dkimResultsFixture("success", map[string][]string{
		"mandrill._domainkey": {rec},
	})
	curr := dkimResultsFixture("warning", map[string][]string{
		"mandrill._domainkey": {rec},
	})
	for _, d := range ComputePostureDiff(prev, curr) {
		if d.Label == "DKIM Status" {
			t.Errorf("key-bits correction produced a drift row for identical records: %+v", d)
		}
	}
}

// TestEstimateKeyBitsRealSizes anchors the fallback buckets to the measured
// SPKI sizes themselves, so the buckets cannot drift away from the DER
// reality they encode.
func TestEstimateKeyBitsRealSizes(t *testing.T) {
	measured := map[int]int{162: 1024, 294: 2048, 422: 3072, 550: 4096, 1062: 8192}
	for size, want := range measured {
		if got := estimateKeyBits(size); got != want {
			t.Errorf("estimateKeyBits(%d) = %d, want %d (measured real SPKI size)", size, got, want)
		}
	}
	if got := estimateKeyBits(140); got != 1024 {
		t.Errorf("estimateKeyBits(140) = %d, want 1024 — truncated material below the smallest real SPKI still lands in the weakest bucket", got)
	}
}
