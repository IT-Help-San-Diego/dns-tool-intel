package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestParseTLSA exercises the "usage selector matching-type association-data"
// parser across valid and malformed inputs (RFC 6698 §2.1.1). It parses
// structurally — out-of-range usage/selector/matching-type values are NOT
// malformed; they are flagged with a specific reason downstream in verifyTLSA.
func TestParseTLSA(t *testing.T) {
	valid := []struct {
		line     string
		usage    int
		selector int
		matching int
	}{
		{"3 1 1 deadbeef", 3, 1, 1},
		{"2 0 2 DEADBEEF", 2, 0, 2},
		{"0 1 0 00", 0, 1, 0},
	}
	for _, tc := range valid {
		rec, ok := parseTLSA(tc.line)
		if !ok {
			t.Errorf("parseTLSA(%q) = !ok, want ok", tc.line)
			continue
		}
		if rec.usage != tc.usage || rec.selector != tc.selector || rec.matchingType != tc.matching {
			t.Errorf("parseTLSA(%q) = (%d,%d,%d), want (%d,%d,%d)",
				tc.line, rec.usage, rec.selector, rec.matchingType, tc.usage, tc.selector, tc.matching)
		}
	}
	malformed := []string{
		"",
		"3 1",
		"3 1 1",
		"x 1 1 deadbeef",
		"-1 1 1 deadbeef", // negative usage is nonsensical
		"not a tlsa record at all",
	}
	for _, line := range malformed {
		if _, ok := parseTLSA(line); ok {
			t.Errorf("parseTLSA(%q) = ok, want !ok", line)
		}
	}
}

// TestDigestAssociation uses known-answer vectors: SHA-256 and SHA-512 of the
// empty byte string, plus the full (no-hash) form of a known input.
func TestDigestAssociation(t *testing.T) {
	sha256Empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sha512Empty := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if got := digestAssociation([]byte{}, 1); got != sha256Empty {
		t.Errorf("digestAssociation(empty, SHA-256) = %q, want %q", got, sha256Empty)
	}
	if got := digestAssociation([]byte{}, 2); got != sha512Empty {
		t.Errorf("digestAssociation(empty, SHA-512) = %q, want %q", got, sha512Empty)
	}
	if got := digestAssociation([]byte{0x01, 0x02, 0xff}, 0); got != "0102ff" {
		t.Errorf("digestAssociation(full) = %q, want 0102ff", got)
	}
}

// TestVerifyTLSA proves the RFC 7671 §5 matching logic without any hashing in
// the test itself (matching type 0 = full association data, direct compare),
// so the routing (usage/selector) is what is under test. It also proves the
// usable-count contract: PKIX/malformed/unsupported records, and an empty
// chain or leaf, are never counted as usable — so nothing that was never
// actually compared can read as a "mismatch".
func TestVerifyTLSA(t *testing.T) {
	leafDER := "deadbeef"
	leafSPKI := "cafebabe"
	chainDER := []string{"00", "11", leafDER}
	chainSPKI := []string{"22", "33", leafSPKI}

	// usage 3 (DANE-EE), selector 0 (full cert), matching 0 (full) -> matches leaf.
	if ok, _, _ := verifyTLSA([]string{"3 0 0 deadbeef"}, leafDER, leafSPKI, chainDER, chainSPKI); !ok {
		t.Errorf("verifyTLSA(DANE-EE selector-0 exact match) = false, want true")
	}

	// usage 3, selector 1 (SPKI), matching 0 -> matches leaf SPKI.
	if ok, _, _ := verifyTLSA([]string{"3 1 0 cafebabe"}, leafDER, leafSPKI, chainDER, chainSPKI); !ok {
		t.Errorf("verifyTLSA(DANE-EE selector-1 exact match) = false, want true")
	}

	// Wrong association data -> usable non-match.
	ok, usable, _ := verifyTLSA([]string{"3 0 0 deadb00f"}, leafDER, leafSPKI, chainDER, chainSPKI)
	if ok || usable != 1 {
		t.Errorf("verifyTLSA(wrong data) = (ok=%v, usable=%d), want (false, 1)", ok, usable)
	}

	// usage 2 (DANE-TA) matches a trust anchor deeper in the presented chain.
	if ok, _, _ := verifyTLSA([]string{"2 0 0 11"}, leafDER, leafSPKI, chainDER, chainSPKI); !ok {
		t.Errorf("verifyTLSA(DANE-TA chain match) = false, want true")
	}

	// usage 1 (PKIX-EE) -> not comparable, must NOT count as a match or usable.
	ok, usable, breakdown := verifyTLSA([]string{"1 0 0 deadbeef"}, leafDER, leafSPKI, chainDER, chainSPKI)
	if ok || usable != 0 {
		t.Errorf("verifyTLSA(PKIX usage) = (ok=%v, usable=%d), want (false, 0)", ok, usable)
	}
	if len(breakdown) != 1 || breakdown[0]["matched"] != false || !strings.Contains(breakdown[0]["reason"].(string), "PKIX") {
		t.Errorf("verifyTLSA(PKIX usage) breakdown = %v, want PKIX not-verifiable reason", breakdown)
	}

	// usage 2 (DANE-TA) with NO presented chain -> not comparable, not usable.
	ok, usable, breakdown = verifyTLSA([]string{"2 0 0 11"}, leafDER, leafSPKI, nil, nil)
	if ok || usable != 0 {
		t.Errorf("verifyTLSA(DANE-TA empty chain) = (ok=%v, usable=%d), want (false, 0)", ok, usable)
	}
	if len(breakdown) != 1 || !strings.Contains(breakdown[0]["reason"].(string), "no chain presented") {
		t.Errorf("verifyTLSA(DANE-TA empty chain) breakdown = %v, want no-chain reason", breakdown)
	}

	// usage 3 (DANE-EE) with NO leaf presented -> not comparable, not usable.
	ok, usable, breakdown = verifyTLSA([]string{"3 0 0 deadbeef"}, "", "", chainDER, chainSPKI)
	if ok || usable != 0 {
		t.Errorf("verifyTLSA(DANE-EE empty leaf) = (ok=%v, usable=%d), want (false, 0)", ok, usable)
	}
	if len(breakdown) != 1 || !strings.Contains(breakdown[0]["reason"].(string), "could not decode leaf") {
		t.Errorf("verifyTLSA(DANE-EE empty leaf) breakdown = %v, want decode-failure reason", breakdown)
	}

	// Out-of-range fields are flagged with a specific reason, not "malformed",
	// and are never counted as usable.
	for _, tc := range []struct{ line, want string }{
		{"4 1 1 deadbeef", "unsupported usage"},
		{"3 9 1 deadbeef", "unsupported selector"},
		{"3 1 9 deadbeef", "unsupported matching type"},
	} {
		ok, usable, breakdown := verifyTLSA([]string{tc.line}, leafDER, leafSPKI, chainDER, chainSPKI)
		if ok || usable != 0 {
			t.Errorf("verifyTLSA(%q) = (ok=%v, usable=%d), want (false, 0)", tc.line, ok, usable)
		}
		if len(breakdown) != 1 || !strings.Contains(breakdown[0]["reason"].(string), tc.want) {
			t.Errorf("verifyTLSA(%q) breakdown = %v, want reason containing %q", tc.line, breakdown, tc.want)
		}
	}

	// Malformed record -> reported, not matched, not usable.
	ok, usable, breakdown = verifyTLSA([]string{"garbage"}, leafDER, leafSPKI, chainDER, chainSPKI)
	if ok || usable != 0 {
		t.Errorf("verifyTLSA(malformed) = (ok=%v, usable=%d), want (false, 0)", ok, usable)
	}
	if len(breakdown) != 1 || !strings.Contains(breakdown[0]["reason"].(string), "malformed") {
		t.Errorf("verifyTLSA(malformed) breakdown = %v, want malformed reason", breakdown)
	}
}

// TestDaneVerdictStatus pins the three-status verdict derivation — the layer
// where the flatten bug lived — including that "not_verifiable" carries the
// specific reason (which next action the reader takes depends on it).
func TestDaneVerdictStatus(t *testing.T) {
	pkix := "PKIX-based usage requires full PKIX validation, not performed by this probe (RFC 6698 §2.1.1)"
	tests := []struct {
		name    string
		matched bool
		usable  int
		reason  string
		want    string
		wantMsg string
	}{
		{"any match -> verified", true, 3, "", "verified", ""},
		{"usable non-match -> mismatch", false, 1, "", "mismatch", "TLSA record(s) do not match the presented certificate"},
		{"zero usable, PKIX reason -> not_verifiable w/ reason", false, 0, pkix, "not_verifiable", pkix},
		{"zero usable, empty reason -> generic", false, 0, "", "not_verifiable", "no usable TLSA record to verify against"},
	}
	for _, tc := range tests {
		got, msg := daneVerdictStatus(tc.matched, tc.usable, tc.reason)
		if got != tc.want {
			t.Errorf("daneVerdictStatus(%v,%d,%q) = %q, want %q", tc.matched, tc.usable, tc.reason, got, tc.want)
		}
		if msg != tc.wantMsg {
			t.Errorf("daneVerdictStatus(%v,%d,%q) message = %q, want %q", tc.matched, tc.usable, tc.reason, msg, tc.wantMsg)
		}
	}
}

// TestSummarizeUnusable pins the reason-collapsing rule: a uniform reason is
// reported verbatim; mixed reasons fall back to the generic summary.
func TestSummarizeUnusable(t *testing.T) {
	uniform := []map[string]any{{"reason": "malformed TLSA record"}, {"reason": "malformed TLSA record"}}
	if got := summarizeUnusable(uniform); got != "malformed TLSA record" {
		t.Errorf("summarizeUnusable(uniform) = %q, want the single reason", got)
	}
	mixed := []map[string]any{{"reason": "malformed TLSA record"}, {"reason": "unsupported matching type"}}
	if got := summarizeUnusable(mixed); got != "no usable TLSA record to verify against" {
		t.Errorf("summarizeUnusable(mixed) = %q, want generic", got)
	}
	if got := summarizeUnusable(nil); got != "no usable TLSA record to verify against" {
		t.Errorf("summarizeUnusable(empty) = %q, want generic", got)
	}
}

// TestParseTLSAWrappedData pins the fix for the truncation bug: `dig +short
// TLSA` wraps association data into 56-hex chunks separated by spaces, so a
// SHA-256 association (64 hex) arrives as two fields. The parser must join
// fields[3:] or every real DANE record truncates and reports a false mismatch.
func TestParseTLSAWrappedData(t *testing.T) {
	chunk1 := strings.Repeat("a", 56)
	chunk2 := "12345678" // 8 hex -> 64 total
	rec, ok := parseTLSA("3 1 1 " + chunk1 + " " + chunk2)
	if !ok {
		t.Fatalf("parseTLSA(wrapped) = !ok, want ok")
	}
	want := chunk1 + chunk2
	if rec.data != want {
		t.Errorf("parseTLSA(wrapped).data = %q, want %q (joined 56+8 chunks)", rec.data, want)
	}
	if len(rec.data) != 64 {
		t.Errorf("parseTLSA(wrapped).data length = %d, want 64", len(rec.data))
	}
}

// TestVerifyTLSAWrappedSHA256 proves the end-to-end path a wrapped record
// takes: parseTLSA joins the chunks, matchLeaf hashes the SPKI, and the SHA-256
// digest matches. This is the exact case the truncation bug turned into a
// false "mismatch" on correctly-configured DANE domains.
func TestVerifyTLSAWrappedSHA256(t *testing.T) {
	spki := []byte("example-spki-material")
	digest := sha256.Sum256(spki)
	digestHex := hex.EncodeToString(digest[:]) // 64 hex chars
	record := "3 1 1 " + digestHex[:56] + " " + digestHex[56:]
	leafDER := "deadbeef"
	leafSPKI := hex.EncodeToString(spki)

	ok, usable, _ := verifyTLSA([]string{record}, leafDER, leafSPKI, nil, nil)
	if !ok || usable != 1 {
		t.Errorf("verifyTLSA(wrapped SHA-256) = (ok=%v, usable=%d), want (true, 1)", ok, usable)
	}
}
