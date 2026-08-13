// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"fmt"
	"testing"
)

// The captured key from the local dev DB (cloudflare.com mandrill._domainkey,
// domain_analyses rows 19 and 50 — byte-identical across scans). The record is
// long enough that DNS transports split it into 255-byte character-strings;
// different transports rejoin the chunks differently. Every representation
// below is the SAME published RDATA (RFC 6376 §3.6.1: FWS is ignored inside
// base64 tag values; the quotes are DNS character-string framing, never record
// content).
const (
	mandrillP1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrLHiExVd55zd/IQ/J/mRwSRMAocV/hMB3jXwaHH36d9NaVynQFYV8NaWi69c1veUtRzGt7yAioXqLj7Z4TeEUoOLgrKsn8Y"
	mandrillP2 = "nckGs9i3B3tVFB+Ch/4mPhXWiNfNdynHWBcPcbJ8kjEQ2U8y78dHZj1YeRXXVvWob2OaKynO8/lQIDAQAB"
)

func dkimRepresentations() map[string]string {
	clean := "v=DKIM1; k=rsa; p=" + mandrillP1 + mandrillP2
	return map[string]string{
		"clean-joined":    clean,
		"space-joined":    "v=DKIM1; k=rsa; p=" + mandrillP1 + " " + mandrillP2,
		"quoted-chunks":   `"v=DKIM1; k=rsa; p=` + mandrillP1 + `" "` + mandrillP2 + `"`,
		"doh-inner-quote": "v=DKIM1; k=rsa; p=" + mandrillP1 + `" "` + mandrillP2,
		"adjacent-quotes": "v=DKIM1; k=rsa; p=" + mandrillP1 + `""` + mandrillP2,
		"double-space":    "v=DKIM1;  k=rsa;  p=" + mandrillP1 + mandrillP2,
	}
}

// TestCanonicalDKIMRecordCollapsesRepresentations pins the canonical form:
// every transport representation of the same RDATA reduces to one string.
func TestCanonicalDKIMRecordCollapsesRepresentations(t *testing.T) {
	reps := dkimRepresentations()
	want := canonicalDKIMRecord(reps["clean-joined"])
	if want == "" {
		t.Fatal("canonical form of the clean representation is empty")
	}
	for name, rep := range reps {
		if got := canonicalDKIMRecord(rep); got != want {
			t.Errorf("%s: canonical form diverged\n got %q\nwant %q", name, got, want)
		}
	}
	// A genuinely different key must NOT collapse into the same form.
	other := "v=DKIM1; k=rsa; p=" + mandrillP2 + mandrillP1
	if canonicalDKIMRecord(other) == want {
		t.Error("different RDATA collapsed to the same canonical form")
	}
}

// TestAnalyzeDKIMKeyRepresentationInvariant pins the false-positive class from
// Carey's 2026-08-03 walkthrough (defect 2): the SAME key in any transport
// representation must produce the SAME key analysis. Before the fix, the p=
// capture stopped at whitespace/choked on quote framing, so a chunked
// representation yielded different key_bits than the clean join — flipping the
// weak-key verdict, the DKIM status, the posture hash, and finally the drift
// banner, for a key that never changed.
func TestAnalyzeDKIMKeyRepresentationInvariant(t *testing.T) {
	reps := dkimRepresentations()
	ref := analyzeDKIMKey(reps["clean-joined"])
	refBits := ref[mapKeyKeyBits]
	if refBits == nil {
		t.Fatalf("clean representation did not yield key bits: %#v", ref)
	}
	refIssues := fmt.Sprintf("%v", ref[mapKeyIssues])
	for name, rep := range reps {
		ka := analyzeDKIMKey(rep)
		if got := ka[mapKeyKeyBits]; got != refBits {
			t.Errorf("%s: key_bits = %v, clean representation = %v (same key must analyze identically)", name, got, refBits)
		}
		if got := fmt.Sprintf("%v", ka[mapKeyIssues]); got != refIssues {
			t.Errorf("%s: issues = %v, clean representation = %v", name, got, refIssues)
		}
		if rev := ka[mapKeyRevoked]; rev != false {
			t.Errorf("%s: revoked = %v for a key with a non-empty p=", name, rev)
		}
	}
}

// TestAnalyzeDKIMKeyRevokedStillDetected guards the other direction: the
// canonicalization must not make a genuinely revoked key (empty p=, RFC 6376
// §3.6.1) look healthy.
func TestAnalyzeDKIMKeyRevokedStillDetected(t *testing.T) {
	for _, rec := range []string{"v=DKIM1; p=", `"v=DKIM1; p="`, "v=DKIM1;  p=;"} {
		ka := analyzeDKIMKey(rec)
		if ka[mapKeyRevoked] != true {
			t.Errorf("%q: revoked = %v, want true", rec, ka[mapKeyRevoked])
		}
	}
}

func dkimResultsFixture(status string, selectorRecords map[string][]string) map[string]any {
	selectors := map[string]any{}
	for name, recs := range selectorRecords {
		recAny := make([]any, len(recs))
		for i, r := range recs {
			recAny[i] = r
		}
		selectors[name] = map[string]any{"records": recAny}
	}
	return map[string]any{
		mapKeyDkimAnalysis: map[string]any{
			mapKeyStatus: status,
			"selectors":  selectors,
		},
	}
}

// TestPostureDiffSuppressesDKIMStatusWhenRecordsIdentical pins the walkthrough
// false positive end to end: two scans whose canonicalized DKIM record sets are
// identical ("it is the same key") must not produce a "DKIM Status" drift row,
// even when the stored verdicts disagree (representation artifact or parser
// version skew in the earlier row).
func TestPostureDiffSuppressesDKIMStatusWhenRecordsIdentical(t *testing.T) {
	reps := dkimRepresentations()
	prev := dkimResultsFixture("warning", map[string][]string{
		"mandrill._domainkey": {reps["doh-inner-quote"]},
	})
	curr := dkimResultsFixture("success", map[string][]string{
		"mandrill._domainkey": {reps["clean-joined"]},
	})
	for _, d := range ComputePostureDiff(prev, curr) {
		if d.Label == "DKIM Status" {
			t.Errorf("DKIM Status drift reported for identical record sets: %+v", d)
		}
	}
}

// TestPostureDiffKeepsDKIMStatusOnRealChange guards Carey's ruling — "if it's
// real then they should know": a record-set change (key replaced) or a
// disappearance (selector no longer answering) must still surface.
func TestPostureDiffKeepsDKIMStatusOnRealChange(t *testing.T) {
	reps := dkimRepresentations()
	prev := dkimResultsFixture("success", map[string][]string{
		"mandrill._domainkey": {reps["clean-joined"]},
	})

	rotated := dkimResultsFixture("warning", map[string][]string{
		"mandrill._domainkey": {"v=DKIM1; k=rsa; p=" + mandrillP2 + mandrillP1},
	})
	found := false
	for _, d := range ComputePostureDiff(prev, rotated) {
		if d.Label == "DKIM Status" {
			found = true
		}
	}
	if !found {
		t.Error("DKIM Status drift missing for a genuinely rotated key")
	}

	gone := dkimResultsFixture("info", map[string][]string{})
	found = false
	for _, d := range ComputePostureDiff(prev, gone) {
		if d.Label == "DKIM Status" {
			found = true
		}
	}
	if !found {
		t.Error("DKIM Status drift missing when selectors stopped answering (cannot prove the key is unchanged — must surface)")
	}
}
