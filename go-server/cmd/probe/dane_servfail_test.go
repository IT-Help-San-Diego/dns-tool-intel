package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeDig writes an executable "dig" shim into dir that emits stdout and
// exits 0 — a stand-in for the real binary so the handler's dig invocation can
// be driven without network. The heredoc form keeps the header comment verbatim.
func writeFakeDig(t *testing.T, dir, stdout string) {
	t.Helper()
	script := "#!/bin/sh\ncat <<'DIGEOF'\n" + stdout + "\nDIGEOF\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "dig"), []byte(script), 0o755); err != nil {
		t.Fatalf("writeFakeDig: %v", err)
	}
}

// TestParseDigTLSA pins the rcode extraction: the status comment is the only
// thing separating "no records" (NOERROR) from "could not measure" (SERVFAIL).
func TestParseDigTLSA(t *testing.T) {
	// NOERROR with a TLSA answer -> rcode NOERROR, one record with full RDATA.
	rcode, records := parseDigTLSA(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n_25._tcp.mx.example.com. 3600 IN TLSA 3 1 1 deadbeef")
	if rcode != "NOERROR" {
		t.Errorf("NOERROR rcode = %q, want NOERROR", rcode)
	}
	if len(records) != 1 || records[0] != "3 1 1 deadbeef" {
		t.Errorf("records = %v, want [3 1 1 deadbeef]", records)
	}

	// SERVFAIL with no answer -> rcode SERVFAIL, zero records.
	rcode, records = parseDigTLSA(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 2")
	if rcode != "SERVFAIL" {
		t.Errorf("SERVFAIL rcode = %q, want SERVFAIL", rcode)
	}
	if len(records) != 0 {
		t.Errorf("SERVFAIL records = %v, want empty", records)
	}
}

// TestHandleDANEVerifySERVFAILIsError is the mutation guard for the SERVFAIL
// hole: a DNSSEC-bogus zone makes `dig +short` exit 0 with empty stdout, which
// the old code read as measured absence ("no_tlsa"). A SERVFAIL header must
// instead report "error" — could not measure, not evidence of absence.
func TestHandleDANEVerifySERVFAILIsError(t *testing.T) {
	dir := t.TempDir()
	writeFakeDig(t, dir, ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 12345")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	req := httptest.NewRequest(http.MethodPost, "/probe/dane-verify", strings.NewReader(`{"host":"mx.example","port":25}`))
	rec := httptest.NewRecorder()
	handleDANEVerify(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "error" {
		t.Errorf("SERVFAIL status = %v, want error (could not measure, never no_tlsa)", resp["status"])
	}
}

// TestHandleDANEVerifyNoErrorEmptyIsNoTLSA is the honest-absence control: an
// authoritative NOERROR with zero records IS measured absence and may report
// no_tlsa.
func TestHandleDANEVerifyNoErrorEmptyIsNoTLSA(t *testing.T) {
	dir := t.TempDir()
	writeFakeDig(t, dir, ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	req := httptest.NewRequest(http.MethodPost, "/probe/dane-verify", strings.NewReader(`{"host":"mx.example","port":25}`))
	rec := httptest.NewRecorder()
	handleDANEVerify(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "no_tlsa" {
		t.Errorf("NOERROR-empty status = %v, want no_tlsa", resp["status"])
	}
}

// TestHandleDANEVerifyHeaderlessDigIsError pins the positive-observation rule
// (Science's finding on #407): "no_tlsa" is a measured-absence claim and
// requires actually seeing status NOERROR. A dig reply with no parseable
// header comment — empty output, or an answer with the comments missing —
// must land on "error": the instrument's own state is unknown, so neither an
// absence claim nor a verification is licensed.
func TestHandleDANEVerifyHeaderlessDigIsError(t *testing.T) {
	cases := map[string]string{
		"empty output":     "",
		"answer-only line": "_25._tcp.mx.example. 3600 IN TLSA 3 1 1 deadbeef",
	}
	for name, stdout := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFakeDig(t, dir, stdout)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

			req := httptest.NewRequest(http.MethodPost, "/probe/dane-verify", strings.NewReader(`{"host":"mx.example","port":25}`))
			rec := httptest.NewRecorder()
			handleDANEVerify(rec, req)

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s: bad JSON: %v", name, err)
			}
			if resp["status"] != "error" {
				t.Errorf("%s: status = %v, want error (absence requires observing NOERROR)", name, resp["status"])
			}
		})
	}
}
