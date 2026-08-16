package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDaneVerificationOverall(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		want   string
	}{
		{"mismatch outranks verified", map[string]int{"verified": 1, "mismatch": 2}, "mismatch"},
		{"mismatch beats not_verifiable", map[string]int{"mismatch": 1, "not_verifiable": 1}, "mismatch"},
		{"verified beats not_verifiable", map[string]int{"verified": 1, "not_verifiable": 1}, "verified"},
		{"not_verifiable beats cert_error", map[string]int{"not_verifiable": 1, "cert_error": 1}, "not_verifiable"},
		{"cert_error beats no_tlsa", map[string]int{"cert_error": 1, "no_tlsa": 1}, "cert_error"},
		{"cert_error beats error", map[string]int{"cert_error": 1, "error": 1}, "cert_error"},
		{"error beats no_tlsa (unmeasured host blocks an absence claim)", map[string]int{"error": 1, "no_tlsa": 1}, "error"},
		{"error beats unreachable", map[string]int{"error": 1, "unreachable": 1}, "error"},
		{"no_tlsa beats unreachable", map[string]int{"no_tlsa": 1, "unreachable": 1}, "no_tlsa"},
		{"error (couldn't measure)", map[string]int{"error": 2}, "error"},
		{"no_tlsa", map[string]int{"no_tlsa": 2}, "no_tlsa"},
		{"empty -> unreachable", map[string]int{}, "unreachable"},
	}
	for _, tc := range tests {
		if got := daneVerificationOverall(tc.counts); got != tc.want {
			t.Errorf("daneVerificationOverall(%v) = %q, want %q", tc.counts, got, tc.want)
		}
	}
}

// TestVerifyDANEHosts drives the analyzer-side wiring against a mock probe:
// one host verified, one mismatch (a real measurement, not a transport
// failure), one probe-side dig failure (status "error"), one transport
// failure. The aggregate must report the measured mismatch as the worst
// honest state, count every couldn't-measure flavor in its own named bucket,
// and never conflate any of them with a measured absence.
func TestVerifyDANEHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch body.Host {
		case "verified.example":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "verified", "host": body.Host})
		case "mismatch.example":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "mismatch",
				"message":    "TLSA record(s) do not match the presented certificate",
				"tlsa_match": []any{map[string]any{"matched": false, "reason": "digest mismatch with leaf certificate"}},
			})
		case "digerr.example":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "TLSA lookup failed — could not measure (dig transport error), not evidence of absence",
			})
		case "gone.example":
			w.WriteHeader(http.StatusBadGateway)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "not_verifiable"})
		}
	}))
	defer srv.Close()

	a := &Analyzer{Probes: []ProbeEndpoint{{URL: srv.URL}}}
	ver := verifyDANEHosts(context.Background(), a, []string{"verified.example", "mismatch.example", "digerr.example", "gone.example"})
	if ver == nil {
		t.Fatal("verifyDANEHosts returned nil, want aggregate")
	}
	if ver["status"] != "mismatch" {
		t.Errorf("overall status = %v, want mismatch (a measured mismatch outranks a sibling verified)", ver["status"])
	}
	if ver["verified"] != 1 || ver["mismatch"] != 1 || ver["error"] != 1 || ver["unreachable"] != 1 {
		t.Errorf("counts = verified:%v mismatch:%v error:%v unreachable:%v, want 1/1/1/1",
			ver["verified"], ver["mismatch"], ver["error"], ver["unreachable"])
	}
	// Every attempted host lands in exactly one named bucket: the seven counts
	// must sum to checked, or a status has silently dropped out of the
	// aggregate's contract (the v1 "error" hole).
	sum := 0
	for _, k := range []string{"verified", "mismatch", "not_verifiable", "cert_error", "error", "no_tlsa", "unreachable"} {
		n, _ := ver[k].(int)
		sum += n
	}
	if checked, _ := ver["checked"].(int); sum != checked {
		t.Errorf("named counts sum to %d, want checked=%d — a status is missing from the aggregate contract", sum, checked)
	}
	if perHost, ok := ver["per_host"].([]map[string]any); !ok || len(perHost) != 4 {
		t.Errorf("per_host = %v, want 4 entries", ver["per_host"])
	}
}

// TestVerifyDANEHostsNoProbe pins the honest no-op: with no configured probe,
// the verification is nil and AnalyzeDANE must not fabricate a verification.
func TestVerifyDANEHostsNoProbe(t *testing.T) {
	a := &Analyzer{Probes: nil}
	if ver := verifyDANEHosts(context.Background(), a, []string{"mx.example"}); ver != nil {
		t.Errorf("verifyDANEHosts(no probe) = %v, want nil", ver)
	}
}
