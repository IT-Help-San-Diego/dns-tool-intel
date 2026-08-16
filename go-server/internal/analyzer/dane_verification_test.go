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
		{"any verified wins", map[string]int{"verified": 1, "mismatch": 2}, "verified"},
		{"mismatch beats not_verifiable", map[string]int{"mismatch": 1, "not_verifiable": 1}, "mismatch"},
		{"not_verifiable beats cert_error", map[string]int{"not_verifiable": 1, "cert_error": 1}, "not_verifiable"},
		{"cert_error beats no_tlsa", map[string]int{"cert_error": 1, "no_tlsa": 1}, "cert_error"},
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
// failure), one transport failure. The aggregate must report verified as the
// strongest signal, with the transport failure counted separately and never
// conflated with a measured absence.
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
		case "gone.example":
			w.WriteHeader(http.StatusBadGateway)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "not_verifiable"})
		}
	}))
	defer srv.Close()

	a := &Analyzer{Probes: []ProbeEndpoint{{URL: srv.URL}}}
	ver := verifyDANEHosts(context.Background(), a, []string{"verified.example", "mismatch.example", "gone.example"})
	if ver == nil {
		t.Fatal("verifyDANEHosts returned nil, want aggregate")
	}
	if ver["status"] != "verified" {
		t.Errorf("overall status = %v, want verified", ver["status"])
	}
	if ver["verified"] != 1 || ver["mismatch"] != 1 || ver["unreachable"] != 1 {
		t.Errorf("counts = verified:%v mismatch:%v unreachable:%v, want 1/1/1",
			ver["verified"], ver["mismatch"], ver["unreachable"])
	}
	if perHost, ok := ver["per_host"].([]map[string]any); !ok || len(perHost) != 3 {
		t.Errorf("per_host = %v, want 3 entries", ver["per_host"])
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
