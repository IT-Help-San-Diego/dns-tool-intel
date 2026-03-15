package analyzer

import (
	"testing"
)

func TestLookupPhaseGroup(t *testing.T) {
	tests := []struct {
		task     string
		expected string
	}{
		{"basic", "dns_records"},
		{"auth", "dns_records"},
		{"resolver_consensus", "dns_records"},
		{"spf", "email_auth"},
		{"dmarc", "email_auth"},
		{"dkim", "email_auth"},
		{"dnssec", "dnssec_dane"},
		{"cds_cdnskey", "dnssec_dane"},
		{"dnssec_ops", "dnssec_dane"},
		{"dane", "dnssec_dane"},
		{"ct_subdomains", "ct_subdomains"},
		{"security_txt", "ct_subdomains"},
		{"ai_surface", "ct_subdomains"},
		{"secret_exposure", "ct_subdomains"},
		{"smtp_transport", "smtp_transport"},
		{"nmap_dns", "smtp_transport"},
		{"smimea_openpgpkey", "smtp_transport"},
		{"mta_sts", "policy_records"},
		{"tlsrpt", "policy_records"},
		{"bimi", "policy_records"},
		{"caa", "policy_records"},
		{"registrar", "registrar_infra"},
		{"ns_delegation", "registrar_infra"},
		{"ns_fleet", "registrar_infra"},
		{"delegation_consistency", "registrar_infra"},
		{"https_svcb", "registrar_infra"},
		{"posture", "analysis_engine"},
		{"hosting", "analysis_engine"},
		{"unknown_task", "analysis_engine"},
	}

	for _, tt := range tests {
		t.Run(tt.task, func(t *testing.T) {
			got := LookupPhaseGroup(tt.task)
			if got != tt.expected {
				t.Errorf("LookupPhaseGroup(%q) = %q, want %q", tt.task, got, tt.expected)
			}
		})
	}
}

func TestComputeTelemetryHash(t *testing.T) {
	timings := []PhaseTiming{
		{PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 500},
		{PhaseGroup: "email_auth", PhaseTask: "spf", StartedAtMs: 0, DurationMs: 800},
	}

	hash1 := ComputeTelemetryHash(timings)
	if len(hash1) != 128 {
		t.Errorf("expected 128-char hex hash, got %d chars", len(hash1))
	}

	hash2 := ComputeTelemetryHash(timings)
	if hash1 != hash2 {
		t.Error("identical inputs must produce identical hashes")
	}

	reversed := []PhaseTiming{timings[1], timings[0]}
	hash3 := ComputeTelemetryHash(reversed)
	if hash1 != hash3 {
		t.Error("hash must be order-independent (canonical sorting)")
	}

	different := []PhaseTiming{
		{PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 999},
		{PhaseGroup: "email_auth", PhaseTask: "spf", StartedAtMs: 0, DurationMs: 800},
	}
	hash4 := ComputeTelemetryHash(different)
	if hash1 == hash4 {
		t.Error("different inputs must produce different hashes")
	}
}

func TestNewScanTelemetry(t *testing.T) {
	timings := []PhaseTiming{
		{PhaseGroup: "dns_records", PhaseTask: "basic", StartedAtMs: 0, DurationMs: 500},
	}
	tel := NewScanTelemetry(timings, 500)
	if tel.TotalDurationMs != 500 {
		t.Errorf("TotalDurationMs = %d, want 500", tel.TotalDurationMs)
	}
	if tel.SHA3Hash == "" {
		t.Error("SHA3Hash must not be empty")
	}
	if len(tel.Timings) != 1 {
		t.Errorf("expected 1 timing, got %d", len(tel.Timings))
	}
}
