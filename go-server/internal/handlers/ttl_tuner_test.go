package handlers

import (
        "testing"

        "dnstool/go-server/internal/icuae"
)

func dummyProfile() icuae.ProviderProfile {
        return icuae.ProviderProfile{}
}

func TestCleanDomainInput(t *testing.T) {
        tests := []struct {
                name     string
                input    string
                expected string
        }{
                {"plain domain", "example.com", "example.com"},
                {"http prefix", "http://example.com", "example.com"},
                {"https prefix", "https://example.com", "example.com"},
                {"trailing slash", "example.com/", "example.com"},
                {"https with path", "https://example.com/path/to/page", "example.com"},
                {"http with path and slash", "http://example.com/foo/bar/", "example.com"},
                {"already clean", "sub.example.com", "sub.example.com"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := cleanDomainInput(tc.input)
                        if got != tc.expected {
                                t.Errorf("cleanDomainInput(%q) = %q, want %q", tc.input, got, tc.expected)
                        }
                })
        }
}

func TestFormatHumanTTL(t *testing.T) {
        tests := []struct {
                ttl      uint32
                expected string
        }{
                {86400, "1 day"},
                {172800, "2 days"},
                {3600, "1 hour"},
                {7200, "2 hours"},
                {60, "1 minute"},
                {300, "5 minutes"},
                {30, "30 seconds"},
                {1, "1 seconds"},
                {0, "0 seconds"},
                {3601, "3601 seconds"},
                {90, "90 seconds"},
        }
        for _, tc := range tests {
                t.Run(tc.expected, func(t *testing.T) {
                        got := formatHumanTTL(tc.ttl)
                        if got != tc.expected {
                                t.Errorf("formatHumanTTL(%d) = %q, want %q", tc.ttl, got, tc.expected)
                        }
                })
        }
}

func TestTtlForProfile(t *testing.T) {
        tests := []struct {
                name       string
                recordType string
                profile    string
                expected   uint32
        }{
                {"A stability", "A", "stability", 3600},
                {"A agility", "A", "agility", 300},
                {"NS stability", "NS", "stability", 86400},
                {"NS agility", "NS", "agility", 3600},
                {"MX stability", "MX", "stability", 3600},
                {"MX agility", "MX", "agility", 1800},
                {"CNAME stability", "CNAME", "stability", 3600},
                {"CNAME agility", "CNAME", "agility", 300},
                {"AAAA stability", "AAAA", "stability", 3600},
                {"AAAA agility", "AAAA", "agility", 300},
                {"TXT stability", "TXT", "stability", 3600},
                {"TXT agility", "TXT", "agility", 300},
                {"CAA stability", "CAA", "stability", 3600},
                {"SOA stability", "SOA", "stability", 3600},
                {"unknown stability", "UNKNOWN", "stability", 300},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := ttlForProfile(tc.recordType, tc.profile)
                        if got != tc.expected {
                                t.Errorf("ttlForProfile(%q, %q) = %d, want %d", tc.recordType, tc.profile, got, tc.expected)
                        }
                })
        }
}

func TestFormatTotalReduction(t *testing.T) {
        tests := []struct {
                name     string
                oldQ     float64
                newQ     float64
                expected string
        }{
                {"zero old", 0, 100, ""},
                {"zero new", 100, 0, ""},
                {"both zero", 0, 0, ""},
                {"reduction", 1000, 500, "50% fewer DNS queries per day"},
                {"increase", 500, 1000, "100% more DNS queries per day (for faster propagation)"},
                {"no change", 100, 100, ""},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := formatTotalReduction(tc.oldQ, tc.newQ)
                        if got != tc.expected {
                                t.Errorf("formatTotalReduction(%f, %f) = %q, want %q", tc.oldQ, tc.newQ, got, tc.expected)
                        }
                })
        }
}

func TestHasMigrationRecord(t *testing.T) {
        tests := []struct {
                name     string
                records  []TTLRecordResult
                expected bool
        }{
                {"empty", nil, false},
                {"has A", []TTLRecordResult{{RecordType: "A"}}, true},
                {"has AAAA", []TTLRecordResult{{RecordType: "AAAA"}}, true},
                {"has MX only", []TTLRecordResult{{RecordType: "MX"}}, false},
                {"mixed with A", []TTLRecordResult{{RecordType: "MX"}, {RecordType: "A"}}, true},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := hasMigrationRecord(tc.records)
                        if got != tc.expected {
                                t.Errorf("hasMigrationRecord() = %v, want %v", got, tc.expected)
                        }
                })
        }
}

func TestCalculateQueryReduction(t *testing.T) {
        tests := []struct {
                name     string
                observed uint32
                typical  uint32
                wantNon  bool
        }{
                {"both zero", 0, 0, false},
                {"observed zero", 0, 3600, false},
                {"typical zero", 3600, 0, false},
                {"same values", 3600, 3600, false},
                {"higher observed", 300, 3600, true},
                {"lower observed", 86400, 3600, true},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := calculateQueryReduction(tc.observed, tc.typical)
                        if tc.wantNon && got == "" {
                                t.Errorf("calculateQueryReduction(%d, %d) = empty, want non-empty", tc.observed, tc.typical)
                        }
                        if !tc.wantNon && got != "" {
                                t.Errorf("calculateQueryReduction(%d, %d) = %q, want empty", tc.observed, tc.typical, got)
                        }
                })
        }
}

func TestBuildPropagationNote(t *testing.T) {
        tests := []struct {
                name     string
                rt       string
                observed uint32
                wantNon  bool
        }{
                {"MX record", "MX", 7200, false},
                {"TXT record", "TXT", 7200, false},
                {"A high TTL", "A", 7200, true},
                {"AAAA high TTL", "AAAA", 7200, true},
                {"A low TTL", "A", 300, true},
                {"A mid TTL", "A", 1800, false},
                {"A zero TTL", "A", 0, false},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        got := buildPropagationNote(tc.rt, tc.observed)
                        if tc.wantNon && got == "" {
                                t.Errorf("buildPropagationNote(%q, %d) = empty, want non-empty", tc.rt, tc.observed)
                        }
                        if !tc.wantNon && got != "" {
                                t.Errorf("buildPropagationNote(%q, %d) = %q, want empty", tc.rt, tc.observed, got)
                        }
                })
        }
}

func TestDetermineTunerStatus(t *testing.T) {
        tests := []struct {
                name        string
                observed    uint32
                typical     uint32
                locked      bool
                lockReason  string
                profileName string
                wantStatus  string
                wantClass   string
        }{
                {"locked", 300, 3600, true, "Provider locks this", "stability", "Provider-Locked", "secondary"},
                {"optimal", 3600, 3600, false, "", "stability", "Optimal", "success"},
                {"not set", 0, 3600, false, "", "stability", "Not Set", "warning"},
                {"acceptable ratio", 2400, 3600, false, "", "stability", "Acceptable", "info"},
                {"too high", 86400, 3600, false, "", "stability", "Adjust", "warning"},
                {"too low", 60, 3600, false, "", "stability", "Adjust", "warning"},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        status, class, _ := determineTunerStatus(tc.observed, tc.typical, tc.locked, tc.lockReason, tc.profileName)
                        if status != tc.wantStatus {
                                t.Errorf("status = %q, want %q", status, tc.wantStatus)
                        }
                        if class != tc.wantClass {
                                t.Errorf("class = %q, want %q", class, tc.wantClass)
                        }
                })
        }
}

func TestBuildRoute53JSON(t *testing.T) {
        got := buildRoute53JSON("A", 3600)
        if got == "" {
                t.Error("expected non-empty Route53 JSON")
        }
        if !stringContains(got, `"Type": "A"`) {
                t.Error("expected record type A in JSON")
        }
        if !stringContains(got, `"TTL": 3600`) {
                t.Error("expected TTL 3600 in JSON")
        }
}

func TestCheckProviderLock(t *testing.T) {
        tests := []struct {
                name         string
                rt           string
                observed     uint32
                providerName string
                hasProvider  bool
                wantLocked   bool
        }{
                {"no provider", "A", 300, "", false, false},
                {"non-matching provider", "A", 300, "SomeProvider", true, false},
                {"MX cloudflare", "MX", 300, "Cloudflare", true, false},
        }
        for _, tc := range tests {
                t.Run(tc.name, func(t *testing.T) {
                        locked, _ := checkProviderLock(tc.rt, tc.observed, tc.providerName, dummyProfile(), tc.hasProvider)
                        if locked != tc.wantLocked {
                                t.Errorf("locked = %v, want %v", locked, tc.wantLocked)
                        }
                })
        }
}

func TestBuildTunerRecord(t *testing.T) {
        rec := buildTunerRecord("A", 300, 3600, "", dummyProfile(), false, "stability")
        if rec.RecordType != "A" {
                t.Errorf("RecordType = %q, want A", rec.RecordType)
        }
        if rec.ObservedTTL != 300 {
                t.Errorf("ObservedTTL = %d, want 300", rec.ObservedTTL)
        }
        if rec.TypicalTTL != 3600 {
                t.Errorf("TypicalTTL = %d, want 3600", rec.TypicalTTL)
        }
        if rec.CloudflareUI == "" {
                t.Error("expected non-empty CloudflareUI")
        }
        if rec.BINDSnippet == "" {
                t.Error("expected non-empty BINDSnippet")
        }
        if rec.GenericStep == "" {
                t.Error("expected non-empty GenericStep")
        }
}

func TestTunerRecordOrder(t *testing.T) {
        if tunerRecordOrder["A"] >= tunerRecordOrder["AAAA"] {
                t.Error("A should come before AAAA in order")
        }
        if tunerRecordOrder["AAAA"] >= tunerRecordOrder["CNAME"] {
                t.Error("AAAA should come before CNAME in order")
        }
}

func stringContains(s, substr string) bool {
        for i := 0; i <= len(s)-len(substr); i++ {
                if s[i:i+len(substr)] == substr {
                        return true
                }
        }
        return false
}
