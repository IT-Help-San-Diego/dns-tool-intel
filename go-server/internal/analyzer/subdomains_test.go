package analyzer

import (
        "testing"
        "time"
)

func TestNormalizeCTName(t *testing.T) {
        tests := []struct {
                name   string
                input  string
                domain string
                want   string
        }{
                {"valid subdomain", "www.example.com", "example.com", "www.example.com"},
                {"uppercase", "WWW.EXAMPLE.COM", "example.com", "www.example.com"},
                {"wildcard prefix", "*.example.com", "example.com", ""},
                {"wildcard sub", "*.sub.example.com", "example.com", "sub.example.com"},
                {"empty", "", "example.com", ""},
                {"domain itself", "example.com", "example.com", ""},
                {"different domain", "other.net", "example.com", ""},
                {"whitespace", "  www.example.com  ", "example.com", "www.example.com"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := normalizeCTName(tt.input, tt.domain)
                        if got != tt.want {
                                t.Errorf("normalizeCTName(%q, %q) = %q, want %q", tt.input, tt.domain, got, tt.want)
                        }
                })
        }
}

func TestSimplifyIssuer(t *testing.T) {
        tests := []struct {
                name  string
                input string
                want  string
        }{
                {"org field", "CN=R3, O=Let's Encrypt, C=US", "Let's Encrypt"},
                {"cn only", "CN=DigiCert", "DigiCert"},
                {"empty", "", ""},
                {"long issuer", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA..."},
                {"org with quotes", `CN=Test, O="Acme, Inc.", C=US`, "Acme, Inc."},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := simplifyIssuer(tt.input)
                        if got != tt.want {
                                t.Errorf("simplifyIssuer(%q) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestParseDNAttributes(t *testing.T) {
        tests := []struct {
                name  string
                input string
                want  int
        }{
                {"simple", "CN=Test, O=Org", 2},
                {"single", "CN=Test", 1},
                {"empty", "", 0},
                {"quoted comma", `CN=Test, O="Org, Inc."`, 2},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := parseDNAttributes(tt.input)
                        if len(got) != tt.want {
                                t.Errorf("parseDNAttributes(%q) returned %d parts, want %d", tt.input, len(got), tt.want)
                        }
                })
        }
}

func TestAtoi(t *testing.T) {
        tests := []struct {
                input string
                want  int
        }{
                {"0", 0},
                {"1", 1},
                {"123", 123},
                {"abc", 0},
                {"12abc", 12},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := atoi(tt.input); got != tt.want {
                                t.Errorf("atoi(%q) = %d, want %d", tt.input, got, tt.want)
                        }
                })
        }
}

func TestItoa(t *testing.T) {
        tests := []struct {
                input int
                want  string
        }{
                {0, "0"},
                {1, "1"},
                {42, "42"},
                {100, "100"},
        }
        for _, tt := range tests {
                t.Run(tt.want, func(t *testing.T) {
                        if got := itoa(tt.input); got != tt.want {
                                t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestParseCertDate(t *testing.T) {
        tests := []struct {
                name    string
                input   string
                wantZer bool
        }{
                {"iso date", "2024-01-15", false},
                {"datetime", "2024-01-15T12:00:00", false},
                {"datetime space", "2024-01-15 12:00:00", false},
                {"empty", "", true},
                {"invalid", "not-a-date", true},
                {"whitespace", "  2024-01-15  ", false},
                {"long with extra", "2024-01-15T12:00:00.000Z", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := parseCertDate(tt.input)
                        if tt.wantZer && !got.IsZero() {
                                t.Errorf("parseCertDate(%q) should be zero", tt.input)
                        }
                        if !tt.wantZer && got.IsZero() {
                                t.Errorf("parseCertDate(%q) should not be zero", tt.input)
                        }
                })
        }
}

func TestContainsString(t *testing.T) {
        tests := []struct {
                name   string
                ss     []string
                target string
                want   bool
        }{
                {"found", []string{"a", "b", "c"}, "b", true},
                {"not found", []string{"a", "b", "c"}, "d", false},
                {"empty slice", []string{}, "a", false},
                {"nil slice", nil, "a", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := containsString(tt.ss, tt.target); got != tt.want {
                                t.Errorf("containsString(%v, %q) = %v, want %v", tt.ss, tt.target, got, tt.want)
                        }
                })
        }
}

func TestDeduplicateCTEntries(t *testing.T) {
        entries := []ctEntry{
                {SerialNumber: "abc", NameValue: "a.example.com"},
                {SerialNumber: "abc", NameValue: "a.example.com"},
                {SerialNumber: "def", NameValue: "b.example.com"},
                {SerialNumber: "", NameValue: "c.example.com"},
                {SerialNumber: "", NameValue: "d.example.com"},
        }
        got := deduplicateCTEntries(entries)
        if len(got) != 4 {
                t.Errorf("deduplicateCTEntries returned %d entries, want 4", len(got))
        }
}

func TestCountSubdomainStats(t *testing.T) {
        subdomains := []map[string]any{
                {mapKeyIsCurrent: true},
                {mapKeyIsCurrent: false},
                {mapKeyIsCurrent: true},
                {"other": "value"},
        }
        current, expired := countSubdomainStats(subdomains)
        if current != 2 {
                t.Errorf("current = %d, want 2", current)
        }
        if expired != 2 {
                t.Errorf("expired = %d, want 2", expired)
        }
}

func TestCollectSubdomains(t *testing.T) {
        set := map[string]map[string]any{
                "a.example.com": {mapKeyName: "a.example.com", mapKeyCnameTarget: "cdn.example.com"},
                "b.example.com": {mapKeyName: "b.example.com"},
        }
        subs, cnameCount := collectSubdomains(set)
        if len(subs) != 2 {
                t.Errorf("got %d subdomains, want 2", len(subs))
        }
        if cnameCount != 1 {
                t.Errorf("cnameCount = %d, want 1", cnameCount)
        }
}

func TestSortSubdomainsSmartOrder(t *testing.T) {
        subdomains := []map[string]any{
                {mapKeyName: "z.example.com", mapKeyIsCurrent: true},
                {mapKeyName: "a.example.com", mapKeyIsCurrent: true},
                {mapKeyName: "old.example.com", mapKeyIsCurrent: false, mapKeyFirstSeen: "2023-01-01"},
                {mapKeyName: "older.example.com", mapKeyIsCurrent: false, mapKeyFirstSeen: "2022-01-01"},
        }
        sorted := sortSubdomainsSmartOrder(subdomains)
        if len(sorted) != 4 {
                t.Fatalf("got %d, want 4", len(sorted))
        }
        if sorted[0][mapKeyName] != "a.example.com" {
                t.Errorf("first current should be a.example.com, got %v", sorted[0][mapKeyName])
        }
        if sorted[1][mapKeyName] != "z.example.com" {
                t.Errorf("second current should be z.example.com, got %v", sorted[1][mapKeyName])
        }
        if sorted[2][mapKeyName] != "old.example.com" {
                t.Errorf("historical should be sorted descending by first_seen")
        }
}

func TestApplySubdomainDisplayCap(t *testing.T) {
        t.Run("under cap", func(t *testing.T) {
                result := map[string]any{}
                subs := make([]map[string]any, 50)
                applySubdomainDisplayCap(result, subs, 30)
                if result[mapKeyDisplayedCount] != 50 {
                        t.Errorf("displayed_count = %v, want 50", result[mapKeyDisplayedCount])
                }
        })

        t.Run("over cap with low current", func(t *testing.T) {
                result := map[string]any{}
                subs := make([]map[string]any, 300)
                applySubdomainDisplayCap(result, subs, 50)
                if result[mapKeyDisplayedCount] != 200 {
                        t.Errorf("displayed_count = %v, want 200", result[mapKeyDisplayedCount])
                }
                if result["display_capped"] != true {
                        t.Error("expected display_capped to be true")
                }
        })

        t.Run("over cap with high current", func(t *testing.T) {
                result := map[string]any{}
                subs := make([]map[string]any, 500)
                applySubdomainDisplayCap(result, subs, 250)
                if result[mapKeyDisplayedCount] != 275 {
                        t.Errorf("displayed_count = %v, want 275", result[mapKeyDisplayedCount])
                }
        })
}

func TestIsWildcardCertEntry(t *testing.T) {
        tests := []struct {
                name    string
                entry   ctEntry
                pattern string
                want    bool
        }{
                {"match", ctEntry{NameValue: "*.example.com"}, "*.example.com", true},
                {"multiline match", ctEntry{NameValue: "example.com\n*.example.com"}, "*.example.com", true},
                {"no match", ctEntry{NameValue: "www.example.com"}, "*.example.com", false},
                {"case insensitive", ctEntry{NameValue: "*.EXAMPLE.COM"}, "*.example.com", true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := isWildcardCertEntry(tt.entry, tt.pattern); got != tt.want {
                                t.Errorf("isWildcardCertEntry() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestDetectWildcardCerts(t *testing.T) {
        future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
        entries := []ctEntry{
                {
                        NameValue:  "*.example.com\nwww.example.com",
                        NotBefore:  "2024-01-01",
                        NotAfter:   future,
                        IssuerName: "O=Let's Encrypt",
                },
        }
        result := detectWildcardCerts(entries, "example.com")
        if result == nil {
                t.Fatal("expected wildcard result, got nil")
        }
        if result["present"] != true {
                t.Error("expected present=true")
        }
        if result["current"] != true {
                t.Error("expected current=true")
        }
}

func TestDetectWildcardCertsNone(t *testing.T) {
        entries := []ctEntry{
                {NameValue: "www.example.com", NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
        }
        result := detectWildcardCerts(entries, "example.com")
        if result != nil {
                t.Error("expected nil for non-wildcard entries")
        }
}

func TestCtEntryCoversName(t *testing.T) {
        tests := []struct {
                name  string
                entry ctEntry
                qname string
                want  bool
        }{
                {"exact match", ctEntry{NameValue: "www.example.com"}, "www.example.com", true},
                {"wildcard match", ctEntry{NameValue: "*.example.com"}, "www.example.com", true},
                {"no match", ctEntry{NameValue: "other.example.com"}, "www.example.com", false},
                {"multiline", ctEntry{NameValue: "a.example.com\nwww.example.com"}, "www.example.com", true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := ctEntryCoversName(tt.entry, tt.qname); got != tt.want {
                                t.Errorf("ctEntryCoversName() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestMatchCTForName(t *testing.T) {
        future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
        entries := []ctEntry{
                {NameValue: "www.example.com", NotBefore: "2024-01-01", NotAfter: future, IssuerName: "O=Let's Encrypt"},
                {NameValue: "www.example.com", NotBefore: "2023-06-01", NotAfter: "2024-01-01", IssuerName: "O=DigiCert"},
        }
        result := matchCTForName("www.example.com", entries, time.Now())
        if result.certCount != 2 {
                t.Errorf("certCount = %d, want 2", result.certCount)
        }
        if !result.isCurrent {
                t.Error("expected isCurrent=true")
        }
        if len(result.issuers) != 2 {
                t.Errorf("issuers = %d, want 2", len(result.issuers))
        }
}

func TestProcessCTEntries(t *testing.T) {
        future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
        entries := []ctEntry{
                {NameValue: "www.example.com", NotBefore: "2024-01-01", NotAfter: future, IssuerName: "O=Test CA"},
                {NameValue: "api.example.com", NotBefore: "2024-01-01", NotAfter: future, IssuerName: "O=Test CA"},
        }
        set := make(map[string]map[string]any)
        processCTEntries(entries, "example.com", set)
        if len(set) != 2 {
                t.Errorf("got %d subdomains, want 2", len(set))
        }
        if _, ok := set["www.example.com"]; !ok {
                t.Error("expected www.example.com in set")
        }
}

func TestMergeCTSubdomain(t *testing.T) {
        existing := map[string]any{
                mapKeyCertCount: "1",
                mapKeyIsCurrent: false,
                mapKeyIssuers:   []string{"CA1"},
        }
        mergeCTSubdomain(existing, true, "CA2")
        if existing[mapKeyCertCount] != "2" {
                t.Errorf("cert_count = %v, want 2", existing[mapKeyCertCount])
        }
        if existing[mapKeyIsCurrent] != true {
                t.Error("expected is_current to be true")
        }
        issuers := existing[mapKeyIssuers].([]string)
        if len(issuers) != 2 {
                t.Errorf("issuers len = %d, want 2", len(issuers))
        }
}

func TestBuildCASummary(t *testing.T) {
        future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
        entries := []ctEntry{
                {IssuerName: "O=Let's Encrypt", NotBefore: "2024-01-01", NotAfter: future},
                {IssuerName: "O=Let's Encrypt", NotBefore: "2024-02-01", NotAfter: future},
                {IssuerName: "O=DigiCert", NotBefore: "2024-03-01", NotAfter: future},
        }
        summary := buildCASummary(entries)
        if len(summary) != 2 {
                t.Fatalf("got %d CAs, want 2", len(summary))
        }
        if summary[0][mapKeyName] != "Let's Encrypt" {
                t.Errorf("first CA = %v, want Let's Encrypt", summary[0][mapKeyName])
        }
}

func TestConvertCertspotterEntries(t *testing.T) {
        csEntries := []certspotterEntry{
                {DNSNames: []string{"a.example.com", "b.example.com"}, NotBefore: "2024-01-01", NotAfter: "2025-01-01"},
                {DNSNames: []string{"c.example.com"}, NotBefore: "2024-06-01", NotAfter: "2025-06-01"},
        }
        got := convertCertspotterEntries(csEntries)
        if len(got) != 2 {
                t.Fatalf("got %d entries, want 2", len(got))
        }
        if got[0].NameValue != "a.example.com\nb.example.com" {
                t.Errorf("NameValue = %q", got[0].NameValue)
        }
}

func TestClassifyCTFailure(t *testing.T) {
        tests := []struct {
                name  string
                input string
                want  string
        }{
                {"empty is timeout", "", "timeout"},
                {"deadline is timeout", "context deadline exceeded", "timeout"},
                {"timeout string", "operation timeout reached", "timeout"},
                {"other error", "connection refused", "error"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := classifyCTFailure(tt.input)
                        if got != tt.want {
                                t.Errorf("classifyCTFailure(%q) = %q, want %q", tt.input, got, tt.want)
                        }
                })
        }
}

func TestPopulateCTResults(t *testing.T) {
        t.Run("available", func(t *testing.T) {
                result := map[string]any{}
                future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
                entries := []ctEntry{
                        {IssuerName: "O=Test", NotBefore: "2024-01-01", NotAfter: future, SerialNumber: "1"},
                        {IssuerName: "O=Test", NotBefore: "2024-01-01", NotAfter: future, SerialNumber: "2"},
                }
                deduped := deduplicateCTEntries(entries)
                populateCTResults(result, entries, deduped, "example.com", true)
                if result["total_certs"] != 2 {
                        t.Errorf("total_certs = %v, want 2", result["total_certs"])
                }
        })

        t.Run("not available", func(t *testing.T) {
                result := map[string]any{}
                populateCTResults(result, nil, nil, "example.com", false)
                if _, ok := result["total_certs"]; ok {
                        t.Error("should not set total_certs when not available")
                }
        })
}

func TestCollectWildcardSANs(t *testing.T) {
        acc := &wildcardAccum{sanSet: make(map[string]bool)}
        collectWildcardSANs("*.example.com\nwww.example.com\nexample.com\nother.net", "*.example.com", "example.com", acc)
        if len(acc.sanSet) != 1 {
                t.Errorf("sanSet size = %d, want 1 (www.example.com only)", len(acc.sanSet))
        }
        if !acc.sanSet["www.example.com"] {
                t.Error("expected www.example.com in sanSet")
        }
}

func TestTrackWildcardIssuer(t *testing.T) {
        acc := &wildcardAccum{issuerSeen: make(map[string]bool)}
        trackWildcardIssuer("CA1", acc)
        trackWildcardIssuer("CA1", acc)
        trackWildcardIssuer("CA2", acc)
        if len(acc.issuers) != 2 {
                t.Errorf("issuers = %d, want 2", len(acc.issuers))
        }
}

func TestReturnCachedSubdomains(t *testing.T) {
        cached := []map[string]any{
                {mapKeyName: "a.example.com", mapKeyIsCurrent: true, mapKeyCnameTarget: "cdn.example.com"},
                {mapKeyName: "b.example.com", mapKeyIsCurrent: false},
        }
        result := map[string]any{
                mapKeySubdomains: []map[string]any{},
        }
        got := returnCachedSubdomains(result, cached)
        if got[mapKeyUniqueSubdomains] != 2 {
                t.Errorf("unique_subdomains = %v, want 2", got[mapKeyUniqueSubdomains])
        }
        if got["ct_source"] != "cache" {
                t.Errorf("ct_source = %v, want cache", got["ct_source"])
        }
        if got[mapKeyCnameCount] != float64(1) {
                t.Errorf("cname_count = %v, want 1", got[mapKeyCnameCount])
        }
}

func TestEnrichDNSWithCTData(t *testing.T) {
        future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
        ctEntries := []ctEntry{
                {NameValue: "www.example.com", NotBefore: "2024-01-01", NotAfter: future, IssuerName: "O=TestCA"},
        }
        subdomainSet := map[string]map[string]any{
                "www.example.com": {mapKeyName: "www.example.com", mapKeySource: "dns"},
                "api.example.com": {mapKeyName: "api.example.com", mapKeySource: "ct"},
        }
        enrichDNSWithCTData(ctEntries, "example.com", subdomainSet)
        if subdomainSet["www.example.com"][mapKeyCertCount] != "1" {
                t.Error("expected www.example.com to be enriched with cert data")
        }
        if _, ok := subdomainSet["api.example.com"][mapKeyCertCount]; ok {
                t.Error("ct source entries should not be enriched")
        }
}
