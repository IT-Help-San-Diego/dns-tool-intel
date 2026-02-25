// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "testing"
)

func TestCheckDSKeyAlignment_BothMatch(t *testing.T) {
        ds := []DSRecord{
                {KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
        }
        keys := []DNSKEYRecord{
                {Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true},
                {Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 54321, IsZSK: true},
        }

        result := CheckDSKeyAlignment(ds, keys)

        if !result.Aligned {
                t.Error("expected aligned DS/DNSKEY")
        }
        if len(result.MatchedPairs) != 1 {
                t.Errorf("expected 1 matched pair, got %d", len(result.MatchedPairs))
        }
        if len(result.UnmatchedDS) != 0 {
                t.Errorf("expected 0 unmatched DS, got %d", len(result.UnmatchedDS))
        }
        if len(result.Issues) != 0 {
                t.Errorf("expected 0 issues, got %d: %v", len(result.Issues), result.Issues)
        }
}

func TestCheckDSKeyAlignment_Mismatched(t *testing.T) {
        ds := []DSRecord{
                {KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
        }
        keys := []DNSKEYRecord{
                {Flags: 257, Protocol: 3, Algorithm: 8, KeyTag: 12345, IsKSK: true},
        }

        result := CheckDSKeyAlignment(ds, keys)

        if len(result.Issues) == 0 {
                t.Error("expected issues for algorithm mismatch")
        }
}

func TestCheckDSKeyAlignment_MissingDS(t *testing.T) {
        ds := []DSRecord{}
        keys := []DNSKEYRecord{
                {Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 12345, IsKSK: true},
        }

        result := CheckDSKeyAlignment(ds, keys)

        if result.Aligned {
                t.Error("expected not aligned when DS is missing")
        }
        if len(result.UnmatchedKeys) != 1 {
                t.Errorf("expected 1 unmatched key, got %d", len(result.UnmatchedKeys))
        }
}

func TestCheckDSKeyAlignment_MissingDNSKEY(t *testing.T) {
        ds := []DSRecord{
                {KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
        }
        keys := []DNSKEYRecord{}

        result := CheckDSKeyAlignment(ds, keys)

        if result.Aligned {
                t.Error("expected not aligned when DNSKEY is missing")
        }
        if len(result.UnmatchedDS) != 1 {
                t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
        }
}

func TestCheckDSKeyAlignment_BothEmpty(t *testing.T) {
        result := CheckDSKeyAlignment([]DSRecord{}, []DNSKEYRecord{})

        if !result.Aligned {
                t.Error("expected aligned when both empty (no DNSSEC)")
        }
        if len(result.Issues) != 0 {
                t.Errorf("expected 0 issues, got %d", len(result.Issues))
        }
}

func TestCheckDSKeyAlignment_NoKeyTagMatch(t *testing.T) {
        ds := []DSRecord{
                {KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: "abc"},
        }
        keys := []DNSKEYRecord{
                {Flags: 257, Protocol: 3, Algorithm: 13, KeyTag: 65535, IsKSK: true},
        }

        result := CheckDSKeyAlignment(ds, keys)

        if result.Aligned {
                t.Error("expected not aligned when key tags don't match")
        }
        if len(result.UnmatchedDS) != 1 {
                t.Errorf("expected 1 unmatched DS, got %d", len(result.UnmatchedDS))
        }
        if len(result.UnmatchedKeys) != 1 {
                t.Errorf("expected 1 unmatched key, got %d", len(result.UnmatchedKeys))
        }
}

func TestIsInBailiwick(t *testing.T) {
        tests := []struct {
                ns, domain string
                expected   bool
        }{
                {"ns1.example.com.", "example.com", true},
                {"ns1.example.com", "example.com", true},
                {"ns1.dns.example.com", "example.com", true},
                {"ns1.cloudflare.com", "example.com", false},
                {"ns1.example.com", "other.com", false},
        }

        for _, tt := range tests {
                t.Run(tt.ns+"_"+tt.domain, func(t *testing.T) {
                        got := isInBailiwick(tt.ns, tt.domain)
                        if got != tt.expected {
                                t.Errorf("isInBailiwick(%q, %q) = %v, want %v", tt.ns, tt.domain, got, tt.expected)
                        }
                })
        }
}

func TestCheckGlueCompleteness_AllPresent(t *testing.T) {
        nameservers := []string{"ns1.example.com.", "ns2.example.com."}
        domain := "example.com"
        glueIPv4 := map[string][]string{
                "ns1.example.com": {"1.2.3.4"},
                "ns2.example.com": {"5.6.7.8"},
        }
        glueIPv6 := map[string][]string{
                "ns1.example.com": {"2001:db8::1"},
                "ns2.example.com": {"2001:db8::2"},
        }

        result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

        if !result.Complete {
                t.Error("expected complete glue")
        }
        if result.InBailiwickCount != 2 {
                t.Errorf("expected 2 in-bailiwick, got %d", result.InBailiwickCount)
        }
        if result.GluePresent != 2 {
                t.Errorf("expected 2 glue present, got %d", result.GluePresent)
        }
        if len(result.Issues) != 0 {
                t.Errorf("expected 0 issues, got %d: %v", len(result.Issues), result.Issues)
        }
}

func TestCheckGlueCompleteness_MissingGlue(t *testing.T) {
        nameservers := []string{"ns1.example.com."}
        domain := "example.com"
        glueIPv4 := map[string][]string{}
        glueIPv6 := map[string][]string{}

        result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

        if result.Complete {
                t.Error("expected incomplete when glue is missing")
        }
        if result.GlueMissing != 1 {
                t.Errorf("expected 1 glue missing, got %d", result.GlueMissing)
        }
        if len(result.Issues) == 0 {
                t.Error("expected issues for missing glue")
        }
}

func TestCheckGlueCompleteness_OutOfBailiwick(t *testing.T) {
        nameservers := []string{"ns1.cloudflare.com.", "ns2.cloudflare.com."}
        domain := "example.com"
        glueIPv4 := map[string][]string{}
        glueIPv6 := map[string][]string{}

        result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

        if !result.Complete {
                t.Error("expected complete when all NS are out of bailiwick (no glue needed)")
        }
        if result.InBailiwickCount != 0 {
                t.Errorf("expected 0 in-bailiwick, got %d", result.InBailiwickCount)
        }
}

func TestCheckGlueCompleteness_PartialGlue(t *testing.T) {
        nameservers := []string{"ns1.example.com."}
        domain := "example.com"
        glueIPv4 := map[string][]string{
                "ns1.example.com": {"1.2.3.4"},
        }
        glueIPv6 := map[string][]string{}

        result := CheckGlueCompleteness(nameservers, domain, glueIPv4, glueIPv6)

        if result.GluePresent != 1 {
                t.Errorf("expected 1 glue present, got %d", result.GluePresent)
        }
        found := false
        for _, issue := range result.Issues {
                if len(issue) > 0 {
                        found = true
                }
        }
        if !found {
                t.Error("expected issues for partial glue (missing IPv6)")
        }
}

func TestCompareTTLs_Match(t *testing.T) {
        parent := uint32(3600)
        child := uint32(3600)

        result := CompareTTLs(&parent, &child)

        if !result.Match {
                t.Error("expected TTLs to match")
        }
        if result.DriftSecs != 0 {
                t.Errorf("expected 0 drift, got %d", result.DriftSecs)
        }
        if len(result.Issues) != 0 {
                t.Errorf("expected 0 issues, got %d", len(result.Issues))
        }
}

func TestCompareTTLs_Mismatch(t *testing.T) {
        parent := uint32(3600)
        child := uint32(300)

        result := CompareTTLs(&parent, &child)

        if result.Match {
                t.Error("expected TTLs not to match")
        }
        if result.DriftSecs != 3300 {
                t.Errorf("expected drift 3300, got %d", result.DriftSecs)
        }
        if len(result.Issues) == 0 {
                t.Error("expected issues for TTL mismatch")
        }
}

func TestCompareTTLs_NilParent(t *testing.T) {
        child := uint32(3600)

        result := CompareTTLs(nil, &child)

        if result.Match {
                t.Error("expected no match when parent TTL is nil")
        }
        if len(result.Issues) == 0 {
                t.Error("expected issues when parent TTL missing")
        }
}

func TestCompareTTLs_BothNil(t *testing.T) {
        result := CompareTTLs(nil, nil)

        if result.Match {
                t.Error("expected no match when both TTLs are nil")
        }
        if len(result.Issues) == 0 {
                t.Error("expected issues when both TTLs missing")
        }
}

func TestCheckSOAConsistency_Consistent(t *testing.T) {
        serials := map[string]uint32{
                "ns1.example.com": 2026022201,
                "ns2.example.com": 2026022201,
                "ns3.example.com": 2026022201,
        }

        result := CheckSOAConsistency(serials)

        if !result.Consistent {
                t.Error("expected consistent SOA serials")
        }
        if result.UniqueCount != 1 {
                t.Errorf("expected 1 unique serial, got %d", result.UniqueCount)
        }
        if len(result.Issues) != 0 {
                t.Errorf("expected 0 issues, got %d", len(result.Issues))
        }
}

func TestCheckSOAConsistency_Inconsistent(t *testing.T) {
        serials := map[string]uint32{
                "ns1.example.com": 2026022201,
                "ns2.example.com": 2026022200,
        }

        result := CheckSOAConsistency(serials)

        if result.Consistent {
                t.Error("expected inconsistent SOA serials")
        }
        if result.UniqueCount != 2 {
                t.Errorf("expected 2 unique serials, got %d", result.UniqueCount)
        }
        if len(result.Issues) == 0 {
                t.Error("expected issues for SOA inconsistency")
        }
}

func TestCheckSOAConsistency_Empty(t *testing.T) {
        serials := map[string]uint32{}

        result := CheckSOAConsistency(serials)

        if len(result.Issues) == 0 {
                t.Error("expected issues when no serials available")
        }
}

func TestParseSOASerial(t *testing.T) {
        tests := []struct {
                name    string
                input   string
                serial  uint32
                ok      bool
        }{
                {"valid SOA", "ns1.example.com. admin.example.com. 2026022201 3600 900 604800 86400", 2026022201, true},
                {"too short", "ns1.example.com. admin.example.com.", 0, false},
                {"invalid serial", "ns1.example.com. admin.example.com. notanumber 3600", 0, false},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        serial, ok := parseSOASerial(tt.input)
                        if ok != tt.ok {
                                t.Errorf("parseSOASerial(%q) ok=%v, want %v", tt.input, ok, tt.ok)
                        }
                        if serial != tt.serial {
                                t.Errorf("parseSOASerial(%q) serial=%d, want %d", tt.input, serial, tt.serial)
                        }
                })
        }
}

func TestStructToMap_DSKeyAlignment(t *testing.T) {
        align := DSKeyAlignment{
                Aligned: true,
                MatchedPairs: []DSKeyPair{
                        {DSKeyTag: 100, DSAlgorithm: 13, DNSKEYKeyTag: 100, DNSKEYAlgorithm: 13},
                },
                UnmatchedDS:   []DSRecord{},
                UnmatchedKeys: []DNSKEYRecord{},
                Issues:        []string{},
        }

        m := structToMap(align)
        if m["aligned"] != true {
                t.Error("expected aligned=true in map")
        }
        pairs, ok := m["matched_pairs"].([]map[string]any)
        if !ok || len(pairs) != 1 {
                t.Error("expected 1 matched pair in map")
        }
}

func TestStructToMap_TTLComparison(t *testing.T) {
        p := uint32(3600)
        c := uint32(300)
        comp := TTLComparison{
                ParentTTL: &p,
                ChildTTL:  &c,
                Match:     false,
                DriftSecs: 3300,
                Issues:    []string{"mismatch"},
        }

        m := structToMap(comp)
        if m["match"] != false {
                t.Error("expected match=false")
        }
        if m["parent_ttl"] != uint32(3600) {
                t.Error("expected parent_ttl=3600")
        }
}

func TestStructToMap_SOAConsistency(t *testing.T) {
        soa := SOAConsistency{
                Consistent:  false,
                Serials:     map[string]uint32{"ns1": 100, "ns2": 200},
                UniqueCount: 2,
                Issues:      []string{"mismatch"},
        }

        m := structToMap(soa)
        if m["consistent"] != false {
                t.Error("expected consistent=false")
        }
        if m["unique_count"] != 2 {
                t.Error("expected unique_count=2")
        }
}
