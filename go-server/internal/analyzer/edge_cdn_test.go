package analyzer

import (
        "testing"
)

func TestDetectEdgeCDN(t *testing.T) {
        result := DetectEdgeCDN(map[string]any{})
        if result["status"] != "success" {
                t.Errorf("status = %v, want success", result["status"])
        }
}

func TestCheckASNForCDN(t *testing.T) {
        provider, indicators := checkASNForCDN(map[string]any{}, nil)
        if provider != "" {
                t.Errorf("provider = %q, want empty for no ASN input", provider)
        }
        if len(indicators) != 0 {
                t.Errorf("indicators = %v, want empty", indicators)
        }
}

func TestCheckCNAMEForCDN(t *testing.T) {
        provider, indicators := checkCNAMEForCDN(map[string]any{}, nil)
        if provider != "" {
                t.Errorf("provider = %q, want empty for no CNAME input", provider)
        }
        if len(indicators) != 0 {
                t.Errorf("indicators = %v, want empty", indicators)
        }
}

func TestCheckPTRForCDN(t *testing.T) {
        provider, indicators := checkPTRForCDN(map[string]any{}, nil)
        if provider != "" {
                t.Errorf("provider = %q, want empty for no PTR input", provider)
        }
        if len(indicators) != 0 {
                t.Errorf("indicators = %v, want empty", indicators)
        }
}

func TestMatchASNEntries(t *testing.T) {
        provider, indicators := matchASNEntries(map[string]any{}, "asn", nil)
        if provider != "" {
                t.Errorf("provider = %q, want empty for no ASN input", provider)
        }
        if len(indicators) != 0 {
                t.Errorf("indicators = %v, want empty", indicators)
        }
}

func TestClassifyCloudIP(t *testing.T) {
        provider, isCDN := classifyCloudIP("AS99999", nil)
        if provider != "" {
                t.Errorf("provider = %q, want empty for unknown ASN", provider)
        }
        if isCDN {
                t.Error("expected isCDN=false for unknown ASN")
        }
}

func TestEdgeCDNMapsPopulated(t *testing.T) {
        if len(cdnASNs) == 0 {
                t.Error("cdnASNs should be populated with CDN provider data")
        }
        if len(cloudASNs) == 0 {
                t.Error("cloudASNs should be populated with cloud provider data")
        }
        if len(cloudCDNPTRPatterns) == 0 {
                t.Error("cloudCDNPTRPatterns should be populated with PTR patterns")
        }
        if len(cdnCNAMEPatterns) == 0 {
                t.Error("cdnCNAMEPatterns should be populated with CNAME patterns")
        }
}

func TestDetectEdgeCDNResultFields(t *testing.T) {
        result := DetectEdgeCDN(map[string]any{
                "some_key": "some_value",
        })
        if result["status"] != "success" {
                t.Errorf("status = %v, want success", result["status"])
        }
        if result["cdn_provider"] != "" {
                t.Errorf("cdn_provider = %v, want empty for no matching input", result["cdn_provider"])
        }
        indicators, ok := result["cdn_indicators"].([]string)
        if !ok {
                t.Fatal("cdn_indicators should be []string")
        }
        if len(indicators) != 0 {
                t.Errorf("indicators = %v, want empty", indicators)
        }
        issues, ok := result["issues"].([]string)
        if !ok {
                t.Fatal("issues should be []string")
        }
        if len(issues) != 0 {
                t.Errorf("issues should be empty, got %v", issues)
        }
}

func TestCheckASNForCDNWithData(t *testing.T) {
        results := map[string]any{
                "asn_info": map[string]any{
                        "ipv4_asn": []map[string]any{
                                {"asn": "13335"},
                        },
                },
        }
        provider, indicators := checkASNForCDN(results, []string{"existing"})
        if provider == "" {
                t.Error("expected provider detection for Cloudflare ASN 13335")
        }
        if len(indicators) < 2 {
                t.Errorf("indicators should include existing + new, got %v", indicators)
        }
}

func TestMatchASNEntriesWithData(t *testing.T) {
        asnData := map[string]any{
                "ipv4_asn": []map[string]any{
                        {"asn": "13335"},
                },
        }
        provider, _ := matchASNEntries(asnData, "ipv4_asn", []string{"test"})
        if provider == "" {
                t.Error("expected provider detection for Cloudflare ASN data")
        }
}

func TestCheckCNAMEForCDNWithData(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "CNAME": []string{"cdn.cloudflare.net"},
                },
        }
        provider, indicators := checkCNAMEForCDN(results, nil)
        if provider == "" {
                t.Error("expected provider detection for cloudflare.net CNAME")
        }
        if len(indicators) == 0 {
                t.Error("expected indicators for cloudflare.net CNAME")
        }
}

func TestCheckPTRForCDNWithData(t *testing.T) {
        results := map[string]any{
                "basic_records": map[string]any{
                        "PTR": []string{"server-1.cdn.cloudflare.net"},
                },
        }
        provider, indicators := checkPTRForCDN(results, []string{})
        if provider == "" {
                t.Error("expected provider detection for cloudflare PTR")
        }
        if len(indicators) == 0 {
                t.Error("expected indicators for cloudflare PTR")
        }
}

func TestClassifyCloudIPVariousASNs(t *testing.T) {
        knownCloudASNs := []string{"16509", "15169", "8075", "14618"}
        for _, asn := range knownCloudASNs {
                provider, _ := classifyCloudIP(asn, []string{"server.example.com"})
                if provider == "" {
                        t.Errorf("classifyCloudIP(%q) expected provider detection for known cloud ASN", asn)
                }
        }
}

func TestIsOriginVisible(t *testing.T) {
        if isOriginVisible("Cloudflare") {
                t.Error("origin should NOT be visible behind Cloudflare CDN")
        }
        if !isOriginVisible("") {
                t.Error("origin should be visible when no CDN detected")
        }
        if !isOriginVisible("unknown-provider") {
                t.Error("origin should be visible for unknown provider")
        }
}

