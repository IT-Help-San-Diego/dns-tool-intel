package analyzer

import (
        "context"
        "testing"
)

func TestMatchEnterpriseProvider_Cloudflare(t *testing.T) {
        im := matchEnterpriseProvider([]string{"ns1.cloudflare.com", "ns2.cloudflare.com"})
        if im == nil || im.provider == nil {
                t.Fatal("expected match for Cloudflare NS")
        }
        if im.provider.Name != "Cloudflare" {
                t.Errorf("provider name = %q, want Cloudflare", im.provider.Name)
        }
        if im.tier != tierEnterprise {
                t.Errorf("tier = %q, want %q", im.tier, tierEnterprise)
        }
}

func TestMatchEnterpriseProvider_AWS(t *testing.T) {
        im := matchEnterpriseProvider([]string{"ns-1234.awsdns-12.co.uk"})
        if im == nil || im.provider == nil {
                t.Fatal("expected match for AWS DNS")
        }
        if im.provider.Name != nameAmazonRoute53 {
                t.Errorf("provider name = %q, want %q", im.provider.Name, nameAmazonRoute53)
        }
}

func TestMatchEnterpriseProvider_LegacyBlocklist(t *testing.T) {
        im := matchEnterpriseProvider([]string{"ns1.bluehost.com"})
        if im != nil {
                t.Error("expected nil for blocklisted provider")
        }
}

func TestMatchEnterpriseProvider_Empty(t *testing.T) {
        im := matchEnterpriseProvider(nil)
        if im != nil {
                t.Error("expected nil for empty NS list")
        }
}

func TestMatchEnterpriseProvider_UnknownNS(t *testing.T) {
        im := matchEnterpriseProvider([]string{"ns1.randomdns.example.com"})
        if im != nil {
                t.Error("expected nil for unknown NS")
        }
}

func TestMatchEnterpriseProvider_CaseInsensitive(t *testing.T) {
        im := matchEnterpriseProvider([]string{"NS1.CLOUDFLARE.COM"})
        if im == nil {
                t.Fatal("expected case-insensitive match for Cloudflare")
        }
}

func TestMatchSelfHostedProvider(t *testing.T) {
        got := matchSelfHostedProvider("ns1.example.com")
        if got != nil {
                t.Error("expected nil (empty map in intel build)")
        }
}

func TestMatchManagedProvider(t *testing.T) {
        got := matchManagedProvider("ns1.example.com")
        if got != nil {
                t.Error("expected nil (empty map in intel build)")
        }
}

func TestMatchGovernmentDomain(t *testing.T) {
        im, isGov := matchGovernmentDomain("example.gov")
        if !isGov || im == nil {
                t.Fatal("expected .gov domain to match a government provider")
        }
        if im.provider == nil || im.provider.Name != "U.S. Government" {
                t.Errorf("expected U.S. Government provider for .gov, got %+v", im.provider)
        }
        if none, ok := matchGovernmentDomain("example.com"); ok || none != nil {
                t.Error("expected non-government domain to not match")
        }
}

func TestCollectAltSecurityItems(t *testing.T) {
        got := collectAltSecurityItems(map[string]any{"spf_analysis": map[string]any{}})
        if got != nil {
                t.Error("expected nil")
        }
}

func TestAssessTier(t *testing.T) {
        cases := map[string]string{
                tierEnterprise: "Enterprise-grade DNS infrastructure",
                tierManaged:    "Managed DNS hosting",
                "standard":     "Standard DNS",
                "":             "Standard DNS",
        }
        for tier, want := range cases {
                if got := assessTier(tier); got != want {
                        t.Errorf("assessTier(%q) = %q, want %q", tier, got, want)
                }
        }
}

func TestAnalyzeDNSInfrastructure_EnterpriseProvider(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
                },
        }
        got := a.AnalyzeDNSInfrastructure("example.com", results)
        if got["provider_tier"] != tierEnterprise {
                t.Errorf("provider_tier = %v, want %q", got["provider_tier"], tierEnterprise)
        }
        if got["provider"] != "Cloudflare" {
                t.Errorf("provider = %v, want Cloudflare", got["provider"])
        }
}

func TestAnalyzeDNSInfrastructure_StandardProvider(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns1.random-provider.example.com"},
                },
        }
        got := a.AnalyzeDNSInfrastructure("example.com", results)
        if got["provider_tier"] != "standard" {
                t.Errorf("provider_tier = %v, want 'standard'", got["provider_tier"])
        }
}

func TestAnalyzeDNSInfrastructure_NilBasicRecords(t *testing.T) {
        a := &Analyzer{}
        got := a.AnalyzeDNSInfrastructure("example.com", map[string]any{})
        if got["provider_tier"] != "standard" {
                t.Errorf("provider_tier = %v", got["provider_tier"])
        }
}

func TestAnalyzeDNSInfrastructure_DNSSECExplains(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns1.cloudflare.com"},
                },
                "dnssec": map[string]any{
                        "status": "fail",
                },
        }
        got := a.AnalyzeDNSInfrastructure("example.com", results)
        if got["explains_no_dnssec"] != true {
                t.Error("expected explains_no_dnssec=true when DNSSEC status is not success")
        }
}

func TestGetHostingInfo_WithProviders(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "MX":    []string{"aspmx.l.google.com"},
                        "NS":    []string{"ns1.cloudflare.com"},
                        "CNAME": []string{"example.herokuapp.com"},
                },
        }
        got := a.GetHostingInfo(context.Background(), "example.com", results)
        if got["domain"] != "example.com" {
                t.Errorf("domain = %v", got["domain"])
        }
        if _, ok := got["hosting"].(string); !ok {
                t.Error("hosting should be a string")
        }
}

func TestGetHostingInfo_Empty(t *testing.T) {
        a := &Analyzer{}
        got := a.GetHostingInfo(context.Background(), "example.com", map[string]any{})
        if got["domain"] != "example.com" {
                t.Errorf("domain = %v", got["domain"])
        }
}

func TestGetHostingInfo_NoMailDomain(t *testing.T) {
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{},
                "has_null_mx":   true,
        }
        got := a.GetHostingInfo(context.Background(), "example.com", results)
        email := got["email_hosting"].(string)
        if email != "No Mail Domain" {
                t.Errorf("email_hosting = %q, want 'No Mail Domain'", email)
        }
}

func TestIdentifyEmailProvider_Google(t *testing.T) {
        got := identifyEmailProvider([]string{"aspmx.l.google.com", "alt1.aspmx.l.google.com"})
        if got != nameGoogleWorkspace {
                t.Errorf("identifyEmailProvider = %q, want %q", got, nameGoogleWorkspace)
        }
}

func TestIdentifyEmailProvider_Microsoft(t *testing.T) {
        got := identifyEmailProvider([]string{"mail.protection.outlook.com"})
        if got != nameMicrosoft365 {
                t.Errorf("identifyEmailProvider = %q, want %q", got, nameMicrosoft365)
        }
}

func TestIdentifyEmailProvider_Empty(t *testing.T) {
        got := identifyEmailProvider(nil)
        if got != "" {
                t.Errorf("identifyEmailProvider(nil) = %q, want empty", got)
        }
}

func TestIdentifyDNSProvider_Cloudflare(t *testing.T) {
        got := identifyDNSProvider([]string{"ns1.cloudflare.com"})
        if got != "Cloudflare" {
                t.Errorf("identifyDNSProvider = %q, want Cloudflare", got)
        }
}

func TestIdentifyDNSProvider_Empty(t *testing.T) {
        got := identifyDNSProvider(nil)
        if got != "" {
                t.Errorf("identifyDNSProvider(nil) = %q, want empty", got)
        }
}

func TestIdentifyWebHosting_FromCNAME(t *testing.T) {
        basic := map[string]any{
                "CNAME": []string{"example.herokuapp.com"},
        }
        got := identifyWebHosting(basic)
        if got != "Heroku" {
                t.Errorf("identifyWebHosting = %q, want Heroku", got)
        }
}

func TestIdentifyWebHosting_NilBasic(t *testing.T) {
        got := identifyWebHosting(nil)
        if got != "" {
                t.Errorf("identifyWebHosting(nil) = %q, want empty", got)
        }
}

func TestIdentifyWebHosting_NoCNAME(t *testing.T) {
        basic := map[string]any{}
        got := identifyWebHosting(basic)
        if got != "" {
                t.Errorf("identifyWebHosting(empty) = %q, want empty", got)
        }
}

func TestDetectEmailSecurityManagement(t *testing.T) {
        a := newTestAnalyzerForIP()
        got := a.DetectEmailSecurityManagement(nil, nil, nil, nil, "example.com", nil)
        if got["actively_managed"] != false {
                t.Error("expected actively_managed=false")
        }
        if got["provider_count"] != 0 {
                t.Errorf("provider_count = %v", got["provider_count"])
        }
}

func TestEnterpriseProviders_KnownEntries(t *testing.T) {
        known := []string{"cloudflare", "awsdns", "azure-dns", "google", "akamai"}
        for _, k := range known {
                if _, ok := enterpriseProviders[k]; !ok {
                        t.Errorf("enterpriseProviders missing key %q", k)
                }
        }
}

func TestLegacyProviderBlocklist_KnownEntries(t *testing.T) {
        known := []string{"networksolutions", "bluehost", "hostgator"}
        for _, k := range known {
                if !legacyProviderBlocklist[k] {
                        t.Errorf("legacyProviderBlocklist should contain %q", k)
                }
        }
}

func TestMxProviderPatterns_KnownEntries(t *testing.T) {
        if mxProviderPatterns["google"] != nameGoogleWorkspace {
                t.Error("mxProviderPatterns['google'] mismatch")
        }
        if mxProviderPatterns["outlook"] != nameMicrosoft365 {
                t.Error("mxProviderPatterns['outlook'] mismatch")
        }
}
