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

func TestAnalyzeDNSInfrastructure_DNSSECExplainsCanonicalKey(t *testing.T) {
        // Production structure: the orchestrator attaches the DNSSEC result under
        // "dnssec_analysis", NOT "dnssec". Reading only the bare key left this signal
        // dead in real scans; assert the canonical key drives explains_no_dnssec.
        a := &Analyzer{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "NS": []string{"ns1.cloudflare.com"},
                },
                "dnssec_analysis": map[string]any{
                        "status": "warning",
                },
        }
        got := a.AnalyzeDNSInfrastructure("example.com", results)
        if got["explains_no_dnssec"] != true {
                t.Error("expected explains_no_dnssec=true from canonical dnssec_analysis key")
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

// TestIdentifyDNSProvider_Akamai guards against the regression where the UI
// "DNS Hosting" field rendered "Unknown" for Akamai-hosted NS records even
// though the Footprint detector and the enterprise-tier classifier both named
// the provider — a visible self-contradiction (Unknown vs. Enterprise) on
// Akamai Edge DNS domains such as those using *.akam.net nameservers.
func TestIdentifyDNSProvider_Akamai(t *testing.T) {
        got := identifyDNSProvider([]string{"a1-107.akam.net", "a24-65.akam.net"})
        if got != "Akamai Edge DNS" {
                t.Errorf("identifyDNSProvider = %q, want Akamai Edge DNS", got)
        }
}

// TestIdentifyDNSProvider_EnterpriseRegistrars locks the enterprise/registrar
// DNS provider patterns added to nsProviderPatterns so the UI "DNS Hosting"
// name stays in sync with the Footprint and enterprise-tier classifiers (which
// already recognize these). Each NS sample reflects a real provider hostname.
func TestIdentifyDNSProvider_EnterpriseRegistrars(t *testing.T) {
        cases := []struct {
                name string
                ns   []string
                want string
        }{
                {"CSC dns", []string{"dns1.cscdns.net", "dns2.cscdns.net"}, nameCSCGlobalDNS},
                {"CSC com", []string{"ns1.csc.com"}, nameCSCGlobalDNS},
                {"NetNames", []string{"ns1.netnames.net"}, nameCSCGlobalDNS},
                {"Verisign", []string{"ns1.verisigndns.com"}, "Verisign DNS"},
                {"MarkMonitor", []string{"ns1.markmonitor.com"}, "MarkMonitor DNS"},
                {"Porkbun", []string{"curitiba.ns.porkbun.com"}, "Porkbun"},
        }
        for _, tc := range cases {
                t.Run(tc.name, func(t *testing.T) {
                        if got := identifyDNSProvider(tc.ns); got != tc.want {
                                t.Errorf("identifyDNSProvider(%v) = %q, want %q", tc.ns, got, tc.want)
                        }
                })
        }
}

// TestIdentifyDNSProvider_Deterministic guards the longest-match-wins rule that
// replaced the non-deterministic first-match loop over nsProviderPatterns. When
// an NS set contains more than one provider pattern, Go's randomized map
// iteration could otherwise return a different provider on successive scans —
// the verdict "flapping" the stability gate exists to prevent. The result must
// be (a) stable across many runs and (b) the most specific (longest) pattern.
func TestIdentifyDNSProvider_Deterministic(t *testing.T) {
        // NS hostname that contains two distinct provider substrings ("akam" and
        // the longer, more specific "akamai"). Both map to Akamai Edge DNS, so the
        // answer must be Akamai Edge DNS on every run, never empty or flapping.
        ns := []string{"a1.akamai.akam.net"}
        want := identifyDNSProvider(ns)
        if want == "" {
                t.Fatalf("identifyDNSProvider(%v) = empty, want a provider", ns)
        }
        for i := 0; i < 200; i++ {
                if got := identifyDNSProvider(ns); got != want {
                        t.Fatalf("identifyDNSProvider non-deterministic: run %d = %q, want %q", i, got, want)
                }
        }
}

// TestMatchLongestProvider_MostSpecificWins verifies that when several patterns
// match, the longest (most specific) one is chosen, with alphabetical tie-break.
func TestMatchLongestProvider_MostSpecificWins(t *testing.T) {
        providers := map[string]string{
                "outlook":            "Generic Outlook",
                "protection.outlook": "Microsoft 365",
        }
        got := matchLongestProvider("mail.protection.outlook.com", providers)
        if got != "Microsoft 365" {
                t.Errorf("matchLongestProvider = %q, want Microsoft 365 (longest match)", got)
        }
        if got := matchLongestProvider("nothing-here", providers); got != "" {
                t.Errorf("matchLongestProvider(no match) = %q, want empty", got)
        }
}

// TestMatchLongestProvider_TieBreakDeterministic verifies that when two equal-
// length patterns both match and map to DIFFERENT names, the lexically smaller
// key wins — and does so identically on every run despite randomized map order.
func TestMatchLongestProvider_TieBreakDeterministic(t *testing.T) {
        providers := map[string]string{
                "zzz9": "Provider Z",
                "aaa9": "Provider A",
        }
        const want = "Provider A" // "aaa9" < "zzz9"
        for i := 0; i < 200; i++ {
                if got := matchLongestProvider("ns.aaa9.zzz9.example", providers); got != want {
                        t.Fatalf("matchLongestProvider tie-break non-deterministic: run %d = %q, want %q", i, got, want)
                }
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

// TestIdentifyHostingFromPTR_UsesSeam guards the lookupAddrFn seam: reverse-DNS
// hosting detection must route through the package var (which the default-suite
// TestMain stubs to keep the gate network-free) AND still map a matching PTR to
// its provider. If a future change reverts identifyHostingFromPTR to a direct
// net.LookupAddr call, this test fails because the override is bypassed.
func TestIdentifyHostingFromPTR_UsesSeam(t *testing.T) {
        prev := lookupAddrFn
        defer func() { lookupAddrFn = prev }()

        var gotIP string
        lookupAddrFn = func(ip string) ([]string, error) {
                gotIP = ip
                return []string{"ec2-1-2-3-4.compute.amazonaws.com."}, nil
        }

        got := identifyHostingFromPTR([]string{"1.2.3.4"})
        if gotIP != "1.2.3.4" {
                t.Errorf("seam not invoked with the supplied IP: got %q", gotIP)
        }
        if got != "AWS" {
                t.Errorf("identifyHostingFromPTR = %q, want %q (PTR pattern match via seam)", got, "AWS")
        }
}
