package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"dnstool/go-server/internal/telemetry"
)

// newTestAnalyzerForIP builds an Analyzer wired with offline mocks so IP
// investigation runs deterministically without network access. The mock DNS
// returns no records and the mock HTTP client has no configured responses, so
// every probe (PTR, A/AAAA, MX, NS, SPF, CT subdomains, Team Cymru ASN) yields
// empty results — exercising the "no relationship discovered" path.
func newTestAnalyzerForIP() *Analyzer {
	return &Analyzer{
		DNS:        NewMockDNSClient(),
		HTTP:       NewMockHTTPClient(),
		SlowHTTP:   NewMockHTTPClient(),
		Telemetry:  telemetry.NewRegistry(),
		ctCache:    make(map[string]ctCacheEntry),
		ctCacheTTL: time.Hour,
	}
}

func TestInvestigateIP_IPv4(t *testing.T) {
	a := newTestAnalyzerForIP()
	result := a.InvestigateIP(context.Background(), "example.com", "1.2.3.4")
	if result["status"] != sevSuccess {
		t.Errorf("status = %v, want %s", result["status"], sevSuccess)
	}
	if result["ip_version"] != "IPv4" {
		t.Errorf("ip_version = %v, want IPv4", result["ip_version"])
	}
	if result["domain"] != "example.com" {
		t.Errorf("domain = %v", result["domain"])
	}
	if result["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v", result["ip"])
	}
}

func TestInvestigateIP_IPv6(t *testing.T) {
	a := newTestAnalyzerForIP()
	result := a.InvestigateIP(context.Background(), "example.com", "2001:db8::1")
	if result["ip_version"] != "IPv6" {
		t.Errorf("ip_version = %v, want IPv6", result["ip_version"])
	}
}

func TestInvestigateIP_DefaultClassification(t *testing.T) {
	a := newTestAnalyzerForIP()
	result := a.InvestigateIP(context.Background(), "example.com", "1.2.3.4")
	// With no DNS relationships and no ASN/CDN data, the IP is Unrelated and not a CDN.
	if result["classification"] != classUnrelated {
		t.Errorf("classification = %v, want %s", result["classification"], classUnrelated)
	}
	if result["is_cdn"] != false {
		t.Error("expected is_cdn=false when no CDN ASN is detected")
	}
}

func TestFetchNeighborhoodDomains_NoSecurityTrails(t *testing.T) {
	// Without SecurityTrails credentials FetchDomainsByIP errors, so the
	// neighborhood lookup yields no domains and a zero total.
	domains, total := fetchNeighborhoodDomains(context.Background(), "1.2.3.4", "example.com")
	if domains != nil {
		t.Errorf("expected nil domains without SecurityTrails, got %v", domains)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

func TestBuildNeighborhoodContext(t *testing.T) {
	if got := buildNeighborhoodContext("", 0); got == "" {
		t.Error("expected a descriptive message when no co-tenant domains were found")
	}
	cdn := buildNeighborhoodContext("Cloudflare", 100)
	if !strings.Contains(cdn, "Cloudflare") {
		t.Errorf("CDN neighborhood context must mention the provider, got %q", cdn)
	}
	if largeShared := buildNeighborhoodContext("", 100); largeShared == "" {
		t.Error("expected a shared-hosting message for many co-tenant domains")
	}
}

func TestBuildExecutiveVerdict_DirectAsset(t *testing.T) {
	got := buildExecutiveVerdict(classDirectA, "", "example.com", "1.2.3.4", nil, nil, nil)
	if got == "" {
		t.Fatal("expected a non-empty verdict for a direct-asset classification")
	}
	if !strings.Contains(got, "example.com") {
		t.Errorf("verdict must reference the domain, got %q", got)
	}
}

func TestVerdictSeverity(t *testing.T) {
	if got := verdictSeverity(classDirectA); got != sevSuccess {
		t.Errorf("verdictSeverity(%q) = %q, want %q", classDirectA, got, sevSuccess)
	}
	if got := verdictSeverity(classCDNEdge); got != sevPrimary {
		t.Errorf("verdictSeverity(%q) = %q, want %q", classCDNEdge, got, sevPrimary)
	}
	if got := verdictSeverity(classUnrelated); got != sevSecondary {
		t.Errorf("verdictSeverity(%q) = %q, want %q", classUnrelated, got, sevSecondary)
	}
}

func TestFindSPFTXTRecord(t *testing.T) {
	got := findSPFTXTRecord([]string{"some-other-record", "v=spf1 include:_spf.google.com ~all"})
	if got != "v=spf1 include:_spf.google.com ~all" {
		t.Errorf("findSPFTXTRecord = %q, want the SPF record", got)
	}
	if none := findSPFTXTRecord([]string{"not-spf", "also-not-spf"}); none != "" {
		t.Errorf("expected empty string when no SPF record present, got %q", none)
	}
}

func TestCheckIPInSPFRecord(t *testing.T) {
	if !checkIPInSPFRecord("v=spf1 ip4:1.2.3.4 ~all", "1.2.3.4") {
		t.Error("expected true: 1.2.3.4 is explicitly authorized by the SPF record")
	}
	if checkIPInSPFRecord("v=spf1 ip4:1.2.3.4 ~all", "5.6.7.8") {
		t.Error("expected false: 5.6.7.8 is not authorized by the SPF record")
	}
}

func TestCheckASNForCDNDirect_NoData(t *testing.T) {
	provider, isCDN := checkASNForCDNDirect(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty for missing ASN data", provider)
	}
	if isCDN {
		t.Error("expected isCDN=false for missing ASN data")
	}
}

func TestClassifyOverall_Unrelated(t *testing.T) {
	classification, summary := classifyOverall(nil, nil, "", map[string]any{"ip": "1.2.3.4", "domain": "example.com"})
	if classification != classUnrelated {
		t.Errorf("classification = %q, want %s", classification, classUnrelated)
	}
	if summary == "" {
		t.Error("expected a non-empty summary explaining the absence of a relationship")
	}
}
