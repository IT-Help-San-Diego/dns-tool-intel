//go:build coverage

package analyzer

import (
	"testing"
)

func TestAnnotateWeb3Results_NotWeb3(t *testing.T) {
	results := map[string]any{mapKeyDomain: "example.com"}
	web3 := Web3ResolutionResult{IsWeb3Input: false}
	annotateWeb3Results(results, web3, "example.com", InputKindDNSDomain)
	if _, ok := results["web3_resolution"]; ok {
		t.Error("expected no web3_resolution for DNS domain")
	}
}

func TestAnnotateWeb3Results_Web3Input(t *testing.T) {
	results := map[string]any{
		mapKeyDomain: "example.eth",
		mapKeyWeb3:   map[string]any{"status": "resolved"},
	}
	web3 := Web3ResolutionResult{
		IsWeb3Input:        true,
		ResolvedDomain:     "example.com",
		ResolutionType:     "ens",
		AttributionWarning: "test warning",
	}
	annotateWeb3Results(results, web3, "example.eth", InputKindENSName)
	if results["web3_original_input"] != "example.eth" {
		t.Errorf("expected web3_original_input='example.eth', got %v", results["web3_original_input"])
	}
	if results["input_kind"] != string(InputKindENSName) {
		t.Error("expected input_kind to be set")
	}
	if results["attribution_warning"] != "test warning" {
		t.Error("expected attribution warning")
	}
	w3a, ok := results[mapKeyWeb3].(map[string]any)
	if !ok || w3a["resolution_info"] == nil {
		t.Error("expected resolution_info in web3_analysis")
	}
}

func TestAnnotateWeb3Results_NoWeb3Analysis(t *testing.T) {
	results := map[string]any{mapKeyDomain: "example.eth"}
	web3 := Web3ResolutionResult{IsWeb3Input: true, ResolvedDomain: "example.com"}
	annotateWeb3Results(results, web3, "example.eth", InputKindENSName)
	if results["web3_original_input"] != "example.eth" {
		t.Error("expected web3_original_input set")
	}
}

func TestAnnotateWeb3Results_EmptyWarning(t *testing.T) {
	results := map[string]any{mapKeyDomain: "test.eth"}
	web3 := Web3ResolutionResult{IsWeb3Input: true, AttributionWarning: ""}
	annotateWeb3Results(results, web3, "test.eth", InputKindENSName)
	if _, ok := results["attribution_warning"]; ok {
		t.Error("expected no attribution_warning for empty warning")
	}
}

func TestComputeSMTPResult_TLD(t *testing.T) {
	resultsMap := map[string]any{
		mapKeySpfOrch:      map[string]any{mapKeyStatus: "pass"},
		mapKeyDmarc:        map[string]any{mapKeyStatus: "pass"},
		mapKeyDkimOrch:     map[string]any{mapKeyStatus: "pass"},
		mapKeyMtaSts:       map[string]any{mapKeyStatus: "pass"},
		mapKeyTlsrpt:       map[string]any{mapKeyStatus: "pass"},
		mapKeyBimi:         map[string]any{mapKeyStatus: "pass"},
		mapKeyCtSubdomains: map[string]any{mapKeyStatus: "pass"},
	}
	// computeSMTPResult was removed when dane/smtp moved into the
	// concurrent fan-out; the behaviour it held now lives in the named
	// helpers below, which is why they are named rather than inline.
	applyTLDNotApplicable(resultsMap)
	result := tldSMTPNotApplicable()
	if result[mapKeyStatus] != statusNA {
		t.Errorf("expected status=n/a for TLD, got %v", result[mapKeyStatus])
	}
	if result["reason"] == nil {
		t.Error("expected reason for TLD")
	}
	if spf, ok := resultsMap[mapKeySpfOrch].(map[string]any); !ok || spf[mapKeyStatus] != statusNA {
		t.Error("expected TLD to set spf to n/a")
	}
}

func TestComputeSMTPResult_NonTLD(t *testing.T) {
	mockDNS := NewMockDNSClient()
	a := &Analyzer{
		DNS:           mockDNS,
		HTTP:          &MockHTTPClient{},
		SMTPProbeMode: "skip",
	}
	resultsMap := map[string]any{
		mapKeyMtaSts:   map[string]any{mapKeyStatus: "pass", "mode": "enforce"},
		mapKeyTlsrpt:   map[string]any{mapKeyStatus: "success", "record": "v=TLSRPTv1;rua=mailto:t@example.com"},
		mapKeyDaneOrch: map[string]any{"has_dane": false},
	}
	// Non-TLD SMTP transport is now analysed directly; the orchestrator
	// supplies the same three inputs the removed wrapper assembled.
	inputs := AnalysisInputs{
		MTASTSResult: getMapResult(resultsMap, mapKeyMtaSts),
		TLSRPTResult: getMapResult(resultsMap, mapKeyTlsrpt),
		DANEResult:   getMapResult(resultsMap, mapKeyDaneOrch),
	}
	result := a.AnalyzeSMTPTransport(t.Context(), "example.com", []string{"mx.example.com"}, inputs)
	if result == nil {
		t.Fatal("expected result")
	}
}

func TestAcquireSlot_Success(t *testing.T) {
	a := &Analyzer{semaphore: make(chan struct{}, 2)}
	result := a.acquireSlot("example.com")
	if result != nil {
		t.Error("expected nil (slot acquired)")
	}
	<-a.semaphore
}

func TestBuildAnalysisProvenance_DNS(t *testing.T) {
	web3 := Web3ResolutionResult{IsWeb3Input: false}
	prov := buildAnalysisProvenance(InputKindDNSDomain, ScopeOwnedDNS, web3, map[string]any{})
	if prov == nil {
		t.Error("expected provenance map")
	}
}

func TestBuildAnalysisProvenance_Web3(t *testing.T) {
	web3 := Web3ResolutionResult{
		IsWeb3Input:    true,
		ResolvedDomain: "example.com",
		ResolutionType: "ens",
	}
	prov := buildAnalysisProvenance(InputKindENSName, ScopeGatewayDerived, web3, map[string]any{})
	if prov == nil {
		t.Error("expected provenance map")
	}
}

func TestBuildGatewayPosture_Coverage(t *testing.T) {
	results := map[string]any{
		"analysis_scope": string(ScopeGatewayDerived),
	}
	posture := buildGatewayPosture(results)
	if posture == nil {
		t.Fatal("expected gateway posture")
	}
}

func TestEnrichHostingFromEdgeCDN_Coverage(t *testing.T) {
	results := map[string]any{
		"edge_cdn": map[string]any{
			"detected": true,
			"provider": "Cloudflare",
		},
		mapKeyHostingSummary: map[string]any{
			"web_hosting": map[string]any{
				"provider": "Unknown",
			},
		},
	}
	enrichHostingFromEdgeCDN(results)
}

func TestExtractSaaSTXTFootprint_Coverage(t *testing.T) {
	results := map[string]any{
		mapKeyBasicRecords: map[string]any{
			"TXT": []string{
				"v=spf1 include:_spf.google.com ~all",
				"google-site-verification=abc123",
				"MS=ms12345678",
				"docusign=abc-123",
				"atlassian-domain-verification=xyz",
				"apple-domain-verification=abc",
			},
		},
	}
	saas := ExtractSaaSTXTFootprint(results)
	if saas == nil {
		t.Fatal("expected SaaS footprint result")
	}
}

func TestExtractSaaSTXTFootprint_EmptyMap(t *testing.T) {
	results := map[string]any{}
	saas := ExtractSaaSTXTFootprint(results)
	if saas == nil {
		t.Fatal("expected SaaS footprint result even with no basic_records")
	}
}
