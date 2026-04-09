package analyzer

import (
        "context"
        "testing"
        "time"

        "dnstool/go-server/internal/icuae"
)

func TestEnrichCurrencyInput_WithData_C3(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "ns": map[string]any{
                        "dns_providers": []string{"Cloudflare"},
                },
                mapKeyBasicRecords: map[string]any{
                        "NS":  []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
                        "SOA": []string{"ns1.cloudflare.com admin.example.com 2024010101 3600 600 604800 1800"},
                },
        }
        enrichCurrencyInput(input, results)
        if len(input.DNSProviders) != 1 || input.DNSProviders[0] != "Cloudflare" {
                t.Errorf("expected Cloudflare provider, got %v", input.DNSProviders)
        }
        if len(input.NSRecords) != 2 {
                t.Errorf("expected 2 NS records, got %d", len(input.NSRecords))
        }
        if input.SOARaw == "" {
                t.Error("expected non-empty SOARaw")
        }
}

func TestEnrichCurrencyInput_NoData_C3(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{}
        enrichCurrencyInput(input, results)
        if len(input.DNSProviders) != 0 {
                t.Error("expected 0 providers for empty results")
        }
}

func TestEnrichCurrencyInput_PartialData_C3(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "ns": map[string]any{},
                mapKeyBasicRecords: map[string]any{
                        "NS": []string{"ns1.example.com"},
                },
        }
        enrichCurrencyInput(input, results)
        if len(input.NSRecords) != 1 {
                t.Errorf("expected 1 NS record, got %d", len(input.NSRecords))
        }
}

func TestBuildICuAEReport_WithData_C3(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300, "MX": 3600}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{}
        report := buildICuAEReport(resolverTTL, authTTL, results)
        if report.OverallScore == 0 && report.OverallGrade == "" {
                t.Log("report generated, fields may default to zero for minimal input")
        }
}

func TestBuildICuAEReport_WithConsensus_C3(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{
                mapKeyResolverConsensus: map[string]any{
                        "resolvers_queried": 5,
                        "per_record_consensus": map[string]any{
                                "A": map[string]any{"consensus": true, "resolver_count": 5},
                        },
                },
        }
        report := buildICuAEReport(resolverTTL, authTTL, results)
        _ = report
}

func TestBuildCoreResults_Coverage_C3(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}, "MX": []string{}}
        auth := map[string]any{"A": []string{"1.2.3.4"}}
        resultsMap := map[string]any{
                mapKeySpfOrch:  map[string]any{mapKeyStatus: mapKeySuccess, "no_mail_intent": false},
                mapKeyDmarc:    map[string]any{mapKeyStatus: mapKeySuccess},
                mapKeyDkimOrch: map[string]any{mapKeyStatus: mapKeySuccess},
        }
        msg := "active domain"
        results := buildCoreResults("example.com", "active", &msg, basic, auth, nil, nil, nil, resultsMap, map[string]any{})
        if results[mapKeyDomain] != "example.com" {
                t.Error("expected domain=example.com")
        }
        if results["domain_exists"] != true {
                t.Error("expected domain_exists=true")
        }
        if results["propagation_status"] == nil {
                t.Error("expected propagation_status")
        }
}

func TestPopulateExtendedResults_Coverage_C3(t *testing.T) {
        results := make(map[string]any)
        resultsMap := make(map[string]any)
        populateExtendedResults(results, resultsMap)
        expectedKeys := []string{mapKeyHttpsSvcb, mapKeyCdsCdnskey, mapKeySmimeaOpenpgpkey, mapKeySecurityTxt, mapKeyAiSurface, mapKeySecretExposure, mapKeyNmapDns, mapKeyDelegationConsistency, mapKeyNsFleet, mapKeyDnssecOps}
        for _, key := range expectedKeys {
                if results[key] == nil {
                        t.Errorf("expected key %s to be populated", key)
                }
        }
}

func TestPopulateExtendedResults_WithExisting_C3(t *testing.T) {
        results := make(map[string]any)
        existing := map[string]any{mapKeyStatus: "pass", "extra": "data"}
        resultsMap := map[string]any{
                mapKeyHttpsSvcb: existing,
        }
        populateExtendedResults(results, resultsMap)
        val, ok := results[mapKeyHttpsSvcb].(map[string]any)
        if !ok {
                t.Error("expected map for httpsSvcb")
        }
        if val[mapKeyStatus] != "pass" {
                t.Error("expected existing data to be used")
        }
}

func TestTimedTask_Coverage_C3(t *testing.T) {
        ch := make(chan namedResult, 1)
        analysisStart := time.Now()
        fn := timedTask(ch, "test_key", analysisStart, func() any {
                return map[string]any{"result": "ok"}
        })
        fn()
        result := <-ch
        if result.key != "test_key" {
                t.Errorf("expected key=test_key, got %s", result.key)
        }
        if result.elapsed <= 0 {
                t.Error("expected positive elapsed time")
        }
}

func TestTimedTaskWithProgress_Coverage_C3(t *testing.T) {
        ch := make(chan namedResult, 1)
        analysisStart := time.Now()
        var progressCalled bool
        cb := func(group, status string, durationMs int) {
                progressCalled = true
        }
        fn := timedTaskWithProgress(ch, "spf", analysisStart, cb, func() any {
                return map[string]any{mapKeyStatus: "pass"}
        })
        fn()
        result := <-ch
        if result.key != "spf" {
                t.Errorf("expected key=spf, got %s", result.key)
        }
        if !progressCalled {
                t.Error("expected progress callback to be called")
        }
}

func TestTimedTaskWithProgress_NilCallback_C3(t *testing.T) {
        ch := make(chan namedResult, 1)
        analysisStart := time.Now()
        fn := timedTaskWithProgress(ch, "dkim", analysisStart, nil, func() any {
                return "result"
        })
        fn()
        result := <-ch
        if result.key != "dkim" {
                t.Errorf("expected key=dkim, got %s", result.key)
        }
}

func TestCheckExistence_HNSResolved_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        web3 := Web3ResolutionResult{IsWeb3Input: true, ResolutionType: "hns", ResolvedDomain: "example.com"}
        status, msg, earlyReturn := a.checkExistence(context.Background(), "example.com", "test.hns", InputKindHNSName, web3)
        if earlyReturn != nil {
                t.Error("expected no early return for HNS resolved")
        }
        if status != "hns_resolved" {
                t.Errorf("expected hns_resolved, got %s", status)
        }
        if msg == nil {
                t.Error("expected message for HNS resolved")
        }
}

func TestCheckExistence_Web3NotExist_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        web3 := Web3ResolutionResult{IsWeb3Input: true, ResolvedDomain: "nonexistent.com"}
        status, _, earlyReturn := a.checkExistence(context.Background(), "nonexistent.com", "test.eth", InputKindENSName, web3)
        if earlyReturn == nil {
                t.Error("expected early return for non-existent web3 domain")
        }
        if status != "undelegated" {
                t.Errorf("expected undelegated, got %s", status)
        }
        if earlyReturn != nil {
                if earlyReturn["web3_resolution"] == nil {
                        t.Error("expected web3_resolution in early return")
                }
                if earlyReturn["input_kind"] != string(InputKindENSName) {
                        t.Error("expected input_kind set")
                }
        }
}

func TestResolveWeb3Input_DNSDomain_C3(t *testing.T) {
        a := &Analyzer{}
        web3, resolved, earlyReturn := a.resolveWeb3Input(context.Background(), "example.com", InputKindDNSDomain)
        if resolved != "" {
                t.Error("expected no resolution for DNS domain")
        }
        if earlyReturn != nil {
                t.Error("expected no early return for DNS domain")
        }
        if web3.IsWeb3Input {
                t.Error("expected IsWeb3Input=false for DNS domain")
        }
}

func TestStringSetEqual_C3(t *testing.T) {
        tests := []struct {
                name string
                a, b []string
                want bool
        }{
                {"empty", nil, nil, true},
                {"equal", []string{"a", "b"}, []string{"b", "a"}, true},
                {"not equal", []string{"a"}, []string{"b"}, false},
                {"different length", []string{"a", "b"}, []string{"a"}, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := stringSetEqual(tt.a, tt.b); got != tt.want {
                                t.Errorf("stringSetEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
                        }
                })
        }
}

func TestBuildPropagationStatus_MultipleTypes_C3(t *testing.T) {
        basic := map[string]any{
                "A":    []string{"1.2.3.4"},
                "AAAA": []string{"::1"},
                "MX":   []string{"10 mx.test"},
                "_ttl": map[string]uint32{"A": 300},
        }
        auth := map[string]any{
                "A":    []string{"1.2.3.4"},
                "AAAA": []string{"::1"},
        }
        result := buildPropagationStatus(basic, auth)
        if _, ok := result["_ttl"]; ok {
                t.Error("expected _ttl to be skipped")
        }
        if a, ok := result["A"].(map[string]any); ok {
                if a[mapKeyStatus] != "synchronized" {
                        t.Error("expected A synchronized")
                }
        }
        if mx, ok := result["MX"].(map[string]any); ok {
                if mx[mapKeyStatus] != "unknown" {
                        t.Errorf("expected MX unknown (not in auth), got %v", mx[mapKeyStatus])
                }
        }
}

func TestBuildAnalysisProvenance_Web3WithGateway_C3(t *testing.T) {
        web3 := Web3ResolutionResult{
                IsWeb3Input:        true,
                ResolutionType:     "ens",
                IsGatewayDomain:    true,
                Gateway:            "eth.link",
                AttributionWarning: "gateway-derived",
        }
        results := map[string]any{
                mapKeyWeb3: map[string]any{"dnslink_source": "ipfs"},
        }
        prov := buildAnalysisProvenance(InputKindENSName, ScopeGatewayDerived, web3, results)
        if prov["resolution_type"] != "ens" {
                t.Error("expected resolution_type=ens")
        }
        if prov["gateway_detected"] != true {
                t.Error("expected gateway_detected=true")
        }
        if prov["gateway"] != "eth.link" {
                t.Error("expected gateway=eth.link")
        }
        if prov["attribution_warning_emitted"] != true {
                t.Error("expected attribution_warning_emitted=true")
        }
        if prov["dnslink_source"] != "ipfs" {
                t.Error("expected dnslink_source=ipfs")
        }
}

func TestBuildAnalysisProvenance_SkipReason_C3(t *testing.T) {
        web3 := Web3ResolutionResult{}
        results := map[string]any{
                "skip_reason": "rate_limited",
        }
        prov := buildAnalysisProvenance(InputKindDNSDomain, ScopeOwnedDNS, web3, results)
        if prov["skip_reason"] != "rate_limited" {
                t.Error("expected skip_reason=rate_limited")
        }
}

func TestBuildGatewayPosture_Fields_C3(t *testing.T) {
        results := map[string]any{"analysis_scope": string(ScopeGatewayDerived)}
        posture := buildGatewayPosture(results)
        if posture["risk"] != "attribution_limited" {
                t.Error("expected risk=attribution_limited")
        }
        if posture["grade"] != "N/A" {
                t.Error("expected grade=N/A")
        }
        if posture["attribution_note"] == nil {
                t.Error("expected attribution_note")
        }
}

func TestBuildGatewaySkippedResults_AllKeys_C3(t *testing.T) {
        a := &Analyzer{}
        results := a.buildGatewaySkippedResults()
        for key := range emailProtocolKeys {
                r, ok := results[key].(map[string]any)
                if !ok {
                        t.Errorf("expected map for key %s", key)
                        continue
                }
                if r[mapKeyStatus] != "skipped" {
                        t.Errorf("expected status=skipped for %s", key)
                }
                if r["reason"] != "gateway_attribution" {
                        t.Errorf("expected reason=gateway_attribution for %s", key)
                }
        }
}

func TestDetectNullMX_Variants_C3(t *testing.T) {
        tests := []struct {
                name string
                mx   []string
                want bool
        }{
                {"zero only", []string{"0"}, true},
                {"zero dot", []string{"0."}, true},
                {"zero space dot", []string{"0 ."}, true},
                {"normal", []string{"10 mx.test.com"}, false},
                {"empty", nil, false},
                {"multi with null", []string{"10 mx.test.com", "0 ."}, true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        basic := map[string]any{"MX": tt.mx}
                        if got := detectNullMX(basic); got != tt.want {
                                t.Errorf("detectNullMX(%v) = %v, want %v", tt.mx, got, tt.want)
                        }
                })
        }
}

func TestBuildSectionStatus_AllTypes_C3(t *testing.T) {
        resultsMap := map[string]any{
                "spf":    map[string]any{mapKeyStatus: mapKeySuccess},
                "dmarc":  map[string]any{mapKeyStatus: "timeout"},
                "dkim":   map[string]any{mapKeyStatus: mapKeyError, mapKeyMessage: "lookup error"},
                "bimi":   map[string]any{mapKeyStatus: mapKeyError},
                "mta":    map[string]any{mapKeyStatus: "warning"},
                "nonmap": "stringval",
        }
        ss := buildSectionStatus(resultsMap)
        if len(ss) != 6 {
                t.Errorf("expected 6 section status entries, got %d", len(ss))
        }
        if bimi, ok := ss["bimi"].(map[string]any); ok {
                if bimi[mapKeyMessage] != "Lookup failed" {
                        t.Errorf("expected default message 'Lookup failed', got %v", bimi[mapKeyMessage])
                }
        }
}

func TestAdjustHostingSummary_NullMX_C3(t *testing.T) {
        results := map[string]any{
                mapKeyHostingSummary: map[string]any{mapKeyEmailHosting: "Unknown"},
                mapKeyIsNoMailDomain: false,
                mapKeyHasNullMx:      true,
        }
        adjustHostingSummary(results)
        hs := results[mapKeyHostingSummary].(map[string]any)
        if hs[mapKeyEmailHosting] != "No Mail Domain" {
                t.Errorf("expected 'No Mail Domain' for null MX, got %v", hs[mapKeyEmailHosting])
        }
}

func TestInferEmailFromDKIM_UnknownProvider_C3(t *testing.T) {
        hs := map[string]any{mapKeyEmailHosting: "Unknown"}
        results := map[string]any{mapKeyDkimAnalysis: map[string]any{"primary_provider": "Unknown"}}
        inferEmailFromDKIM(hs, results)
        if hs[mapKeyEmailHosting] != "Unknown" {
                t.Error("should not set email hosting to 'Unknown' from DKIM")
        }
}

func TestInferEmailFromDKIM_EmptyProvider_C3(t *testing.T) {
        hs := map[string]any{mapKeyEmailHosting: "Unknown"}
        results := map[string]any{mapKeyDkimAnalysis: map[string]any{"primary_provider": ""}}
        inferEmailFromDKIM(hs, results)
        if hs[mapKeyEmailHosting] != "Unknown" {
                t.Error("should not change for empty provider")
        }
}

func TestEnrichBasicRecords_PartialData_C3(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        resultsMap := map[string]any{
                mapKeyDmarc: map[string]any{mapKeyStatus: "error"},
        }
        enrichBasicRecords(basic, resultsMap)
        if basic["DMARC"] != nil {
                t.Error("expected no DMARC for error status")
        }
}

func TestEnrichBasicRecords_WarningDMARC_C3(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{
                mapKeyDmarc: map[string]any{mapKeyStatus: mapKeyWarning, "valid_records": []string{"v=DMARC1; p=none"}},
        }
        enrichBasicRecords(basic, resultsMap)
        if basic["DMARC"] == nil {
                t.Error("expected DMARC for warning status with valid_records")
        }
}

func TestEnrichMisplacedDMARC_NotDetected_C3(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=spf1 include:_spf.google.com ~all"},
        }
        resultsMap := map[string]any{
                mapKeyDmarc: map[string]any{mapKeyStatus: mapKeySuccess, mapKeyIssues: []string{}},
        }
        enrichMisplacedDMARC(basic, resultsMap)
        dmarc := resultsMap[mapKeyDmarc].(map[string]any)
        if dmarc["misplaced_dmarc"] != nil {
                t.Error("expected no misplaced_dmarc for non-DMARC TXT")
        }
}

func TestCheckDomainExists_ViaTXT_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddResponse("TXT", "example.com", []string{"v=spf1 ~all"})
        a := &Analyzer{DNS: mockDNS}
        exists, status, msg := a.checkDomainExists(context.Background(), "example.com")
        if !exists || status != "active" || msg != nil {
                t.Error("expected exists/active/nil for TXT records")
        }
}

func TestCheckDomainExists_ViaMX_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddResponse("MX", "example.com", []string{"10 mx.example.com"})
        a := &Analyzer{DNS: mockDNS}
        exists, status, _ := a.checkDomainExists(context.Background(), "example.com")
        if !exists || status != "active" {
                t.Error("expected exists/active for MX records")
        }
}

func TestBuildNonExistentResult_AllKeys_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        msg := "test message"
        result := a.buildNonExistentResult("nonexist.com", "undelegated", &msg)
        expectedKeys := []string{mapKeyDomain, "domain_exists", "domain_status", "domain_status_message", "section_status", mapKeyBasicRecords, "posture", "remediation"}
        for _, key := range expectedKeys {
                if _, ok := result[key]; !ok {
                        t.Errorf("missing key: %s", key)
                }
        }
}

func TestPopulateTTLReports_NilMaps_C3(t *testing.T) {
        results := map[string]any{}
        populateTTLReports(results)
        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix even with nil TTL maps")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report even with nil TTL maps")
        }
}

func TestExtractResolverAgreements_NoConsensus_C3(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 4,
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      false,
                                "resolver_count": 4,
                        },
                },
        }
        agreements, rc := extractResolverAgreements(consensus)
        if rc != 4 {
                t.Errorf("expected 4 resolvers, got %d", rc)
        }
        if len(agreements) != 1 {
                t.Fatalf("expected 1 agreement, got %d", len(agreements))
        }
        if agreements[0].Unanimous {
                t.Error("expected not unanimous")
        }
        if agreements[0].AgreeCount != 3 {
                t.Errorf("expected agree_count=3, got %d", agreements[0].AgreeCount)
        }
}

func TestDerefStr_Coverage_C3(t *testing.T) {
        s := "hello"
        if derefStr(&s) != "hello" {
                t.Error("expected hello")
        }
        if derefStr(nil) != nil {
                t.Error("expected nil")
        }
}
