//go:build coverage

package analyzer

import (
        "context"
        "testing"
)

func TestDetectNullMX_ZeroDot_C2(t *testing.T) {
        if !detectNullMX(map[string]any{"MX": []string{"0 ."}}) {
                t.Error("expected true for '0 .'")
        }
}

func TestDetectNullMX_ZeroTrailingDot_C2(t *testing.T) {
        if !detectNullMX(map[string]any{"MX": []string{"0."}}) {
                t.Error("expected true for '0.'")
        }
}

func TestDetectNullMX_NormalMX_C2(t *testing.T) {
        if detectNullMX(map[string]any{"MX": []string{"10 mx.example.com"}}) {
                t.Error("expected false for normal MX")
        }
}

func TestBuildPropagationStatus_Synced_C2(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        auth := map[string]any{"A": []string{"1.2.3.4"}}
        result := buildPropagationStatus(basic, auth)
        if a, ok := result["A"].(map[string]any); ok {
                if a[mapKeyStatus] != "synchronized" {
                        t.Errorf("expected synchronized, got %v", a[mapKeyStatus])
                }
        } else {
                t.Error("expected A entry")
        }
}

func TestBuildPropagationStatus_Diff_C2(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        auth := map[string]any{"A": []string{"5.6.7.8"}}
        result := buildPropagationStatus(basic, auth)
        if a, ok := result["A"].(map[string]any); ok {
                if a[mapKeyStatus] != "propagating" {
                        t.Errorf("expected propagating, got %v", a[mapKeyStatus])
                }
        }
}

func TestBuildPropagationStatus_NoAuth_C2(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        auth := map[string]any{}
        result := buildPropagationStatus(basic, auth)
        if a, ok := result["A"].(map[string]any); ok {
                if a[mapKeyStatus] != "unknown" {
                        t.Errorf("expected unknown, got %v", a[mapKeyStatus])
                }
        }
}

func TestBuildSectionStatus_C2(t *testing.T) {
        resultsMap := map[string]any{
                "spf":    map[string]any{mapKeyStatus: mapKeySuccess},
                "dmarc":  map[string]any{mapKeyStatus: "timeout"},
                "dkim":   map[string]any{mapKeyStatus: mapKeyError, mapKeyMessage: "lookup error"},
                "bimi":   map[string]any{mapKeyStatus: mapKeyError},
                "nonmap": "stringval",
        }
        ss := buildSectionStatus(resultsMap)
        if spf, ok := ss["spf"].(map[string]any); !ok || spf[mapKeyStatus] != "ok" {
                t.Error("expected spf=ok")
        }
        if dmarc, ok := ss["dmarc"].(map[string]any); !ok || dmarc[mapKeyStatus] != "timeout" {
                t.Error("expected dmarc=timeout")
        }
        if dkim, ok := ss["dkim"].(map[string]any); !ok || dkim[mapKeyStatus] != mapKeyError {
                t.Error("expected dkim=error")
        }
}

func TestGetMapResult_C2(t *testing.T) {
        m := map[string]any{"key": map[string]any{"inner": "val"}}
        got := getMapResult(m, "key")
        if got["inner"] != "val" {
                t.Error("expected inner=val")
        }
        got = getMapResult(m, "missing")
        if len(got) != 0 {
                t.Error("expected empty map for missing key")
        }
        m2 := map[string]any{"key": "not-a-map"}
        got = getMapResult(m2, "key")
        if len(got) != 0 {
                t.Error("expected empty map for non-map value")
        }
}

func TestGetOrDefault_C2(t *testing.T) {
        m := map[string]any{"key": "value"}
        got := getOrDefault(m, "key", map[string]any{"default": true})
        if got != "value" {
                t.Error("expected existing value")
        }
        got = getOrDefault(m, "missing", map[string]any{"default": true})
        defMap, ok := got.(map[string]any)
        if !ok || defMap["default"] != true {
                t.Error("expected default map")
        }
}

func TestExtractAndRemove_C2(t *testing.T) {
        m := map[string]any{"key": "val", "other": "keep"}
        got := extractAndRemove(m, "key")
        if got != "val" {
                t.Error("expected val")
        }
        if _, ok := m["key"]; ok {
                t.Error("expected key removed")
        }
}

func TestCountSlice_C2(t *testing.T) {
        if countSlice([]any{1, 2, 3}) != 3 {
                t.Error("expected 3 for []any")
        }
        if countSlice([]string{"a", "b"}) != 2 {
                t.Error("expected 2 for []string")
        }
        if countSlice([]map[string]any{{}, {}}) != 2 {
                t.Error("expected 2 for []map")
        }
        if countSlice("not a slice") != 0 {
                t.Error("expected 0 for non-slice")
        }
}

func TestToInt_C2(t *testing.T) {
        if toInt(42) != 42 {
                t.Error("int")
        }
        if toInt(int32(42)) != 42 {
                t.Error("int32")
        }
        if toInt(int64(42)) != 42 {
                t.Error("int64")
        }
        if toInt(42.0) != 42 {
                t.Error("float64")
        }
        if toInt("bad") != 0 {
                t.Error("non-numeric")
        }
}

func TestExtractResultMeta_C2(t *testing.T) {
        rc, err := extractResultMeta(map[string]any{"error": "test err", "records": []string{"a", "b"}})
        if rc != 2 {
                t.Errorf("expected recordCount=2, got %d", rc)
        }
        if err != "test err" {
                t.Errorf("expected error='test err', got %q", err)
        }

        rc, _ = extractResultMeta(map[string]any{"count": 5})
        if rc != 5 {
                t.Errorf("expected recordCount=5, got %d", rc)
        }

        rc, err = extractResultMeta("not-a-map")
        if rc != 0 || err != "" {
                t.Error("expected 0,empty for non-map")
        }
}

func TestBuildNonExistentResult_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        msg := "test message"
        result := a.buildNonExistentResult("example.com", "undelegated", &msg)
        if result[mapKeyDomain] != "example.com" {
                t.Error("expected domain")
        }
        if result["domain_exists"] != false {
                t.Error("expected domain_exists=false")
        }
}

func TestBuildNonExistentResult_NilMsg_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        result := a.buildNonExistentResult("example.com", "undelegated", nil)
        if result["domain_status_message"] != nil {
                t.Errorf("expected nil message, got %v", result["domain_status_message"])
        }
}

func TestCheckDomainExists_ViaA_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddResponse("A", "example.com", []string{"1.2.3.4"})
        a := &Analyzer{DNS: mockDNS}
        exists, status, msg := a.checkDomainExists(context.Background(), "example.com")
        if !exists || status != "active" || msg != nil {
                t.Error("expected exists/active/nil")
        }
}

func TestCheckDomainExists_ViaNS_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddResponse("NS", "example.com", []string{"ns1.example.com"})
        a := &Analyzer{DNS: mockDNS}
        exists, status, _ := a.checkDomainExists(context.Background(), "example.com")
        if !exists || status != "active" {
                t.Error("expected exists/active")
        }
}

func TestCheckDomainExists_NotExist_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        exists, status, msg := a.checkDomainExists(context.Background(), "nonexistent.invalid")
        if exists {
                t.Error("expected not exists")
        }
        if status != "undelegated" {
                t.Errorf("expected undelegated, got %s", status)
        }
        if msg == nil {
                t.Error("expected message")
        }
}

func TestPopulateTTLReports_FullData_C2(t *testing.T) {
        results := map[string]any{
                mapKeyResolverTtl: map[string]uint32{"A": 300, "MX": 3600},
                mapKeyAuthTtl:     map[string]uint32{"A": 300},
        }
        populateTTLReports(results)
        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report")
        }
}

func TestBuildRecordCurrencies_C2(t *testing.T) {
        ttls := map[string]uint32{"A": 300, "MX": 3600}
        records := buildRecordCurrencies(ttls)
        if len(records) != 2 {
                t.Errorf("expected 2 records, got %d", len(records))
        }
}

func TestBuildObservedTypes_C2(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"A": 300, "MX": 3600}
        observed := buildObservedTypes(resolver, auth)
        if len(observed) != 2 {
                t.Errorf("expected 2 types, got %d", len(observed))
        }
}

func TestExtractResolverAgreements_Empty_C2(t *testing.T) {
        agreements, rc := extractResolverAgreements(map[string]any{})
        if agreements != nil {
                t.Error("expected nil agreements")
        }
        if rc != 5 {
                t.Errorf("expected 5 default resolvers, got %d", rc)
        }
}

func TestExtractResolverAgreements_WithPerRecord_C2(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 3,
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      true,
                                "resolver_count": 3,
                        },
                        "MX": map[string]any{
                                "consensus":      false,
                                "resolver_count": 3,
                        },
                        "bad": "not-a-map",
                },
        }
        agreements, rc := extractResolverAgreements(consensus)
        if rc != 3 {
                t.Errorf("expected 3 resolvers, got %d", rc)
        }
        if len(agreements) != 2 {
                t.Errorf("expected 2 agreements, got %d", len(agreements))
        }
}

func TestAdjustHostingSummary_NoMail_C2(t *testing.T) {
        results := map[string]any{
                mapKeyHostingSummary: map[string]any{mapKeyEmailHosting: "Unknown"},
                mapKeyIsNoMailDomain: true,
                mapKeyHasNullMx:      false,
        }
        adjustHostingSummary(results)
        hs := results[mapKeyHostingSummary].(map[string]any)
        if hs[mapKeyEmailHosting] != "No Mail Domain" {
                t.Errorf("expected 'No Mail Domain', got %v", hs[mapKeyEmailHosting])
        }
}

func TestAdjustHostingSummary_InferDKIM_C2(t *testing.T) {
        results := map[string]any{
                mapKeyHostingSummary: map[string]any{mapKeyEmailHosting: "Unknown"},
                mapKeyIsNoMailDomain: false,
                mapKeyHasNullMx:      false,
                mapKeyDkimAnalysis:   map[string]any{"primary_provider": "Google Workspace"},
        }
        adjustHostingSummary(results)
        hs := results[mapKeyHostingSummary].(map[string]any)
        if hs[mapKeyEmailHosting] != "Google Workspace" {
                t.Errorf("expected 'Google Workspace', got %v", hs[mapKeyEmailHosting])
        }
}

func TestAdjustHostingSummary_NoHostingSummary_C2(t *testing.T) {
        results := map[string]any{}
        adjustHostingSummary(results)
}

func TestAdjustHostingSummary_AlreadyKnown_C2(t *testing.T) {
        results := map[string]any{
                mapKeyHostingSummary: map[string]any{mapKeyEmailHosting: "Microsoft 365"},
                mapKeyIsNoMailDomain: false,
        }
        adjustHostingSummary(results)
        hs := results[mapKeyHostingSummary].(map[string]any)
        if hs[mapKeyEmailHosting] != "Microsoft 365" {
                t.Error("should not override known provider")
        }
}

func TestInferEmailFromDKIM_NoDKIM_C2(t *testing.T) {
        hs := map[string]any{mapKeyEmailHosting: "Unknown"}
        results := map[string]any{}
        inferEmailFromDKIM(hs, results)
        if hs[mapKeyEmailHosting] != "Unknown" {
                t.Error("should not change without DKIM")
        }
}

func TestInferEmailFromDKIM_WithExistingConfidence_C2(t *testing.T) {
        hs := map[string]any{
                mapKeyEmailHosting: "Unknown",
                "email_confidence":  map[string]any{"level": "confirmed"},
        }
        results := map[string]any{mapKeyDkimAnalysis: map[string]any{"primary_provider": "Google Workspace"}}
        inferEmailFromDKIM(hs, results)
        ec, _ := hs["email_confidence"].(map[string]any)
        if ec["level"] != "confirmed" {
                t.Error("should preserve existing confidence")
        }
}

func TestEnrichBasicRecords_C2(t *testing.T) {
        basic := map[string]any{"A": []string{"1.2.3.4"}}
        resultsMap := map[string]any{
                mapKeyDmarc:  map[string]any{mapKeyStatus: mapKeySuccess, "valid_records": []string{"v=DMARC1; p=reject"}},
                mapKeyMtaSts: map[string]any{"record": "v=STSv1; id=abc"},
                mapKeyTlsrpt: map[string]any{"record": "v=TLSRPTv1; rua=mailto:t@example.com"},
        }
        enrichBasicRecords(basic, resultsMap)
        if basic["DMARC"] == nil {
                t.Error("expected DMARC in basic")
        }
        if basic["MTA-STS"] == nil {
                t.Error("expected MTA-STS in basic")
        }
        if basic["TLS-RPT"] == nil {
                t.Error("expected TLS-RPT in basic")
        }
}

func TestEnrichMisplacedDMARC_C2(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject; rua=mailto:d@example.com"},
        }
        resultsMap := map[string]any{
                mapKeyDmarc: map[string]any{mapKeyStatus: mapKeySuccess, mapKeyIssues: []string{}},
        }
        enrichMisplacedDMARC(basic, resultsMap)
        dmarc := resultsMap[mapKeyDmarc].(map[string]any)
        if dmarc["misplaced_dmarc"] == nil {
                t.Error("expected misplaced_dmarc annotation")
        }
}

func TestEnrichMisplacedDMARC_NoDMARCResult_C2(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{
                mapKeyDmarc: "not-a-map",
        }
        enrichMisplacedDMARC(basic, resultsMap)
}

func TestBuildGatewaySkippedResults_C2(t *testing.T) {
        a := &Analyzer{}
        results := a.buildGatewaySkippedResults()
        for key := range emailProtocolKeys {
                r, ok := results[key].(map[string]any)
                if !ok {
                        t.Errorf("expected map for key %s", key)
                        continue
                }
                if r[mapKeyStatus] != "skipped" {
                        t.Errorf("expected status=skipped for %s, got %v", key, r[mapKeyStatus])
                }
        }
}

func TestMakeStringSet_C2(t *testing.T) {
        set := makeStringSet([]string{"a", "b", "a"})
        if len(set) != 2 {
                t.Errorf("expected 2 unique items, got %d", len(set))
        }
}

func TestKeysOf_C2(t *testing.T) {
        keys := keysOf(map[string]bool{"a": true, "b": true})
        if len(keys) != 2 {
                t.Errorf("expected 2 keys, got %d", len(keys))
        }
}

func TestDerefStr_Nil_C2(t *testing.T) {
        got := derefStr(nil)
        if got != nil {
                t.Errorf("expected nil, got %v", got)
        }
}

func TestDerefStr_Value_C2(t *testing.T) {
        s := "hello"
        got := derefStr(&s)
        if got != "hello" {
                t.Errorf("expected 'hello', got %v", got)
        }
}
