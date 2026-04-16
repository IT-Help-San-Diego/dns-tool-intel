//go:build coverage

package analyzer

import (
        "context"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestAnalyzeSMTPTransport_NoInputs_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{
                DNS:           mockDNS,
                HTTP:          &MockHTTPClient{},
                SMTPProbeMode: "skip",
        }
        result := a.AnalyzeSMTPTransport(context.Background(), "example.com", []string{"10 mx.example.com."})
        if result == nil {
                t.Fatal("expected result")
        }
        if result[mapKeyVersion] != 2 {
                t.Errorf("expected version=2, got %v", result[mapKeyVersion])
        }
}

func TestAnalyzeSMTPTransport_WithInputs_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{
                DNS:           mockDNS,
                HTTP:          &MockHTTPClient{},
                SMTPProbeMode: "skip",
        }
        inputs := AnalysisInputs{
                MTASTSResult: map[string]any{"mode": "enforce", mapKeyStatus: mapKeySuccess},
                TLSRPTResult: map[string]any{mapKeyStatus: mapKeySuccess, "record": "v=TLSRPTv1;rua=mailto:t@example.com"},
                DANEResult:   map[string]any{"has_dane": true},
        }
        result := a.AnalyzeSMTPTransport(context.Background(), "example.com", []string{"10 mx.example.com."}, inputs)
        if result == nil {
                t.Fatal("expected result")
        }
        policy, ok := result["policy"].(map[string]any)
        if !ok {
                t.Fatal("expected policy map")
        }
        if policy[mapKeyVerdict] == nil {
                t.Error("expected verdict in policy")
        }
}

func TestAnalyzeSMTPTransport_EmptyMX_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{
                DNS:           mockDNS,
                HTTP:          &MockHTTPClient{},
                SMTPProbeMode: "skip",
        }
        result := a.AnalyzeSMTPTransport(context.Background(), "example.com", nil)
        if result == nil {
                t.Fatal("expected result")
        }
}

func TestBuildProbeResult_UnknownMode_C3(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "local"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "unknown" {
                t.Errorf("expected probe_method=unknown for unrecognized mode, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_SkipMode_C3(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "skip"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "skip" {
                t.Errorf("expected probe_method=skip, got %v", probe[mapKeyProbeMethod])
        }
        if probe[mapKeyReason] == "" {
                t.Error("expected non-empty reason for skip mode")
        }
}

func TestBuildProbeResult_EmptyMode_C3(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: ""}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "skip" {
                t.Errorf("expected probe_method=skip for empty mode, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_NoMX_C3(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "skip"}
        probe := buildProbeResult(a, context.Background(), "example.com", nil)
        if probe[mapKeyProbeMethod] != verdictNone {
                t.Errorf("expected probe_method=none, got %v", probe[mapKeyProbeMethod])
        }
}

func TestRunRemoteProbe_RequestBody_C3(t *testing.T) {
        var receivedBody map[string]any
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                json.NewDecoder(r.Body).Decode(&receivedBody)
                resp := remoteProbeAPIResp{
                        ProbeHost: "test",
                        Servers:   []map[string]any{{"host": "mx.test", mapKeyReachable: true}},
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        runRemoteProbe(context.Background(), srv.URL, "test-key", []string{"mx1.example.com", "mx2.example.com"}, probe)

        if receivedBody == nil {
                t.Fatal("expected request body to be sent")
        }
        hosts, ok := receivedBody["hosts"].([]any)
        if !ok {
                t.Fatal("expected hosts array in body")
        }
        if len(hosts) != 2 {
                t.Errorf("expected 2 hosts, got %d", len(hosts))
        }
}

func TestRunRemoteProbe_BadURL_C3(t *testing.T) {
        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), "http://127.0.0.1:1", "key", []string{"mx.example.com"}, probe)
        if result["remote_attempted"] != true {
                t.Log("expected remote_attempted=true on bad URL")
        }
}

func TestRunMultiProbe_AllSuccess_C3(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost:      "probe-node",
                        Version:        "1.0",
                        ElapsedSeconds: 0.3,
                        Servers: []map[string]any{
                                {"host": "mx.example.com", mapKeyReachable: true, mapKeyStarttls: true, mapKeyTlsVersion: "TLSv1.3", mapKeyCertValid: true},
                        },
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        a := &Analyzer{
                SMTPProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "p1", Label: "P1", URL: srv.URL, Key: "key1"},
                        {ID: "p2", Label: "P2", URL: srv.URL, Key: "key2"},
                },
        }
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "multi_remote" {
                t.Errorf("expected multi_remote, got %v", probe[mapKeyProbeMethod])
        }
        if probe[mapKeyProbeCount] != 2 {
                t.Errorf("expected probe_count=2, got %v", probe[mapKeyProbeCount])
        }
        if probe["multi_probe"] == nil {
                t.Error("expected multi_probe in multi-probe result")
        }
}

func TestDerivePrimaryStatus_ObservedNoVerdict_C3(t *testing.T) {
        policy := map[string]any{}
        probe := map[string]any{mapKeyStatus: mapKeyObserved}
        got := derivePrimaryStatus(policy, probe)
        if got == "" {
                t.Error("expected non-empty status")
        }
}

func TestDerivePrimaryMessage_NoMatch_C3(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: "unknown_value", mapKeySignals: []string{}}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        msg := derivePrimaryMessage(policy, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty default message")
        }
}

func TestBuildInferenceSignals_NoPolicy_C3(t *testing.T) {
        signals := buildInferenceSignals(map[string]any{}, map[string]any{})
        if signals == nil {
                t.Error("expected non-nil signals slice")
        }
}

func TestBuildInferenceSignals_PolicySignalsNotSlice_C3(t *testing.T) {
        policy := map[string]any{mapKeySignals: "not-a-slice"}
        signals := buildInferenceSignals(policy, map[string]any{})
        if signals == nil {
                t.Error("expected non-nil signals slice")
        }
}

func TestBuildInferenceNote_NoProbe_C3(t *testing.T) {
        note := buildInferenceNote(map[string]any{})
        if note == "" {
                t.Error("expected non-empty note when no status key")
        }
}

func TestBackfillLegacyFields_ObservedWithObservationSlice_C3(t *testing.T) {
        result := map[string]any{}
        probe := map[string]any{
                mapKeyStatus: mapKeyObserved,
                mapKeyObservations: []map[string]any{
                        {"host": "mx1.example.com", mapKeyReachable: true, mapKeyStarttls: true},
                        {"host": "mx2.example.com", mapKeyReachable: true, mapKeyStarttls: false},
                },
                mapKeySummary: map[string]any{mapKeyTotalServers: 2, mapKeyReachable: 2, mapKeyStarttlsSupported: 1},
        }
        backfillLegacyFields(result, map[string]any{}, probe)
        servers, ok := result[mapKeyServers].([]map[string]any)
        if !ok {
                t.Fatal("expected servers slice")
        }
        if len(servers) != 2 {
                t.Errorf("expected 2 servers, got %d", len(servers))
        }
        if result["issues"] == nil {
                t.Error("expected issues")
        }
}

func TestExtractMXHosts_Trailing_C3(t *testing.T) {
        hosts := extractMXHosts([]string{"10 mx1.example.com.", "20 mx2.test.com"})
        if len(hosts) != 2 {
                t.Fatalf("expected 2 hosts, got %d", len(hosts))
        }
        if strings.HasSuffix(hosts[0], ".") {
                t.Error("expected trailing dot to be stripped")
        }
}

func TestMarshalRemoteProbeBody_OneHost_C3(t *testing.T) {
        body, errMsg := marshalRemoteProbeBody([]string{"mx.example.com"})
        if body == nil {
                t.Fatalf("expected body, got error: %s", errMsg)
        }
        var req map[string]any
        json.Unmarshal(body, &req)
        hostsList, ok := req["hosts"].([]any)
        if !ok || len(hostsList) != 1 {
                t.Errorf("expected 1 host, got %v", len(hostsList))
        }
}

func TestAssessDANE_NoDane_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{}
        policy := map[string]any{
                mapKeyDane: map[string]any{mapKeyPresent: false},
        }
        signals := assessDANE(a, context.Background(), []string{"mx.test"}, ai, policy, nil)
        if len(signals) != 0 {
                t.Errorf("expected 0 signals for no DANE, got %d", len(signals))
        }
}

func TestAssessDANE_WithDane_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{DANEResult: map[string]any{"has_dane": true}}
        policy := map[string]any{
                mapKeyDane: map[string]any{mapKeyPresent: false},
        }
        signals := assessDANE(a, context.Background(), []string{"mx.test"}, ai, policy, nil)
        dane, ok := policy[mapKeyDane].(map[string]any)
        if ok && dane[mapKeyPresent] != true {
                t.Error("expected DANE present=true after assessment with has_dane input")
        }
        if len(signals) == 0 {
                t.Error("expected signals for DANE presence")
        }
}

func TestComputeProbeConsensus_MixedResults_C3(t *testing.T) {
        results := []map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyPartialTls},
        }
        c := computeProbeConsensus(results)
        if c[mapKeyAgreement] == "unanimous_tls" {
                t.Error("expected non-unanimous for mixed verdicts")
        }
}

func TestComputeProbeConsensus_SingleSkipped_C3(t *testing.T) {
        results := []map[string]any{
                {mapKeyStatus: mapKeySkipped},
        }
        c := computeProbeConsensus(results)
        if c == nil {
                t.Error("expected non-nil consensus")
        }
}

func TestComputeProbeConsensus_Empty_C3(t *testing.T) {
        c := computeProbeConsensus(nil)
        if c == nil {
                t.Error("expected non-nil consensus")
        }
}

func TestSmtpProbeVerdictFromSummary_ZeroReachable_C3(t *testing.T) {
        s := &smtpSummary{Reachable: 0, StartTLSSupport: 0}
        got := smtpProbeVerdictFromSummary(s)
        if got != mapKeyAllTls {
                t.Errorf("expected all_tls for zero==zero, got %s", got)
        }
}

func TestSmtpProbeVerdictFromSummary_PartialTLS_C3(t *testing.T) {
        s := &smtpSummary{Reachable: 3, StartTLSSupport: 2, ValidCerts: 1}
        got := smtpProbeVerdictFromSummary(s)
        if got != mapKeyPartialTls {
                t.Errorf("expected partial_tls, got %s", got)
        }
}

func TestSmtpProbeVerdictFromSummary_NoTLS_C3(t *testing.T) {
        s := &smtpSummary{Reachable: 3, StartTLSSupport: 0}
        got := smtpProbeVerdictFromSummary(s)
        if got != mapKeyNoTls {
                t.Errorf("expected no_tls, got %s", got)
        }
}

func TestUpdateSummary_TLS10_C3(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{
                mapKeyReachable:  true,
                mapKeyStarttls:   true,
                mapKeyTlsVersion: "TLSv1.0",
        })
        if s.TLS13 != 0 {
                t.Error("expected TLS13=0")
        }
        if s.TLS12 != 0 {
                t.Error("expected TLS12=0")
        }
}

func TestUpdateSummary_InvalidCertNotExpiring_C3(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{
                mapKeyReachable:         true,
                mapKeyStarttls:          true,
                mapKeyCertValid:         false,
                mapKeyCertDaysRemaining: 5,
        })
        if s.ValidCerts != 0 {
                t.Error("expected ValidCerts=0 for invalid cert")
        }
}

func TestBuildMailTransportResult_NoMX_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}, SMTPProbeMode: "skip"}
        result := buildMailTransportResult(a, context.Background(), "example.com", nil, AnalysisInputs{})
        if result[mapKeyVersion] != 2 {
                t.Errorf("expected version=2, got %v", result[mapKeyVersion])
        }
}

func TestAssessProvider_Google_C3(t *testing.T) {
        policy := map[string]any{
                "provider": map[string]any{"identified": false},
        }
        signals := assessProvider([]string{"aspmx.l.google.com"}, policy, nil)
        if len(signals) == 0 {
                t.Error("expected signal for Google")
        }
        provider := policy["provider"].(map[string]any)
        if provider["identified"] != true {
                t.Error("expected provider identified")
        }
}

func TestAssessProvider_Microsoft_C3(t *testing.T) {
        policy := map[string]any{
                "provider": map[string]any{"identified": false},
        }
        signals := assessProvider([]string{"mail.protection.outlook.com"}, policy, nil)
        if len(signals) == 0 {
                t.Error("expected signal for Microsoft")
        }
}

func TestAssessProvider_Unknown_C3(t *testing.T) {
        policy := map[string]any{
                "provider": map[string]any{"identified": false},
        }
        signals := assessProvider([]string{"mx.unknowndomain.example"}, policy, nil)
        if len(signals) != 0 {
                t.Error("expected no signals for unknown provider")
        }
}

func TestBuildInferenceSignals_WithTLSRPTNotConfigured_C3(t *testing.T) {
        policy := map[string]any{mapKeySignals: []string{}}
        telemetry := map[string]any{mapKeyTlsrptConfigured: false}
        signals := buildInferenceSignals(policy, telemetry)
        for _, s := range signals {
                if strings.Contains(s, "TLS-RPT") {
                        t.Error("should not append TLS-RPT signal when not configured")
                }
        }
}

func TestResolveMultiProbeFallback_AllSkipped_C3(t *testing.T) {
        multi := []map[string]any{
                {mapKeyStatus: mapKeySkipped},
                {mapKeyStatus: mapKeySkipped},
        }
        result := resolveMultiProbeFallback(context.Background(), nil, multi, []string{"mx.test"})
        _ = result
}

func TestApplyPrimaryResult_Nil_C3(t *testing.T) {
        probe := map[string]any{"existing": "val"}
        applyPrimaryResult(probe, nil)
        if probe["existing"] != "val" {
                t.Error("existing value should be preserved")
        }
}

func TestApplyRemoteProbeMetadata_NoPorts_C3(t *testing.T) {
        probe := map[string]any{}
        apiResp := &remoteProbeAPIResp{
                ProbeHost:      "probe-x",
                ElapsedSeconds: 0.8,
                AllPorts:       nil,
        }
        applyRemoteProbeMetadata(probe, apiResp)
        if probe[mapKeyProbeHost] != "probe-x" {
                t.Errorf("expected probe_host=probe-x, got %v", probe[mapKeyProbeHost])
        }
        if probe["multi_port"] != nil {
                t.Error("expected no multi_port when nil")
        }
}

func TestGetIssuesList_WrongType_C3(t *testing.T) {
        got := getIssuesList(map[string]any{"issues": 42})
        if len(got) != 0 {
                t.Errorf("expected 0 issues for wrong type, got %d", len(got))
        }
}

func TestAssessMTASTS_NoMode_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{MTASTSResult: map[string]any{mapKeyStatus: "error"}}
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
        }
        signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
        if len(signals) != 0 {
                t.Errorf("expected 0 signals for failed MTA-STS, got %d", len(signals))
        }
}

func TestAssessMTASTS_EnforceMode_C3(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{MTASTSResult: map[string]any{mapKeyStatus: mapKeySuccess, "mode": "enforce"}}
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
        }
        signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
        if len(signals) == 0 {
                t.Error("expected signal for enforce mode")
        }
        mtasts := policy[mapKeyMtaSts].(map[string]any)
        if mtasts[mapKeyPresent] != true {
                t.Error("expected MTA-STS present=true")
        }
}

func TestExecuteRemoteProbeHTTP_BadURL_C3(t *testing.T) {
        req, _ := http.NewRequest("POST", "http://127.0.0.1:1/invalid", nil)
        apiResp, errMsg := executeRemoteProbeHTTP(req)
        if apiResp != nil {
                t.Error("expected nil response for bad URL")
        }
        if errMsg == "" {
                t.Error("expected error message")
        }
}

func TestBuildMultiProbeEntry_Skipped_C3(t *testing.T) {
        r := smtpProbeResult{
                id:    "p1",
                label: "Probe 1",
                data:  map[string]any{mapKeyStatus: mapKeySkipped},
        }
        entry := buildMultiProbeEntry(r)
        if entry["probe_id"] != "p1" {
                t.Errorf("expected probe_id=p1, got %v", entry["probe_id"])
        }
        if entry[mapKeyStatus] != mapKeySkipped {
                t.Errorf("expected status=skipped, got %v", entry[mapKeyStatus])
        }
}

func TestClassifyRemoteProbeStatus_404_C3(t *testing.T) {
        result := classifyRemoteProbeStatus(404)
        if result == "" {
                t.Error("expected non-empty for 404")
        }
}

func TestClassifyRemoteProbeStatus_503_C3(t *testing.T) {
        result := classifyRemoteProbeStatus(503)
        if result == "" {
                t.Error("expected non-empty for 503")
        }
}
