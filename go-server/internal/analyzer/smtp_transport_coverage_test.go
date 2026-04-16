//go:build coverage

package analyzer

import (
        "bytes"
        "context"
        "encoding/json"
        "io"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestBuildProbeResult_NoMX(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "skip"}
        probe := buildProbeResult(a, context.Background(), "example.com", nil)
        if probe[mapKeyReason] != "No MX records found for this domain" {
                t.Errorf("unexpected reason: %v", probe[mapKeyReason])
        }
        if probe[mapKeyProbeMethod] != verdictNone {
                t.Errorf("expected probe_method=none, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_SkipMode(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "skip"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "skip" {
                t.Errorf("expected probe_method=skip, got %v", probe[mapKeyProbeMethod])
        }
        if probe[mapKeyStatus] != mapKeySkipped {
                t.Errorf("expected status=skipped, got %v", probe[mapKeyStatus])
        }
}

func TestBuildProbeResult_EmptyMode(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: ""}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "skip" {
                t.Errorf("expected probe_method=skip, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_RemoteMisconfigured(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "remote", ProbeAPIURL: "", Probes: nil}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "remote_misconfigured" {
                t.Errorf("expected probe_method=remote_misconfigured, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_UnknownMode(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "banana"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "unknown" {
                t.Errorf("expected probe_method=unknown, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_RemoteSingleProbe(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost:      "test-probe",
                        Version:        "1.0",
                        ElapsedSeconds: 0.5,
                        Servers: []map[string]any{
                                {"host": "mx.example.com", mapKeyReachable: true, mapKeyStarttls: true, mapKeyTlsVersion: "TLSv1.3", mapKeyCertValid: true},
                        },
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        a := &Analyzer{
                SMTPProbeMode: "remote",
                ProbeAPIURL:   srv.URL,
                ProbeAPIKey:   "testkey",
        }
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyStatus] != mapKeyObserved {
                t.Errorf("expected status=observed, got %v", probe[mapKeyStatus])
        }
        if probe[mapKeyProbeHost] != "test-probe" {
                t.Errorf("expected probe_host=test-probe, got %v", probe[mapKeyProbeHost])
        }
}

func TestBuildProbeResult_RemoteMultiProbe(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost:      "test-probe",
                        Version:        "1.0",
                        ElapsedSeconds: 0.5,
                        Servers: []map[string]any{
                                {"host": "mx.example.com", mapKeyReachable: true, mapKeyStarttls: true},
                        },
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        a := &Analyzer{
                SMTPProbeMode: "remote",
                Probes: []ProbeEndpoint{
                        {ID: "probe1", Label: "Probe 1", URL: srv.URL, Key: "key1"},
                        {ID: "probe2", Label: "Probe 2", URL: srv.URL, Key: "key2"},
                },
        }
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        if probe[mapKeyProbeMethod] != "multi_remote" {
                t.Errorf("expected probe_method=multi_remote, got %v", probe[mapKeyProbeMethod])
        }
        if probe[mapKeyProbeCount] != 2 {
                t.Errorf("expected probe_count=2, got %v", probe[mapKeyProbeCount])
        }
}

func TestBuildMailTransportResult_Coverage(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{
                DNS:           mockDNS,
                HTTP:          &MockHTTPClient{},
                SMTPProbeMode: "skip",
        }

        result := buildMailTransportResult(a, context.Background(), "example.com", []string{"mx.example.com"}, AnalysisInputs{})
        if result[mapKeyVersion] != 2 {
                t.Errorf("expected version=2, got %v", result[mapKeyVersion])
        }
        for _, key := range []string{"policy", "probe", "telemetry", mapKeyStatus, "message", "dns_inferred", "inference_note", "inference_signals", mapKeyServers, mapKeySummary, "issues"} {
                if _, ok := result[key]; !ok {
                        t.Errorf("missing key: %s", key)
                }
        }
}

func TestRemoteProbeFailover_Coverage(t *testing.T) {
        ctx := context.Background()
        probe := map[string]any{}
        result := remoteProbeFailover(ctx, []string{"mx.example.com"}, probe, "test error")
        if result["remote_attempted"] != true {
                t.Error("expected remote_attempted=true")
        }
        if result["remote_error"] != "test error" {
                t.Errorf("expected remote_error='test error', got %v", result["remote_error"])
        }
}

func TestRunRemoteProbe_ServerError(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        if result["remote_attempted"] != true {
                t.Logf("result: %v", result)
        }
}

func TestRunRemoteProbe_RateLimited(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusTooManyRequests)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        _ = result
}

func TestRunRemoteProbe_Unauthorized(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusUnauthorized)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        _ = result
}

func TestRunRemoteProbe_EmptyServers(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                json.NewEncoder(w).Encode(remoteProbeAPIResp{
                        ProbeHost: "test",
                        Servers:   []map[string]any{},
                })
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        _ = result
}

func TestRunRemoteProbe_InvalidJSON(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("not json"))
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        _ = result
}

func TestRunRemoteProbe_UnreachableServers(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost: "test-probe",
                        Version:   "1.0",
                        Servers: []map[string]any{
                                {"host": "mx.example.com", mapKeyReachable: false},
                        },
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx.example.com"}, probe)
        if result[mapKeyStatus] != mapKeySkipped {
                t.Errorf("expected status=skipped for unreachable servers, got %v", result[mapKeyStatus])
        }
}

func TestRunRemoteProbe_AllReachable(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost:      "test-probe",
                        Version:        "1.0",
                        ElapsedSeconds: 1.5,
                        Servers: []map[string]any{
                                {"host": "mx1.example.com", mapKeyReachable: true, mapKeyStarttls: true, mapKeyTlsVersion: "TLSv1.3", mapKeyCertValid: true},
                                {"host": "mx2.example.com", mapKeyReachable: true, mapKeyStarttls: true, mapKeyTlsVersion: "TLSv1.2", mapKeyCertValid: true},
                        },
                        AllPorts: []map[string]any{
                                {"host": "mx1.example.com", "port": 465, mapKeyReachable: true},
                        },
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        probe := make(map[string]any)
        result := runRemoteProbe(context.Background(), srv.URL, "key", []string{"mx1.example.com", "mx2.example.com"}, probe)
        if result[mapKeyStatus] != mapKeyObserved {
                t.Errorf("expected status=observed, got %v", result[mapKeyStatus])
        }
}

func TestMarshalRemoteProbeBody_TooManyHosts(t *testing.T) {
        hosts := make([]string, 10)
        for i := range hosts {
                hosts[i] = "mx.example.com"
        }
        body, errMsg := marshalRemoteProbeBody(hosts)
        if body == nil {
                t.Fatal("expected body")
        }
        if errMsg != "" {
                t.Errorf("unexpected error: %s", errMsg)
        }
        var req map[string]any
        json.Unmarshal(body, &req)
        hostsList, ok := req["hosts"].([]any)
        if !ok || len(hostsList) != 5 {
                t.Errorf("expected 5 hosts (capped), got %v", len(hostsList))
        }
}

func TestRunLiveProbe_NoReachable(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping live probe test in short mode")
        }
        ctx, cancel := context.WithTimeout(context.Background(), 3*1e9)
        defer cancel()
        probe := make(map[string]any)
        result := runLiveProbe(ctx, []string{"unreachable.invalid"}, probe)
        if result[mapKeyStatus] != mapKeySkipped {
                t.Logf("expected skipped for unreachable host: %v", result[mapKeyStatus])
        }
}

func TestCollectMultiProbeResults_Coverage(t *testing.T) {
        probes := []ProbeEndpoint{
                {ID: "p1", Label: "Probe 1"},
                {ID: "p2", Label: "Probe 2"},
        }
        results := make(chan smtpProbeResult, 2)
        results <- smtpProbeResult{id: "p1", label: "Probe 1", data: map[string]any{mapKeyStatus: mapKeySkipped}}
        results <- smtpProbeResult{id: "p2", label: "Probe 2", data: map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls}}

        multi, primary := collectMultiProbeResults(probes, results)
        if len(multi) != 2 {
                t.Errorf("expected 2 results, got %d", len(multi))
        }
        if primary == nil {
                t.Error("expected primary result from observed probe")
        }
}

func TestCollectMultiProbeResults_NoneObserved(t *testing.T) {
        probes := []ProbeEndpoint{
                {ID: "p1", Label: "Probe 1"},
        }
        results := make(chan smtpProbeResult, 1)
        results <- smtpProbeResult{id: "p1", label: "Probe 1", data: map[string]any{mapKeyStatus: mapKeySkipped}}

        _, primary := collectMultiProbeResults(probes, results)
        if primary != nil {
                t.Error("expected nil primary when none observed")
        }
}

func TestResolveMultiProbeFallback_NoResults(t *testing.T) {
        result := resolveMultiProbeFallback(context.Background(), nil, nil, nil)
        if result != nil {
                t.Error("expected nil for empty inputs")
        }
}

func TestResolveMultiProbeFallback_OneObserved(t *testing.T) {
        multi := []map[string]any{{mapKeyStatus: mapKeyObserved}}
        result := resolveMultiProbeFallback(context.Background(), nil, multi, nil)
        if result != nil {
                t.Error("expected nil when observed exists")
        }
}

func TestHandlePartialResponse_Coverage(t *testing.T) {
        t.Run("with data", func(t *testing.T) {
                var b strings.Builder
                b.WriteString("220 hello")
                resp, _ := handlePartialResponse(b, io.EOF)
                if resp == "" {
                        t.Error("expected non-empty response")
                }
        })
        t.Run("empty", func(t *testing.T) {
                var b strings.Builder
                _, err := handlePartialResponse(b, io.EOF)
                if err == nil {
                        t.Error("expected error for empty response")
                }
        })
}

func TestReadRemoteProbeBody_Success(t *testing.T) {
        data := remoteProbeAPIResp{
                ProbeHost: "host",
                Servers:   []map[string]any{{"host": "mx.test"}},
        }
        body, _ := json.Marshal(data)
        resp := &http.Response{
                Body: io.NopCloser(bytes.NewReader(body)),
        }
        apiResp, errMsg := readRemoteProbeBody(resp)
        if apiResp == nil {
                t.Fatalf("expected response, got error: %s", errMsg)
        }
        if apiResp.ProbeHost != "host" {
                t.Errorf("expected host='host', got %s", apiResp.ProbeHost)
        }
}

func TestReadRemoteProbeBody_InvalidJSON(t *testing.T) {
        resp := &http.Response{
                Body: io.NopCloser(bytes.NewReader([]byte("not json"))),
        }
        apiResp, errMsg := readRemoteProbeBody(resp)
        if apiResp != nil {
                t.Error("expected nil for invalid JSON")
        }
        if errMsg == "" {
                t.Error("expected error message")
        }
}

func TestReadRemoteProbeBody_EmptyServers(t *testing.T) {
        data := remoteProbeAPIResp{ProbeHost: "host", Servers: []map[string]any{}}
        body, _ := json.Marshal(data)
        resp := &http.Response{
                Body: io.NopCloser(bytes.NewReader(body)),
        }
        apiResp, errMsg := readRemoteProbeBody(resp)
        if apiResp != nil {
                t.Error("expected nil for empty servers")
        }
        if errMsg == "" {
                t.Error("expected error message for empty servers")
        }
}

func TestExecuteRemoteProbeHTTP_Success(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                resp := remoteProbeAPIResp{
                        ProbeHost: "test",
                        Servers:   []map[string]any{{"host": "mx.test"}},
                }
                json.NewEncoder(w).Encode(resp)
        }))
        defer srv.Close()

        req, _ := http.NewRequest("POST", srv.URL, nil)
        apiResp, errMsg := executeRemoteProbeHTTP(req)
        if apiResp == nil {
                t.Fatalf("expected response, got error: %s", errMsg)
        }
}

func TestBackfillLegacyFields_Observed_Coverage(t *testing.T) {
        result := map[string]any{}
        probe := map[string]any{
                mapKeyStatus:       mapKeyObserved,
                mapKeyObservations: []map[string]any{{"host": "mx1"}},
                mapKeySummary:      map[string]any{mapKeyTotalServers: 1},
        }
        backfillLegacyFields(result, map[string]any{}, probe)
        if result[mapKeyServers] == nil {
                t.Error("expected servers")
        }
        if result[mapKeySummary] == nil {
                t.Error("expected summary")
        }
        if result["issues"] == nil {
                t.Error("expected issues")
        }
}

func TestBackfillLegacyFields_NotObserved_Coverage(t *testing.T) {
        result := map[string]any{}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        backfillLegacyFields(result, map[string]any{}, probe)
        servers, ok := result[mapKeyServers].([]map[string]any)
        if !ok || len(servers) != 0 {
                t.Error("expected empty servers slice")
        }
}

func TestBackfillLegacyFields_ObservedNoSummary_Cov(t *testing.T) {
        result := map[string]any{}
        probe := map[string]any{
                mapKeyStatus:       mapKeyObserved,
                mapKeyObservations: "not a slice",
        }
        backfillLegacyFields(result, map[string]any{}, probe)
        if result[mapKeySummary] == nil {
                t.Error("expected empty legacy summary")
        }
}

func TestBuildInferenceSignals_WithTLSRPT(t *testing.T) {
        policy := map[string]any{mapKeySignals: []string{"existing signal"}}
        telemetry := map[string]any{mapKeyTlsrptConfigured: true}
        signals := buildInferenceSignals(policy, telemetry)
        found := false
        for _, s := range signals {
                if strings.Contains(s, "TLS-RPT") {
                        found = true
                }
        }
        if !found {
                t.Error("expected TLS-RPT signal to be appended")
        }
}

func TestBuildInferenceSignals_DuplicatePrevention(t *testing.T) {
        policy := map[string]any{mapKeySignals: []string{"TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)"}}
        telemetry := map[string]any{mapKeyTlsrptConfigured: true}
        signals := buildInferenceSignals(policy, telemetry)
        count := 0
        for _, s := range signals {
                if strings.Contains(s, "TLS-RPT") {
                        count++
                }
        }
        if count != 1 {
                t.Errorf("expected exactly 1 TLS-RPT signal, got %d", count)
        }
}

func TestBuildInferenceNote_Coverage(t *testing.T) {
        if note := buildInferenceNote(map[string]any{mapKeyStatus: mapKeyObserved}); note != "" {
                t.Error("expected empty note for observed")
        }
        if note := buildInferenceNote(map[string]any{mapKeyStatus: mapKeySkipped}); note == "" {
                t.Error("expected non-empty note for skipped")
        }
}

func TestExtractMXHosts_Coverage(t *testing.T) {
        tests := []struct {
                name  string
                input []string
                want  int
        }{
                {"standard MX", []string{"10 mx1.example.com.", "20 mx2.example.com."}, 2},
                {"empty", nil, 0},
                {"no priority", []string{"mx1.example.com"}, 1},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := extractMXHosts(tt.input)
                        if len(got) != tt.want {
                                t.Errorf("extractMXHosts() returned %d hosts, want %d", len(got), tt.want)
                        }
                })
        }
}

func TestAssessProvider_Coverage(t *testing.T) {
        tests := []struct {
                name    string
                mxHosts []string
                wantSig bool
        }{
                {"google", []string{"alt1.aspmx.l.google.com"}, true},
                {"microsoft", []string{"mx.protection.outlook.com"}, true},
                {"protonmail", []string{"mail.protonmail.ch"}, true},
                {"unknown", []string{"mx.custom.example"}, false},
                {"empty", nil, false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        policy := map[string]any{
                                "provider": map[string]any{"identified": false},
                        }
                        signals := assessProvider(tt.mxHosts, policy, nil)
                        if tt.wantSig && len(signals) == 0 {
                                t.Error("expected signal for known provider")
                        }
                        if !tt.wantSig && len(signals) > 0 {
                                t.Error("expected no signal for unknown provider")
                        }
                })
        }
}

func TestSmtpResponseComplete_Coverage(t *testing.T) {
        tests := []struct {
                name string
                data string
                want bool
        }{
                {"complete", "220 ready\r\n", true},
                {"multi-line incomplete", "250-STARTTLS\r\n", false},
                {"multi-line complete", "250-STARTTLS\r\n250 OK\r\n", true},
                {"empty trailing", "220 ok\r\n\r\n", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := smtpResponseComplete(tt.data); got != tt.want {
                                t.Errorf("smtpResponseComplete(%q) = %v, want %v", tt.data, got, tt.want)
                        }
                })
        }
}

func TestUpdateSummary_Coverage(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{
                mapKeyReachable:         true,
                mapKeyStarttls:          true,
                mapKeyTlsVersion:        "TLSv1.3",
                mapKeyCertValid:         true,
                mapKeyCertDaysRemaining: 10,
        })
        if s.Reachable != 1 {
                t.Errorf("expected Reachable=1, got %d", s.Reachable)
        }
        if s.StartTLSSupport != 1 {
                t.Errorf("expected StartTLS=1, got %d", s.StartTLSSupport)
        }
        if s.TLS13 != 1 {
                t.Errorf("expected TLS13=1, got %d", s.TLS13)
        }
        if s.ValidCerts != 1 {
                t.Errorf("expected ValidCerts=1, got %d", s.ValidCerts)
        }
        if s.ExpiringSoon != 1 {
                t.Errorf("expected ExpiringSoon=1, got %d", s.ExpiringSoon)
        }
}
