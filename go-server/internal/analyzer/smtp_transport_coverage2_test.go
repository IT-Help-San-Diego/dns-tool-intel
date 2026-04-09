package analyzer

import (
        "context"
        "crypto/tls"
        "testing"
        "time"
)

func TestDerivePrimaryStatus_Observed_AllTLS_Enforced_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyEnforced}
        probe := map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls}
        if got := derivePrimaryStatus(policy, probe); got != mapKeySuccess {
                t.Errorf("expected success, got %s", got)
        }
}

func TestDerivePrimaryStatus_Observed_AllTLS_NoEnforce_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: verdictNone}
        probe := map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls}
        if got := derivePrimaryStatus(policy, probe); got != mapKeySuccess {
                t.Errorf("expected success, got %s", got)
        }
}

func TestDerivePrimaryStatus_Observed_PartialTLS_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: verdictNone}
        probe := map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyPartialTls}
        if got := derivePrimaryStatus(policy, probe); got != "warning" {
                t.Errorf("expected warning, got %s", got)
        }
}

func TestDerivePrimaryStatus_Observed_NoTLS_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: verdictNone}
        probe := map[string]any{mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls}
        if got := derivePrimaryStatus(policy, probe); got != mapKeyError {
                t.Errorf("expected error, got %s", got)
        }
}

func TestDerivePrimaryStatus_Skipped_Enforced_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyEnforced}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        if got := derivePrimaryStatus(policy, probe); got != mapKeySuccess {
                t.Errorf("expected success, got %s", got)
        }
}

func TestDerivePrimaryStatus_Skipped_Monitored_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyMonitored}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        if got := derivePrimaryStatus(policy, probe); got != "info" {
                t.Errorf("expected info, got %s", got)
        }
}

func TestDerivePrimaryStatus_Skipped_Opportunistic_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyOpportunistic}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        if got := derivePrimaryStatus(policy, probe); got != "inferred" {
                t.Errorf("expected inferred, got %s", got)
        }
}

func TestDerivePrimaryStatus_Skipped_None_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: verdictNone}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        if got := derivePrimaryStatus(policy, probe); got != "info" {
                t.Errorf("expected info, got %s", got)
        }
}

func TestDerivePrimaryMessage_NoMX_C2(t *testing.T) {
        msg := derivePrimaryMessage(map[string]any{}, map[string]any{}, nil)
        if msg != "No MX records found" {
                t.Errorf("expected 'No MX records found', got %q", msg)
        }
}

func TestDerivePrimaryMessage_Observed_AllMatch_C2(t *testing.T) {
        probe := map[string]any{
                mapKeyStatus: mapKeyObserved,
                mapKeySummary: map[string]any{
                        mapKeyReachable:         float64(2),
                        mapKeyStarttlsSupported: float64(2),
                },
        }
        msg := derivePrimaryMessage(map[string]any{mapKeySignals: []string{}}, probe, []string{"mx1", "mx2"})
        if msg == "" {
                t.Error("expected non-empty message")
        }
}

func TestDerivePrimaryMessage_Observed_Partial_C2(t *testing.T) {
        probe := map[string]any{
                mapKeyStatus: mapKeyObserved,
                mapKeySummary: map[string]any{
                        mapKeyReachable:         float64(3),
                        mapKeyStarttlsSupported: float64(1),
                },
        }
        msg := derivePrimaryMessage(map[string]any{mapKeySignals: []string{}}, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty message")
        }
}

func TestDerivePrimaryMessage_Enforced_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyEnforced, mapKeySignals: []string{"sig1"}}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        msg := derivePrimaryMessage(policy, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty enforced message")
        }
}

func TestDerivePrimaryMessage_Monitored_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyMonitored, mapKeySignals: []string{"sig1"}}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        msg := derivePrimaryMessage(policy, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty monitored message")
        }
}

func TestDerivePrimaryMessage_Opportunistic_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: mapKeyOpportunistic, mapKeySignals: []string{"sig1"}}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        msg := derivePrimaryMessage(policy, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty opportunistic message")
        }
}

func TestDerivePrimaryMessage_None_C2(t *testing.T) {
        policy := map[string]any{mapKeyVerdict: verdictNone, mapKeySignals: []string{}}
        probe := map[string]any{mapKeyStatus: mapKeySkipped}
        msg := derivePrimaryMessage(policy, probe, []string{"mx1"})
        if msg == "" {
                t.Error("expected non-empty default message")
        }
}

func TestComputePolicyVerdict_Enforced_C2(t *testing.T) {
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: true, "mode": "enforce"},
                mapKeyDane:   map[string]any{mapKeyPresent: false},
        }
        got := computePolicyVerdict(policy, []string{})
        if got != mapKeyEnforced {
                t.Errorf("expected enforced, got %s", got)
        }
}

func TestComputePolicyVerdict_DaneEnforced_C2(t *testing.T) {
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false, "mode": verdictNone},
                mapKeyDane:   map[string]any{mapKeyPresent: true},
        }
        got := computePolicyVerdict(policy, []string{})
        if got != mapKeyEnforced {
                t.Errorf("expected enforced, got %s", got)
        }
}

func TestComputePolicyVerdict_Testing_C2(t *testing.T) {
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: true, "mode": "testing"},
                mapKeyDane:   map[string]any{mapKeyPresent: false},
        }
        got := computePolicyVerdict(policy, []string{})
        if got != mapKeyMonitored {
                t.Errorf("expected monitored, got %s", got)
        }
}

func TestComputePolicyVerdict_Opportunistic_C2(t *testing.T) {
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false},
                mapKeyDane:   map[string]any{mapKeyPresent: false},
        }
        got := computePolicyVerdict(policy, []string{"signal"})
        if got != mapKeyOpportunistic {
                t.Errorf("expected opportunistic, got %s", got)
        }
}

func TestComputePolicyVerdict_None_C2(t *testing.T) {
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false},
                mapKeyDane:   map[string]any{mapKeyPresent: false},
        }
        got := computePolicyVerdict(policy, []string{})
        if got != verdictNone {
                t.Errorf("expected none, got %s", got)
        }
}

func TestComputePolicyVerdict_NilMaps_C2(t *testing.T) {
        got := computePolicyVerdict(map[string]any{}, nil)
        if got != verdictNone {
                t.Errorf("expected none, got %s", got)
        }
}

func TestExtractTLSRPTURIs_C2(t *testing.T) {
        tests := []struct {
                name   string
                record string
                want   int
        }{
                {"single URI", "v=TLSRPTv1;rua=mailto:t@example.com", 1},
                {"multiple URIs", "v=TLSRPTv1;rua=mailto:a@x.com,mailto:b@x.com", 2},
                {"no rua", "v=TLSRPTv1", 0},
                {"empty rua", "v=TLSRPTv1;rua=", 0},
                {"spaces", "v=TLSRPTv1 ; rua = mailto:a@x.com", 0},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        uris := extractTLSRPTURIs(tt.record)
                        if len(uris) != tt.want {
                                t.Errorf("extractTLSRPTURIs(%q) returned %d URIs, want %d", tt.record, len(uris), tt.want)
                        }
                })
        }
}

func TestBuildTelemetrySection_NilInput_C2(t *testing.T) {
        section := buildTelemetrySection(AnalysisInputs{})
        if section[mapKeyTlsrptConfigured] != false {
                t.Error("expected tlsrpt_configured=false")
        }
}

func TestBuildTelemetrySection_WithTLSRPT_C2(t *testing.T) {
        ai := AnalysisInputs{
                TLSRPTResult: map[string]any{
                        mapKeyStatus: mapKeySuccess,
                        "record":     "v=TLSRPTv1;rua=mailto:t@example.com",
                },
        }
        section := buildTelemetrySection(ai)
        if section[mapKeyTlsrptConfigured] != true {
                t.Error("expected tlsrpt_configured=true")
        }
        if section["observability"] != true {
                t.Error("expected observability=true")
        }
        uris, ok := section["reporting_uris"].([]string)
        if !ok || len(uris) != 1 {
                t.Errorf("expected 1 reporting URI, got %v", section["reporting_uris"])
        }
}

func TestBuildTelemetrySection_TLSRPTNoRecord_C2(t *testing.T) {
        ai := AnalysisInputs{
                TLSRPTResult: map[string]any{mapKeyStatus: mapKeySuccess},
        }
        section := buildTelemetrySection(ai)
        if section[mapKeyTlsrptConfigured] != true {
                t.Error("expected tlsrpt_configured=true")
        }
}

func TestBuildTelemetrySection_TLSRPTFailed_C2(t *testing.T) {
        ai := AnalysisInputs{
                TLSRPTResult: map[string]any{mapKeyStatus: "error"},
        }
        section := buildTelemetrySection(ai)
        if section[mapKeyTlsrptConfigured] != false {
                t.Error("expected tlsrpt_configured=false")
        }
}

func TestSmtpProbeVerdictFromSummary_AllTLS_C2(t *testing.T) {
        s := &smtpSummary{Reachable: 2, StartTLSSupport: 2, ValidCerts: 2}
        if got := smtpProbeVerdictFromSummary(s); got != mapKeyAllTls {
                t.Errorf("expected all_tls, got %s", got)
        }
}

func TestSmtpProbeVerdictFromSummary_PartialTLS_C2(t *testing.T) {
        s := &smtpSummary{Reachable: 3, StartTLSSupport: 1, ValidCerts: 1}
        if got := smtpProbeVerdictFromSummary(s); got != mapKeyPartialTls {
                t.Errorf("expected partial_tls, got %s", got)
        }
}

func TestSmtpProbeVerdictFromSummary_NoTLS_C2(t *testing.T) {
        s := &smtpSummary{Reachable: 2, StartTLSSupport: 0, ValidCerts: 0}
        if got := smtpProbeVerdictFromSummary(s); got != mapKeyNoTls {
                t.Errorf("expected no_tls, got %s", got)
        }
}

func TestComputeProbeConsensus_UnanimousTLS_C2(t *testing.T) {
        results := []map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyAllTls},
        }
        c := computeProbeConsensus(results)
        if c[mapKeyAgreement] != "unanimous_tls" {
                t.Errorf("expected unanimous_tls, got %v", c[mapKeyAgreement])
        }
}

func TestComputeProbeConsensus_UnanimousNoTLS_C2(t *testing.T) {
        results := []map[string]any{
                {mapKeyStatus: mapKeyObserved, mapKeyProbeVerdict: mapKeyNoTls},
        }
        c := computeProbeConsensus(results)
        if c[mapKeyAgreement] != "unanimous_no_tls" {
                t.Errorf("expected unanimous_no_tls, got %v", c[mapKeyAgreement])
        }
}

func TestApplyPrimaryResult_NonNil_C2(t *testing.T) {
        probe := map[string]any{}
        primary := map[string]any{mapKeyStatus: mapKeyObserved, "extra": "val"}
        applyPrimaryResult(probe, primary)
        if probe[mapKeyStatus] != mapKeyObserved {
                t.Error("expected status copied")
        }
        if probe["extra"] != "val" {
                t.Error("expected extra copied")
        }
}

func TestApplyRemoteProbeMetadata_WithPorts_C2(t *testing.T) {
        probe := map[string]any{}
        apiResp := &remoteProbeAPIResp{
                ProbeHost:      "probe-1",
                ElapsedSeconds: 1.5,
                AllPorts:       []map[string]any{{"port": 25}},
        }
        applyRemoteProbeMetadata(probe, apiResp)
        if probe[mapKeyProbeHost] != "probe-1" {
                t.Errorf("expected probe_host=probe-1, got %v", probe[mapKeyProbeHost])
        }
        if probe["multi_port"] == nil {
                t.Error("expected multi_port set")
        }
}

func TestClassifySMTPError_C2(t *testing.T) {
        tests := []struct {
                err  string
                want string
        }{
                {"connection timeout", "Connection timeout"},
                {"context deadline exceeded", "Connection timeout"},
                {"connection refused", "Connection refused"},
                {"network unreachable", "Network unreachable"},
                {"no such host", "DNS resolution failed"},
                {"some other error", "some other error"},
        }
        for _, tt := range tests {
                got := classifySMTPError(errStringC2(tt.err))
                if got != tt.want {
                        t.Errorf("classifySMTPError(%q) = %q, want %q", tt.err, got, tt.want)
                }
        }
}

type errStringC2 string

func (e errStringC2) Error() string { return string(e) }

func TestTlsVersionString_C2(t *testing.T) {
        tests := []struct {
                v    uint16
                want string
        }{
                {tls.VersionTLS13, "TLSv1.3"},
                {tls.VersionTLS12, "TLSv1.2"},
                {tls.VersionTLS11, "TLSv1.1"},
                {tls.VersionTLS10, "TLSv1.0"},
                {0x0000, "TLS 0x0000"},
        }
        for _, tt := range tests {
                got := tlsVersionString(tt.v)
                if got != tt.want {
                        t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.v, got, tt.want)
                }
        }
}

func TestCipherBits_C2(t *testing.T) {
        got256 := cipherBits(tls.TLS_CHACHA20_POLY1305_SHA256)
        if got256 != 256 {
                t.Errorf("expected 256 for CHACHA20, got %d", got256)
        }
        got128 := cipherBits(tls.TLS_AES_128_GCM_SHA256)
        if got128 != 256 {
                t.Errorf("expected 256 for AES_128_GCM_SHA256, got %d", got128)
        }
        got0 := cipherBits(0)
        if got0 != 0 {
                t.Errorf("expected 0 for unknown, got %d", got0)
        }
}

func TestTruncate_C2(t *testing.T) {
        if truncate("hello", 10) != "hello" {
                t.Error("short string should be unchanged")
        }
        if truncate("hello world", 5) != "hello" {
                t.Error("should truncate to 5")
        }
}

func TestIdentifyProviderName_C2(t *testing.T) {
        tests := []struct {
                mxHosts []string
                want    string
        }{
                {[]string{"aspmx.l.google.com"}, "Google Workspace"},
                {[]string{"mx.protection.outlook.com"}, "Microsoft 365"},
                {[]string{"mail.protonmail.ch"}, "Proton Mail"},
                {[]string{"mx.custom.example.com"}, ""},
                {nil, ""},
        }
        for _, tt := range tests {
                got := identifyProviderName(tt.mxHosts)
                if got != tt.want {
                        t.Errorf("identifyProviderName(%v) = %q, want %q", tt.mxHosts, got, tt.want)
                }
        }
}

func TestMapGetStrSafe_C2(t *testing.T) {
        if mapGetStrSafe(nil, "key") != "" {
                t.Error("expected empty for nil map")
        }
        if mapGetStrSafe(map[string]any{"key": 123}, "key") != "" {
                t.Error("expected empty for non-string value")
        }
        if mapGetStrSafe(map[string]any{"key": "val"}, "key") != "val" {
                t.Error("expected 'val'")
        }
}

func TestToFloat64Val_C2(t *testing.T) {
        if toFloat64Val(1.5) != 1.5 {
                t.Error("float64")
        }
        if toFloat64Val(42) != 42.0 {
                t.Error("int")
        }
        if toFloat64Val(int64(100)) != 100.0 {
                t.Error("int64")
        }
        if toFloat64Val("bad") != 0 {
                t.Error("non-numeric should be 0")
        }
}

func TestSummaryToMap_C2(t *testing.T) {
        s := &smtpSummary{TotalServers: 3, Reachable: 2, StartTLSSupport: 1, TLS13: 1, TLS12: 0, ValidCerts: 1, ExpiringSoon: 0}
        m := summaryToMap(s)
        if m[mapKeyTotalServers] != 3 {
                t.Error("expected total_servers=3")
        }
}

func TestEmptyLegacySummary_C2(t *testing.T) {
        m := emptyLegacySummary()
        if m[mapKeyTotalServers] != 0 {
                t.Error("expected 0")
        }
}

func TestInferFromProvider_C2(t *testing.T) {
        tests := []struct {
                mxHosts []string
                wantSig bool
        }{
                {[]string{"aspmx.l.google.com"}, true},
                {[]string{"mx.protection.outlook.com"}, true},
                {[]string{"mail.pphosted.com"}, true},
                {[]string{"us-smtp-inbound-1.mimecast.com"}, true},
                {[]string{"mx.messagelabs.com"}, true},
                {[]string{"mail.fireeyecloud.com"}, true},
                {[]string{"mx1.iphmx.com"}, true},
                {[]string{"registrar-servers.com"}, true},
                {[]string{"mx.custom.example"}, false},
                {nil, false},
        }
        for _, tt := range tests {
                got := inferFromProvider(tt.mxHosts)
                if tt.wantSig && got == "" {
                        t.Errorf("inferFromProvider(%v) returned empty, expected signal", tt.mxHosts)
                }
                if !tt.wantSig && got != "" {
                        t.Errorf("inferFromProvider(%v) = %q, expected empty", tt.mxHosts, got)
                }
        }
}

func TestGetIssuesList_C2(t *testing.T) {
        got := getIssuesList(map[string]any{"issues": []string{"a", "b"}})
        if len(got) != 2 {
                t.Errorf("expected 2 issues, got %d", len(got))
        }
        got = getIssuesList(map[string]any{})
        if len(got) != 0 {
                t.Errorf("expected 0 issues, got %d", len(got))
        }
}

func TestBuildPolicyAssessment_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}, SMTPProbeMode: "skip"}
        ai := AnalysisInputs{
                MTASTSResult: map[string]any{"mode": "enforce", mapKeyStatus: mapKeySuccess},
                TLSRPTResult: map[string]any{mapKeyStatus: mapKeySuccess, "record": "v=TLSRPTv1;rua=mailto:t@example.com"},
                DANEResult:   map[string]any{"has_dane": true},
        }
        policy := buildPolicyAssessment(a, context.Background(), "example.com", []string{"mx.example.com"}, ai)
        verdict, ok := policy[mapKeyVerdict].(string)
        if !ok || verdict != mapKeyEnforced {
                t.Errorf("expected enforced verdict, got %v", policy[mapKeyVerdict])
        }
}

func TestClassifyRemoteProbeStatus_C2(t *testing.T) {
        if classifyRemoteProbeStatus(200) != "" {
                t.Error("expected empty for 200")
        }
        if classifyRemoteProbeStatus(401) == "" {
                t.Error("expected non-empty for 401")
        }
        if classifyRemoteProbeStatus(429) == "" {
                t.Error("expected non-empty for 429")
        }
        if classifyRemoteProbeStatus(500) == "" {
                t.Error("expected non-empty for 500")
        }
}

func TestBuildMultiProbeEntry_C2(t *testing.T) {
        r := smtpProbeResult{
                id:    "p1",
                label: "Probe 1",
                data: map[string]any{
                        mapKeyStatus:       mapKeyObserved,
                        mapKeyProbeHost:    "probe-host",
                        mapKeyProbeElapsed: 1.5,
                        mapKeyObservations: []map[string]any{{"host": "mx1"}},
                        mapKeySummary:      map[string]any{mapKeyTotalServers: 1},
                        mapKeyProbeVerdict: mapKeyAllTls,
                },
        }
        entry := buildMultiProbeEntry(r)
        if entry["probe_id"] != "p1" {
                t.Errorf("expected probe_id=p1, got %v", entry["probe_id"])
        }
        if entry[mapKeyProbeVerdict] != mapKeyAllTls {
                t.Errorf("expected probe_verdict=all_tls, got %v", entry[mapKeyProbeVerdict])
        }
}

func TestUpdateSummary_TLS12_C2(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{
                mapKeyReachable:  true,
                mapKeyStarttls:   true,
                mapKeyTlsVersion: "TLSv1.2",
                mapKeyCertValid:  true,
        })
        if s.TLS12 != 1 {
                t.Errorf("expected TLS12=1, got %d", s.TLS12)
        }
}

func TestUpdateSummary_NotReachable_C2(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{mapKeyReachable: false})
        if s.Reachable != 0 {
                t.Error("expected Reachable=0")
        }
}

func TestUpdateSummary_CertNotExpiring_C2(t *testing.T) {
        s := &smtpSummary{}
        updateSummary(s, map[string]any{
                mapKeyReachable:         true,
                mapKeyCertDaysRemaining: 90,
        })
        if s.ExpiringSoon != 0 {
                t.Error("expected ExpiringSoon=0 for cert with 90 days")
        }
}

func TestAssessMTASTS_WithTestingMode_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{MTASTSResult: map[string]any{"mode": "testing", mapKeyStatus: "pass"}}
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
        }
        signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
        if len(signals) != 1 {
                t.Errorf("expected 1 signal, got %d", len(signals))
        }
}

func TestAssessMTASTS_NoResult_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}}
        ai := AnalysisInputs{MTASTSResult: nil}
        policy := map[string]any{
                mapKeyMtaSts: map[string]any{mapKeyPresent: false, mapKeyMode: verdictNone},
        }
        signals := assessMTASTS(a, context.Background(), "example.com", ai, policy, nil)
        _ = signals
}

func TestAssessTLSRPT_Success_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        ai := AnalysisInputs{TLSRPTResult: map[string]any{mapKeyStatus: mapKeySuccess}}
        policy := map[string]any{"tlsrpt": map[string]any{mapKeyPresent: false}}
        signals := assessTLSRPT(a, context.Background(), "example.com", ai, policy, nil)
        if len(signals) == 0 {
                t.Error("expected TLS-RPT signal")
        }
}

func TestAssessTLSRPT_NoResult_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        ai := AnalysisInputs{}
        policy := map[string]any{"tlsrpt": map[string]any{mapKeyPresent: false}}
        signals := assessTLSRPT(a, context.Background(), "example.com", ai, policy, nil)
        _ = signals
}

func TestAssessDANE_FromResult_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS}
        ai := AnalysisInputs{DANEResult: map[string]any{"has_dane": true}}
        policy := map[string]any{mapKeyDane: map[string]any{mapKeyPresent: false}}
        signals := assessDANE(a, context.Background(), nil, ai, policy, nil)
        if len(signals) == 0 {
                t.Error("expected DANE signal")
        }
}

func TestAssessDANE_FromDNSQuery_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        mockDNS.AddResponse("TLSA", "_25._tcp.mx.example.com", []string{"3 1 1 abc123"})
        a := &Analyzer{DNS: mockDNS}
        ai := AnalysisInputs{}
        policy := map[string]any{mapKeyDane: map[string]any{mapKeyPresent: false}}
        signals := assessDANE(a, context.Background(), []string{"mx.example.com"}, ai, policy, nil)
        if len(signals) == 0 {
                t.Error("expected DANE signal from DNS query")
        }
}

func TestBuildProbeResult_ForceMode_C2(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "force"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"unreachable.invalid"})
        if probe[mapKeyProbeMethod] != "local" {
                t.Errorf("expected probe_method=local, got %v", probe[mapKeyProbeMethod])
        }
}

func TestBuildProbeResult_RemoteWithLegacyURL_C2(t *testing.T) {
        a := &Analyzer{SMTPProbeMode: "remote", ProbeAPIURL: "http://invalid.test:0", ProbeAPIKey: "key"}
        probe := buildProbeResult(a, context.Background(), "example.com", []string{"mx.example.com"})
        _ = probe
}

func TestAnalyzeSMTPTransport_WithInputs_C2(t *testing.T) {
        mockDNS := NewMockDNSClient()
        a := &Analyzer{DNS: mockDNS, HTTP: &MockHTTPClient{}, SMTPProbeMode: "skip"}
        ai := AnalysisInputs{
                MTASTSResult: map[string]any{"mode": "enforce", mapKeyStatus: mapKeySuccess},
                TLSRPTResult: map[string]any{mapKeyStatus: mapKeySuccess},
                DANEResult:   map[string]any{"has_dane": false},
        }
        result := a.AnalyzeSMTPTransport(context.Background(), "example.com", []string{"10 mx.example.com."}, ai)
        if result[mapKeyVersion] != 2 {
                t.Errorf("expected version=2, got %v", result[mapKeyVersion])
        }
}

func TestMarshalRemoteProbeBody_Normal_C2(t *testing.T) {
        body, errMsg := marshalRemoteProbeBody([]string{"mx1.example.com", "mx2.example.com"})
        if body == nil {
                t.Fatal("expected body")
        }
        if errMsg != "" {
                t.Errorf("unexpected error: %s", errMsg)
        }
}

func TestProbeSMTPServers_UnreachableHost_C2(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping in short mode")
        }
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        summary := &smtpSummary{TotalServers: 1}
        servers := probeSMTPServers(ctx, []string{"unreachable.invalid"}, summary)
        if len(servers) != 1 {
                t.Errorf("expected 1 server result, got %d", len(servers))
        }
}
