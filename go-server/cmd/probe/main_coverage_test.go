package main

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestIsValidCID_V0(t *testing.T) {
        if !isValidCID("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG") {
                t.Error("expected valid CID v0")
        }
}

func TestIsValidCID_V1(t *testing.T) {
        if !isValidCID("bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq") {
                t.Error("expected valid CID v1")
        }
}

func TestIsValidCID_Invalid(t *testing.T) {
        if isValidCID("not-a-cid") {
                t.Error("expected invalid CID")
        }
        if isValidCID("") {
                t.Error("expected invalid for empty")
        }
}

func TestIsAllowlistedGateway_Coverage(t *testing.T) {
        tests := []struct {
                gw   string
                want bool
        }{
                {"https://ipfs.io", true},
                {"https://dweb.link", true},
                {"https://evil.com", false},
                {"", false},
        }
        for _, tt := range tests {
                if got := isAllowlistedGateway(tt.gw); got != tt.want {
                        t.Errorf("isAllowlistedGateway(%q) = %v, want %v", tt.gw, got, tt.want)
                }
        }
}

func TestIsAllowlistedGatewayHost_Coverage(t *testing.T) {
        tests := []struct {
                host string
                want bool
        }{
                {"https://ipfs.io", true},
                {"https://dweb.link", true},
                {"evil.com", false},
        }
        for _, tt := range tests {
                if got := isAllowlistedGatewayHost(tt.host); got != tt.want {
                        t.Errorf("isAllowlistedGatewayHost(%q) = %v, want %v", tt.host, got, tt.want)
                }
        }
}

func TestIsValidPortSpec_Coverage(t *testing.T) {
        tests := []struct {
                ports string
                want  bool
        }{
                {"80", true},
                {"80,443", true},
                {"1-1024", true},
                {"80,443,8080-8090", true},
                {"", true},
                {"abc", false},
                {"80;443", false},
        }
        for _, tt := range tests {
                if got := isValidPortSpec(tt.ports); got != tt.want {
                        t.Errorf("isValidPortSpec(%q) = %v, want %v", tt.ports, got, tt.want)
                }
        }
}

func TestFilterNmapScripts_AllowedCov(t *testing.T) {
        valid, rejected := filterNmapScripts([]string{"ssl-cert", "smtp-commands"})
        if len(valid) != 2 {
                t.Errorf("expected 2 valid scripts, got %d", len(valid))
        }
        if len(rejected) != 0 {
                t.Errorf("expected 0 rejected scripts, got %d", len(rejected))
        }
}

func TestFilterNmapScripts_RejectedCov(t *testing.T) {
        valid, rejected := filterNmapScripts([]string{"ssl-cert", "malicious-script"})
        if len(valid) != 1 {
                t.Errorf("expected 1 valid script, got %d", len(valid))
        }
        if len(rejected) != 1 {
                t.Errorf("expected 1 rejected script, got %d", len(rejected))
        }
}

func TestFilterNmapScripts_EmptyCov(t *testing.T) {
        valid, rejected := filterNmapScripts(nil)
        if len(valid) != 3 {
                t.Errorf("expected 3 default valid scripts, got %d", len(valid))
        }
        if len(rejected) != 0 {
                t.Errorf("expected 0 rejected scripts, got %d", len(rejected))
        }
}

func TestClassifyError_TimeoutCov(t *testing.T) {
        err := errString("connection timed out")
        result := classifyError(err)
        if result == "" {
                t.Error("expected non-empty classification for timeout")
        }
}

func TestClassifyError_RefusedCov(t *testing.T) {
        err := errString("connection refused")
        result := classifyError(err)
        if result == "" {
                t.Error("expected non-empty classification for refused")
        }
}

func TestClassifyError_UnknownCov(t *testing.T) {
        err := errString("some random error")
        result := classifyError(err)
        if result == "" {
                t.Error("expected non-empty classification")
        }
}

func TestClassifyIPFSError_TimeoutCov(t *testing.T) {
        err := errString("context deadline exceeded")
        result := classifyIPFSError(err)
        if result == "" {
                t.Error("expected non-empty classification")
        }
}

func TestClassifyIPFSError_DNSCov(t *testing.T) {
        err := errString("no such host")
        result := classifyIPFSError(err)
        if result == "" {
                t.Error("expected non-empty classification")
        }
}

func TestIpfsTLSVersionString_Coverage(t *testing.T) {
        tests := []struct {
                version uint16
                want    string
        }{
                {0x0303, "TLS 1.2"},
                {0x0304, "TLS 1.3"},
                {0x0302, "TLS 1.1"},
                {0x0301, "TLS 1.0"},
                {0x0000, "unknown (0x0000)"},
        }
        for _, tt := range tests {
                if got := ipfsTLSVersionString(tt.version); got != tt.want {
                        t.Errorf("ipfsTLSVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
                }
        }
}

func TestConvertNmapPort_BasicCov(t *testing.T) {
        port := nmapPort{
                Protocol: "tcp",
                PortID:   443,
                State:    nmapPortState{State: "open"},
                Service:  nmapPortService{Name: "https", Product: "nginx"},
        }
        result := convertNmapPort(port)
        if result["protocol"] != "tcp" {
                t.Error("expected protocol=tcp")
        }
        if result["port"] != 443 {
                t.Error("expected port=443")
        }
        if result["state"] != "open" {
                t.Error("expected state=open")
        }
}

func TestConvertNmapPort_WithScriptCov(t *testing.T) {
        port := nmapPort{
                Protocol: "tcp",
                PortID:   25,
                State:    nmapPortState{State: "open"},
                Service:  nmapPortService{Name: "smtp"},
                Scripts: []nmapScript{
                        {ID: "smtp-commands", Output: "STARTTLS"},
                },
        }
        result := convertNmapPort(port)
        scripts, ok := result["scripts"].([]map[string]any)
        if !ok || len(scripts) != 1 {
                t.Error("expected 1 script")
        }
}

func TestConvertNmapHost_Coverage(t *testing.T) {
        host := nmapHost{
                Addresses: []nmapAddress{
                        {Addr: "1.2.3.4", AddrType: "ipv4"},
                },
                Ports: []nmapPort{
                        {Protocol: "tcp", PortID: 80, State: nmapPortState{State: "open"}, Service: nmapPortService{Name: "http"}},
                },
                Hostnames: []nmapHostname{{Name: "example.com"}},
        }
        result := convertNmapHost(host)
        addrs, ok := result["addresses"].([]map[string]string)
        if !ok || len(addrs) != 1 {
                t.Error("expected 1 address")
        }
        ports, ok := result["ports"].([]map[string]any)
        if !ok || len(ports) != 1 {
                t.Error("expected 1 port")
        }
}

func TestHandleIPFSProbe_InvalidBodyCov(t *testing.T) {
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader("not json"))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_InvalidCIDCov(t *testing.T) {
        body := `{"cid":"not-a-valid-cid","gateways":["https://ipfs.io/ipfs/"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_NoGatewaysCov(t *testing.T) {
        body := `{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for no gateways, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_UnallowlistedGatewayCov(t *testing.T) {
        body := `{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","gateways":["https://evil.com/ipfs/"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        var resp map[string]any
        json.NewDecoder(w.Body).Decode(&resp)
}

func TestBuildNmapErrorResponse_Coverage(t *testing.T) {
        response := make(map[string]any)
        buildNmapErrorResponse(response, errString("test error"), "<xml>data</xml>", "stderr output")
        if response["error"] == nil {
                t.Error("expected error message to be set")
        }
        if response["partial_xml"] != "<xml>data</xml>" {
                t.Errorf("expected partial_xml, got %v", response["partial_xml"])
        }
        if response["stderr"] != "stderr output" {
                t.Errorf("expected stderr, got %v", response["stderr"])
        }
}

func TestBuildNmapSuccessResponse_Coverage(t *testing.T) {
        response := make(map[string]any)
        xmlData := `<?xml version="1.0"?><nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`
        buildNmapSuccessResponse(response, xmlData)
        if response["xml"] != xmlData {
                t.Error("expected xml in response")
        }
        if response["status"] != "ok" {
                t.Errorf("expected status=ok, got %v", response["status"])
        }
}

