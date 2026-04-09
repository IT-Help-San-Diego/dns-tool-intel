package main

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func TestHandleDANEVerify_InvalidBody_C2(t *testing.T) {
        req := httptest.NewRequest(http.MethodPost, "/probe/dane", strings.NewReader("not json"))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleDANEVerify(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleDANEVerify_EmptyHost_C2(t *testing.T) {
        body := `{"host":"","port":25}`
        req := httptest.NewRequest(http.MethodPost, "/probe/dane", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleDANEVerify(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for empty host, got %d", w.Code)
        }
}

func TestHandleDANEVerify_InvalidHostname_C2(t *testing.T) {
        body := `{"host":"invalid host!@#","port":25}`
        req := httptest.NewRequest(http.MethodPost, "/probe/dane", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleDANEVerify(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for invalid hostname, got %d", w.Code)
        }
}

func TestHandleDANEVerify_ValidHost_C2(t *testing.T) {
        body := `{"host":"mx.example.com","port":25}`
        req := httptest.NewRequest(http.MethodPost, "/probe/dane", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleDANEVerify(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        json.NewDecoder(w.Body).Decode(&resp)
        if resp["host"] != "mx.example.com" {
                t.Errorf("expected host=mx.example.com, got %v", resp["host"])
        }
}

func TestHandleDANEVerify_DefaultPort_C2(t *testing.T) {
        body := `{"host":"mx.example.com"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/dane", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleDANEVerify(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        json.NewDecoder(w.Body).Decode(&resp)
        port, ok := resp["port"].(float64)
        if !ok || port != 25 {
                t.Errorf("expected default port=25, got %v", resp["port"])
        }
}

func TestHandleNmapScan_InvalidBody_C2(t *testing.T) {
        req := httptest.NewRequest(http.MethodPost, "/probe/nmap", strings.NewReader("not json"))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleNmapScan(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleNmapScan_EmptyHost_C2(t *testing.T) {
        body := `{"host":"","ports":"80"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/nmap", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleNmapScan(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for empty host, got %d", w.Code)
        }
}

func TestHandleNmapScan_InvalidHostname_C2(t *testing.T) {
        body := `{"host":"invalid host!@#","ports":"80"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/nmap", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleNmapScan(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleNmapScan_InvalidPorts_C2(t *testing.T) {
        body := `{"host":"example.com","ports":"abc;def"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/nmap", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleNmapScan(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for invalid ports, got %d", w.Code)
        }
}

func TestHandleTestSSL_InvalidBody_C2(t *testing.T) {
        req := httptest.NewRequest(http.MethodPost, "/probe/testssl", strings.NewReader("not json"))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleTestSSL(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleTestSSL_EmptyHost_C2(t *testing.T) {
        body := `{"host":""}`
        req := httptest.NewRequest(http.MethodPost, "/probe/testssl", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleTestSSL(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for empty host, got %d", w.Code)
        }
}

func TestHandleTestSSL_InvalidHostname_C2(t *testing.T) {
        body := `{"host":"bad host!@#"}`
        req := httptest.NewRequest(http.MethodPost, "/probe/testssl", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleTestSSL(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_ValidCIDWithAllowedGateway_C2(t *testing.T) {
        body := `{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","gateways":["https://ipfs.io","https://dweb.link"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
        var resp map[string]any
        json.NewDecoder(w.Body).Decode(&resp)
        if resp["cid"] != "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" {
                t.Errorf("expected CID in response, got %v", resp["cid"])
        }
}

func TestHandleIPFSProbe_MixedGateways_C2(t *testing.T) {
        body := `{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","gateways":["https://ipfs.io","https://evil.com"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusOK {
                t.Errorf("expected 200, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_NoAllowedGateways_C2(t *testing.T) {
        body := `{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","gateways":["https://evil.com"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400 for no allowed gateways, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_EmptyCID_C2(t *testing.T) {
        body := `{"cid":"","gateways":["https://ipfs.io"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestHandleIPFSProbe_InvalidCID_C2(t *testing.T) {
        body := `{"cid":"notacid","gateways":["https://ipfs.io"]}`
        req := httptest.NewRequest(http.MethodPost, "/probe/ipfs", strings.NewReader(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        handleIPFSProbe(w, req)
        if w.Code != http.StatusBadRequest {
                t.Errorf("expected 400, got %d", w.Code)
        }
}

func TestParseNmapXML_Valid_C2(t *testing.T) {
        xmlData := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
    <hostnames>
      <hostname name="example.com"/>
    </hostnames>
  </host>
</nmaprun>`
        result := parseNmapXML(xmlData)
        hosts, ok := result["hosts"].([]map[string]any)
        if !ok || len(hosts) != 1 {
                t.Error("expected 1 host")
        }
}

func TestParseNmapXML_Empty_C2(t *testing.T) {
        xmlData := `<?xml version="1.0"?><nmaprun></nmaprun>`
        result := parseNmapXML(xmlData)
        hosts, ok := result["hosts"].([]map[string]any)
        if !ok || len(hosts) != 0 {
                t.Error("expected 0 hosts")
        }
}

func TestParseNmapXML_InvalidXML_C2(t *testing.T) {
        result := parseNmapXML("not xml at all")
        if result != nil {
                t.Error("expected nil for invalid XML")
        }
}

func TestConvertNmapHost_NoHostname_C2(t *testing.T) {
        host := nmapHost{
                Addresses: []nmapAddress{{Addr: "1.2.3.4", AddrType: "ipv4"}},
                Ports:     []nmapPort{},
        }
        result := convertNmapHost(host)
        if result["hostnames"] != nil {
                t.Error("expected nil hostnames when none provided")
        }
        addrs, ok := result["addresses"].([]map[string]string)
        if !ok || len(addrs) != 1 {
                t.Error("expected 1 address")
        }
}

func TestConvertNmapPort_NoScripts_C2(t *testing.T) {
        port := nmapPort{
                Protocol: "tcp",
                PortID:   22,
                State:    nmapPortState{State: "filtered"},
                Service:  nmapPortService{Name: "ssh"},
        }
        result := convertNmapPort(port)
        if result["state"] != "filtered" {
                t.Error("expected state=filtered")
        }
        if result["scripts"] != nil {
                t.Error("expected nil scripts for empty scripts list")
        }
}

func TestBuildNmapErrorResponse_EmptyStderr_C2(t *testing.T) {
        response := make(map[string]any)
        buildNmapErrorResponse(response, errString("test error"), "", "")
        if response["error"] == nil {
                t.Error("expected error")
        }
        if response["stderr"] != nil {
                t.Errorf("expected nil stderr for empty input, got %v", response["stderr"])
        }
}

func TestBuildNmapSuccessResponse_Minimal_C2(t *testing.T) {
        response := make(map[string]any)
        buildNmapSuccessResponse(response, `<?xml version="1.0"?><nmaprun></nmaprun>`)
        if response["status"] != "ok" {
                t.Errorf("expected status=ok, got %v", response["status"])
        }
        if response["xml"] == nil {
                t.Error("expected xml in response")
        }
}
