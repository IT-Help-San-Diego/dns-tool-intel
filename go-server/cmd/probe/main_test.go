package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"valid domain", "example.com", true},
		{"valid subdomain", "www.example.com", true},
		{"valid with hyphens", "my-site.example.com", true},
		{"uppercase", "Example.COM", true},
		{"single label", "localhost", true},
		{"empty", "", false},
		{"starts with hyphen", "-evil.com", false},
		{"starts with dot", ".evil.com", false},
		{"semicolon injection", "example.com;rm -rf /", false},
		{"pipe injection", "example.com|cat /etc/passwd", false},
		{"backtick injection", "example.com`whoami`", false},
		{"ampersand injection", "example.com&&echo pwned", false},
		{"dollar injection", "example.com$PATH", false},
		{"newline injection", "example.com\nmalicious", false},
		{"space in hostname", "example .com", false},
		{"nmap flag injection", "--interactive", false},
		{"too long", strings.Repeat("a", 254), false},
		{"max length", strings.Repeat("a", 253), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostname(tt.input)
			if got != tt.expect {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestTlsVersionString(t *testing.T) {
	tests := []struct {
		input  uint16
		expect string
	}{
		{0x0304, "TLSv1.3"},
		{0x0303, "TLSv1.2"},
		{0x0302, "TLSv1.1"},
		{0x0301, "TLSv1.0"},
		{0x0000, "TLS 0x0000"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.input)
		if got != tt.expect {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestCipherBits(t *testing.T) {
	tests := []struct {
		name   string
		suite  uint16
		expect int
	}{
		{"AES-256-GCM-SHA384", 0x009d, 256},
		{"AES-128-GCM-SHA256", 0x009c, 128},
		{"CHACHA20-POLY1305", 0xcca8, 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cipherBits(tt.suite)
			if got != tt.expect {
				t.Errorf("cipherBits(0x%04x) = %d, want %d", tt.suite, got, tt.expect)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		expect string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcdef", 3, "abc"},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.expect {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expect)
		}
	}
}

func TestSmtpComplete(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"complete 220", "220 mail.example.com ESMTP\r\n", true},
		{"complete 250", "250 OK\r\n", true},
		{"continuation", "250-SIZE 10485760\r\n", false},
		{"multi-line complete", "250-STARTTLS\r\n250 OK\r\n", true},
		{"empty last line", "250 OK\r\n\r\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smtpComplete(tt.input)
			if got != tt.expect {
				t.Errorf("smtpComplete(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name   string
		err    string
		expect string
	}{
		{"timeout", "dial tcp: i/o timeout", "Connection timeout"},
		{"deadline", "context deadline exceeded", "Connection timeout"},
		{"refused", "dial tcp: connection refused", "Connection refused"},
		{"unreachable", "network is unreachable", "Network unreachable"},
		{"dns", "dial tcp: lookup example.com: no such host", "DNS resolution failed"},
		{"other", "something unexpected", "something unexpected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(errString(tt.err))
			if got != tt.expect {
				t.Errorf("classifyError(%q) = %q, want %q", tt.err, got, tt.expect)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestAllowedNSEScripts(t *testing.T) {
	expected := []string{"ssl-cert", "http-title", "http-headers", "dns-zone-transfer", "banner", "smtp-commands"}
	for _, s := range expected {
		if !allowedNSEScripts[s] {
			t.Errorf("expected %q in allowed scripts", s)
		}
	}
	if allowedNSEScripts["vuln"] {
		t.Error("vuln should not be in allowed scripts")
	}
	if allowedNSEScripts["exploit"] {
		t.Error("exploit should not be in allowed scripts")
	}
}

func TestParseNmapXML_ValidXML(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" startstr="Mon Feb 24 12:00:00 2026" version="7.95">
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25"/>
        <script id="ssl-cert" output="Subject: commonName=example.com"/>
        <script id="http-title" output="Example Domain"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished timestr="Mon Feb 24 12:00:05 2026" elapsed="5.00"/>
  </runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["scanner"] != "nmap" {
		t.Errorf("expected scanner 'nmap', got %v", result["scanner"])
	}
	if result["version"] != "7.95" {
		t.Errorf("expected version '7.95', got %v", result["version"])
	}

	hosts, ok := result["hosts"].([]map[string]any)
	if !ok || len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %v", result["hosts"])
	}
	if hosts[0]["status"] != "up" {
		t.Errorf("expected status 'up', got %v", hosts[0]["status"])
	}

	ports, ok := hosts[0]["ports"].([]map[string]any)
	if !ok || len(ports) != 1 {
		t.Fatalf("expected 1 port, got %v", hosts[0]["ports"])
	}
	if ports[0]["port"] != 443 {
		t.Errorf("expected port 443, got %v", ports[0]["port"])
	}
	if ports[0]["service"] != "https" {
		t.Errorf("expected service 'https', got %v", ports[0]["service"])
	}
	if ports[0]["product"] != "nginx" {
		t.Errorf("expected product 'nginx', got %v", ports[0]["product"])
	}
}

func TestParseNmapXML_InvalidXML(t *testing.T) {
	result := parseNmapXML("not xml at all")
	if result != nil {
		t.Error("expected nil for invalid XML")
	}
}

func TestParseNmapXML_EmptyHosts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <runstats><finished elapsed="0.5"/></runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"]
	if hosts != nil {
		hostSlice, ok := hosts.([]map[string]any)
		if ok && len(hostSlice) != 0 {
			t.Errorf("expected 0 hosts, got %d", len(hostSlice))
		}
	}
}

func TestParseNmapXML_MultiplePortsAndScripts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4"/>
        <script id="http-title" output="Welcome"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" tunnel="ssl"/>
        <script id="ssl-cert" output="Subject Alternative Name: DNS:example.com"/>
        <script id="http-headers" output="HTTP/1.1 200 OK"/>
      </port>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack"/>
        <service name="smtp" product="Postfix"/>
        <script id="smtp-commands" output="EHLO commands"/>
        <script id="banner" output="220 mail.example.com ESMTP"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="3.00"/></runstats>
</nmaprun>`

	result := parseNmapXML(xml)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	hosts := result["hosts"].([]map[string]any)
	ports := hosts[0]["ports"].([]map[string]any)
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}

	for _, p := range ports {
		scripts, ok := p["scripts"].([]map[string]any)
		if !ok {
			continue
		}
		for _, s := range scripts {
			if s["id"] == "" {
				t.Error("script ID should not be empty")
			}
		}
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %s", body["status"])
	}
}

func TestHandleHealth(t *testing.T) {
	hostname = "test-host"
	startTime = startTime

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", body["status"])
	}
	if body["version"] != probeVersion {
		t.Errorf("expected version %s, got %v", probeVersion, body["version"])
	}
	if body["hostname"] != "test-host" {
		t.Errorf("expected hostname 'test-host', got %v", body["hostname"])
	}
}

func TestAuthMiddleware_Unauthorized(t *testing.T) {
	probeKey = "test-secret-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	probeKey = "correct-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	req.Header.Set("X-Probe-Key", "wrong-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_Authorized(t *testing.T) {
	probeKey = "correct-key"
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest("POST", "/probe/test", nil)
	req.Header.Set("X-Probe-Key", "correct-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rateMu.Lock()
	rateCount = make(map[string]int)
	rateMu.Unlock()

	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d should succeed, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after 20 requests, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_EmptyHosts(t *testing.T) {
	body := `{"hosts": []}`
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSMTPProbe_InvalidHostname(t *testing.T) {
	body := `{"hosts": ["evil;rm -rf /"]}`
	req := httptest.NewRequest("POST", "/probe/smtp", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleSMTPProbe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_EmptyHost(t *testing.T) {
	body := `{"host": ""}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidHostname(t *testing.T) {
	body := `{"host": "--interactive"}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for flag-like hostname, got %d", w.Code)
	}
}

func TestHandleNmapScan_InvalidPorts(t *testing.T) {
	body := `{"host": "example.com", "ports": "80;whoami"}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ports, got %d", w.Code)
	}
}

func TestHandleNmapScan_RejectedScripts(t *testing.T) {
	body := `{"host": "example.com", "scripts": ["ssl-cert", "vuln", "exploit"]}`
	req := httptest.NewRequest("POST", "/probe/nmap", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleNmapScan(w, req)

	if w.Code == http.StatusBadRequest {
		t.Error("should accept request with some valid scripts even if others are rejected")
	}
}

func TestHandleTestSSL_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/testssl", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleTestSSL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleTestSSL_InvalidHostname(t *testing.T) {
	body := `{"host": "evil;cmd"}`
	req := httptest.NewRequest("POST", "/probe/testssl", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleTestSSL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hostname, got %d", w.Code)
	}
}

func TestHandleDANEVerify_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/probe/dane-verify", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleDANEVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDANEVerify_InvalidHostname(t *testing.T) {
	body := `{"host": "evil|cmd"}`
	req := httptest.NewRequest("POST", "/probe/dane-verify", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleDANEVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hostname, got %d", w.Code)
	}
}

func TestMaxSMTPResponseSize(t *testing.T) {
	if maxSMTPResponseSize != 64*1024 {
		t.Errorf("expected maxSMTPResponseSize to be 64KB, got %d", maxSMTPResponseSize)
	}
}
