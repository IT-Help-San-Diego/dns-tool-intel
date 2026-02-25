package main

import (
        "bytes"
        "context"
        "crypto/subtle"
        "crypto/tls"
        "encoding/json"
        "encoding/xml"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "os"
        "os/exec"
        "os/signal"
        "strings"
        "sync"
        "syscall"
        "time"
)

const (
        probeVersion    = "2.1.0"
        maxRequestBody  = 64 * 1024
        maxHosts        = 10
        smtpDialTimeout = 3 * time.Second
        smtpReadTimeout = 2 * time.Second
        tlsTimeout      = 4 * time.Second
        requestTimeout  = 45 * time.Second
)

var (
        probeKey  string
        hostname  string
        startTime time.Time

        rateMu    sync.Mutex
        rateCount = make(map[string]int)
)

func main() {
        probeKey = os.Getenv("PROBE_KEY")
        if probeKey == "" {
                slog.Error("PROBE_KEY environment variable is required")
                os.Exit(1)
        }

        port := os.Getenv("PROBE_PORT")
        if port == "" {
                port = "8443"
        }

        hostname, _ = os.Hostname()
        startTime = time.Now()

        mux := http.NewServeMux()
        mux.HandleFunc("GET /health", handleHealth)
        mux.HandleFunc("POST /probe/smtp", authMiddleware(rateLimitMiddleware(handleSMTPProbe)))
        mux.HandleFunc("POST /probe/testssl", authMiddleware(rateLimitMiddleware(handleTestSSL)))
        mux.HandleFunc("POST /probe/dane-verify", authMiddleware(rateLimitMiddleware(handleDANEVerify)))
        mux.HandleFunc("POST /probe/nmap", authMiddleware(rateLimitMiddleware(handleNmapScan)))

        go resetRateLimits()

        server := &http.Server{
                Addr:         ":" + port,
                Handler:      mux,
                ReadTimeout:  30 * time.Second,
                WriteTimeout: 120 * time.Second,
                IdleTimeout:  120 * time.Second,
        }

        go func() {
                slog.Info("DNS Tool Probe Server starting", "port", port, "version", probeVersion, "hostname", hostname)
                if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        slog.Error("Server failed", "error", err)
                        os.Exit(1)
                }
        }()

        quit := make(chan os.Signal, 1)
        signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
        <-quit
        slog.Info("Shutting down probe server...")
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        server.Shutdown(ctx)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                key := r.Header.Get("X-Probe-Key")
                if subtle.ConstantTimeCompare([]byte(key), []byte(probeKey)) != 1 {
                        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
                        return
                }
                next(w, r)
        }
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                ip := strings.Split(r.RemoteAddr, ":")[0]
                rateMu.Lock()
                rateCount[ip]++
                count := rateCount[ip]
                rateMu.Unlock()
                if count > 20 {
                        http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
                        return
                }
                next(w, r)
        }
}

func resetRateLimits() {
        for {
                time.Sleep(1 * time.Minute)
                rateMu.Lock()
                rateCount = make(map[string]int)
                rateMu.Unlock()
        }
}

func writeJSON(w http.ResponseWriter, status int, v any) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(v)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, http.StatusOK, map[string]any{
                "status":   "ok",
                "version":  probeVersion,
                "hostname": hostname,
                "uptime":   time.Since(startTime).String(),
                "time":     time.Now().UTC().Format(time.RFC3339),
        })
}

func handleSMTPProbe(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
                return
        }

        var req struct {
                Hosts []string `json:"hosts"`
                Ports []int    `json:"ports"`
        }
        if err := json.Unmarshal(body, &req); err != nil || len(req.Hosts) == 0 {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: hosts required"})
                return
        }

        if len(req.Hosts) > maxHosts {
                req.Hosts = req.Hosts[:maxHosts]
        }
        for _, h := range req.Hosts {
                if !isValidHostname(h) {
                        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname: " + truncate(h, 40)})
                        return
                }
        }
        if len(req.Ports) == 0 {
                req.Ports = []int{25, 465, 587}
        }

        ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
        defer cancel()

        servers := probeAllServers(ctx, req.Hosts)

        var allPorts []map[string]any
        for _, host := range req.Hosts {
                for _, port := range req.Ports {
                        if port == 25 {
                                continue
                        }
                        result := probePort(ctx, host, port)
                        allPorts = append(allPorts, result)
                }
        }

        writeJSON(w, http.StatusOK, map[string]any{
                "probe_host":      hostname,
                "version":         probeVersion,
                "elapsed_seconds": time.Since(start).Seconds(),
                "servers":         servers,
                "all_ports":       allPorts,
        })
}

func probeAllServers(ctx context.Context, hosts []string) []map[string]any {
        var mu sync.Mutex
        var wg sync.WaitGroup
        servers := make([]map[string]any, 0, len(hosts))

        for _, host := range hosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        result := probeSMTPServer(ctx, h)
                        mu.Lock()
                        servers = append(servers, result)
                        mu.Unlock()
                }(host)
        }
        wg.Wait()
        return servers
}

func probeSMTPServer(ctx context.Context, host string) map[string]any {
        result := map[string]any{
                "host":                host,
                "reachable":           false,
                "starttls":            false,
                "tls_version":         nil,
                "cipher":              nil,
                "cipher_bits":         nil,
                "cert_valid":          false,
                "cert_expiry":         nil,
                "cert_days_remaining": nil,
                "cert_issuer":         nil,
                "cert_subject":        nil,
                "error":               nil,
        }

        probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(host, "25"))
        if err != nil {
                result["error"] = classifyError(err)
                return result
        }
        defer conn.Close()
        result["reachable"] = true

        banner, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil || !strings.HasPrefix(banner, "220") {
                result["error"] = "Unexpected SMTP banner"
                return result
        }

        fmt.Fprintf(conn, "EHLO probe.dns-observe.com\r\n")
        ehlo, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil {
                result["error"] = "EHLO response timeout"
                return result
        }

        if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
                result["error"] = "STARTTLS not supported"
                return result
        }
        result["starttls"] = true

        fmt.Fprintf(conn, "STARTTLS\r\n")
        startResp, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil || !strings.HasPrefix(startResp, "220") {
                result["error"] = "STARTTLS rejected"
                return result
        }

        tlsCfg := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: true,
        }
        tlsConn := tls.Client(conn, tlsCfg)
        if err := tlsConn.HandshakeContext(probeCtx); err != nil {
                result["error"] = fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 80))
                return result
        }
        defer tlsConn.Close()

        state := tlsConn.ConnectionState()
        result["tls_version"] = tlsVersionString(state.Version)
        result["cipher"] = tls.CipherSuiteName(state.CipherSuite)
        result["cipher_bits"] = cipherBits(state.CipherSuite)

        verifySMTPCert(probeCtx, host, result)

        return result
}

func verifySMTPCert(ctx context.Context, host string, result map[string]any) {
        verifyCtx, cancel := context.WithTimeout(ctx, tlsTimeout)
        defer cancel()

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(verifyCtx, "tcp", net.JoinHostPort(host, "25"))
        if err != nil {
                return
        }
        defer conn.Close()

        banner, _ := readSMTPResponse(conn, 1*time.Second)
        if !strings.HasPrefix(banner, "220") {
                return
        }
        fmt.Fprintf(conn, "EHLO probe.dns-observe.com\r\n")
        readSMTPResponse(conn, 1*time.Second)
        fmt.Fprintf(conn, "STARTTLS\r\n")
        resp, _ := readSMTPResponse(conn, 1*time.Second)
        if !strings.HasPrefix(resp, "220") {
                return
        }

        verifyCfg := &tls.Config{ServerName: host}
        verifyTLS := tls.Client(conn, verifyCfg)
        defer verifyTLS.Close()

        if err := verifyTLS.HandshakeContext(verifyCtx); err != nil {
                result["cert_valid"] = false
                result["error"] = fmt.Sprintf("Certificate invalid: %s", truncate(err.Error(), 100))
                return
        }

        result["cert_valid"] = true
        certs := verifyTLS.ConnectionState().PeerCertificates
        if len(certs) > 0 {
                leaf := certs[0]
                result["cert_expiry"] = leaf.NotAfter.Format("2006-01-02")
                result["cert_days_remaining"] = int(time.Until(leaf.NotAfter).Hours() / 24)
                result["cert_subject"] = leaf.Subject.CommonName
                if len(leaf.Issuer.Organization) > 0 {
                        result["cert_issuer"] = leaf.Issuer.Organization[0]
                } else {
                        result["cert_issuer"] = leaf.Issuer.CommonName
                }
        }
}

func probePort(ctx context.Context, host string, port int) map[string]any {
        result := map[string]any{
                "host":      host,
                "port":      port,
                "reachable": false,
                "tls":       false,
                "error":     nil,
        }

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
        if err != nil {
                result["error"] = classifyError(err)
                return result
        }
        defer conn.Close()
        result["reachable"] = true

        if port == 465 {
                tlsCfg := &tls.Config{
                        ServerName:         host,
                        InsecureSkipVerify: true,
                }
                tlsConn := tls.Client(conn, tlsCfg)
                if err := tlsConn.HandshakeContext(ctx); err == nil {
                        result["tls"] = true
                        state := tlsConn.ConnectionState()
                        result["tls_version"] = tlsVersionString(state.Version)
                }
                tlsConn.Close()
        }

        return result
}

func handleTestSSL(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
                return
        }

        var req struct {
                Host string `json:"host"`
                Port int    `json:"port"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: host required"})
                return
        }
        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname"})
                return
        }
        if req.Port == 0 {
                req.Port = 25
        }

        testsslPath, err := exec.LookPath("testssl.sh")
        if err != nil {
                testsslPath, err = exec.LookPath("testssl")
                if err != nil {
                        writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "testssl.sh not installed"})
                        return
                }
        }

        ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
        defer cancel()

        target := fmt.Sprintf("%s:%d", req.Host, req.Port)
        args := []string{
                "--jsonfile", "/dev/stdout",
                "--quiet",
                "--sneaky",
                "--fast",
                "--ip", "one",
                "--warnings", "off",
        }
        if req.Port == 25 {
                args = append(args, "--starttls", "smtp")
        }
        args = append(args, target)

        cmd := exec.CommandContext(ctx, testsslPath, args...)
        cmd.Env = append(os.Environ(), "TERM=xterm")
        output, err := cmd.Output()

        response := map[string]any{
                "probe_host":      hostname,
                "version":         probeVersion,
                "host":            req.Host,
                "port":            req.Port,
                "elapsed_seconds": time.Since(start).Seconds(),
        }

        if err != nil {
                response["status"] = "error"
                response["error"] = fmt.Sprintf("testssl.sh failed: %s", truncate(err.Error(), 200))
                if len(output) > 0 {
                        response["partial_output"] = string(output[:min(len(output), 4096)])
                }
                writeJSON(w, http.StatusOK, response)
                return
        }

        var testsslResult any
        if err := json.Unmarshal(output, &testsslResult); err != nil {
                response["status"] = "raw"
                response["raw_output"] = string(output[:min(len(output), 32768)])
        } else {
                response["status"] = "ok"
                response["testssl"] = testsslResult
        }

        writeJSON(w, http.StatusOK, response)
}

func handleDANEVerify(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
                return
        }

        var req struct {
                Host string `json:"host"`
                Port int    `json:"port"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: host required"})
                return
        }
        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname"})
                return
        }
        if req.Port == 0 {
                req.Port = 25
        }

        ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
        defer cancel()

        response := map[string]any{
                "probe_host":      hostname,
                "version":         probeVersion,
                "host":            req.Host,
                "port":            req.Port,
                "elapsed_seconds": 0.0,
        }

        tlsaName := fmt.Sprintf("_%d._tcp.%s", req.Port, req.Host)
        digCtx, digCancel := context.WithTimeout(ctx, 8*time.Second)
        defer digCancel()
        digCmd := exec.CommandContext(digCtx, "dig", "+short", "TLSA", tlsaName)
        tlsaOut, err := digCmd.Output()
        tlsaRecords := strings.TrimSpace(string(tlsaOut))

        if err != nil || tlsaRecords == "" {
                response["status"] = "no_tlsa"
                response["message"] = fmt.Sprintf("No TLSA records found at %s", tlsaName)
                response["elapsed_seconds"] = time.Since(start).Seconds()
                writeJSON(w, http.StatusOK, response)
                return
        }

        response["tlsa_records"] = strings.Split(tlsaRecords, "\n")

        var certInfo map[string]any
        if req.Port == 25 {
                certInfo = getCertViaSMTP(ctx, req.Host)
        } else {
                certInfo = getCertViaTLS(ctx, req.Host, req.Port)
        }
        response["cert"] = certInfo

        if certInfo["error"] != nil {
                response["status"] = "cert_error"
        } else {
                response["status"] = "verified"
        }

        response["elapsed_seconds"] = time.Since(start).Seconds()
        writeJSON(w, http.StatusOK, response)
}

func getCertViaSMTP(ctx context.Context, host string) map[string]any {
        result := map[string]any{"method": "smtp_starttls"}

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
        if err != nil {
                result["error"] = classifyError(err)
                return result
        }
        defer conn.Close()

        banner, _ := readSMTPResponse(conn, smtpReadTimeout)
        if !strings.HasPrefix(banner, "220") {
                result["error"] = "Bad SMTP banner"
                return result
        }

        fmt.Fprintf(conn, "EHLO probe.dns-observe.com\r\n")
        ehlo, _ := readSMTPResponse(conn, smtpReadTimeout)
        if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
                result["error"] = "STARTTLS not supported"
                return result
        }

        fmt.Fprintf(conn, "STARTTLS\r\n")
        resp, _ := readSMTPResponse(conn, smtpReadTimeout)
        if !strings.HasPrefix(resp, "220") {
                result["error"] = "STARTTLS rejected"
                return result
        }

        return extractCertInfo(conn, host)
}

func getCertViaTLS(ctx context.Context, host string, port int) map[string]any {
        result := map[string]any{"method": "direct_tls"}

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
        if err != nil {
                result["error"] = classifyError(err)
                return result
        }
        defer conn.Close()

        return extractCertInfo(conn, host)
}

func extractCertInfo(conn net.Conn, host string) map[string]any {
        result := map[string]any{}

        tlsCfg := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: true,
        }
        tlsConn := tls.Client(conn, tlsCfg)
        defer tlsConn.Close()

        if err := tlsConn.Handshake(); err != nil {
                result["error"] = fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 100))
                return result
        }

        state := tlsConn.ConnectionState()
        result["tls_version"] = tlsVersionString(state.Version)
        result["cipher"] = tls.CipherSuiteName(state.CipherSuite)

        if len(state.PeerCertificates) > 0 {
                leaf := state.PeerCertificates[0]
                result["subject"] = leaf.Subject.CommonName
                result["sans"] = leaf.DNSNames
                result["not_before"] = leaf.NotBefore.Format(time.RFC3339)
                result["not_after"] = leaf.NotAfter.Format(time.RFC3339)
                result["days_remaining"] = int(time.Until(leaf.NotAfter).Hours() / 24)
                if len(leaf.Issuer.Organization) > 0 {
                        result["issuer"] = leaf.Issuer.Organization[0]
                } else {
                        result["issuer"] = leaf.Issuer.CommonName
                }

                result["fingerprint_sha256"] = fmt.Sprintf("%x", leaf.Raw)
                result["serial"] = leaf.SerialNumber.String()
        }

        return result
}

const maxSMTPResponseSize = 64 * 1024

func readSMTPResponse(conn net.Conn, timeout time.Duration) (string, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := make([]byte, 4096)
        var response strings.Builder
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        response.Write(buf[:n])
                        if response.Len() > maxSMTPResponseSize {
                                return response.String(), fmt.Errorf("SMTP response exceeded %d bytes", maxSMTPResponseSize)
                        }
                        if smtpComplete(response.String()) {
                                break
                        }
                }
                if err != nil {
                        if response.Len() > 0 {
                                return response.String(), nil
                        }
                        return "", err
                }
        }
        return response.String(), nil
}

func smtpComplete(data string) bool {
        lines := strings.Split(data, "\n")
        last := strings.TrimSpace(lines[len(lines)-1])
        if last == "" && len(lines) > 1 {
                last = strings.TrimSpace(lines[len(lines)-2])
        }
        return len(last) >= 4 && last[3] == ' '
}

func classifyError(err error) string {
        s := err.Error()
        if strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
                return "Connection timeout"
        }
        if strings.Contains(s, "refused") {
                return "Connection refused"
        }
        if strings.Contains(s, "unreachable") {
                return "Network unreachable"
        }
        if strings.Contains(s, "no such host") {
                return "DNS resolution failed"
        }
        return truncate(s, 80)
}

func tlsVersionString(v uint16) string {
        switch v {
        case tls.VersionTLS13:
                return "TLSv1.3"
        case tls.VersionTLS12:
                return "TLSv1.2"
        case tls.VersionTLS11:
                return "TLSv1.1"
        case tls.VersionTLS10:
                return "TLSv1.0"
        default:
                return fmt.Sprintf("TLS 0x%04x", v)
        }
}

func cipherBits(suite uint16) int {
        name := tls.CipherSuiteName(suite)
        if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
                return 256
        }
        if strings.Contains(name, "128") {
                return 128
        }
        return 0
}

func truncate(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen]
}

func isValidHostname(host string) bool {
        if len(host) == 0 || len(host) > 253 {
                return false
        }
        if strings.HasPrefix(host, "-") || strings.HasPrefix(host, ".") {
                return false
        }
        for _, ch := range host {
                if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                        return false
                }
        }
        return true
}

var allowedNSEScripts = map[string]bool{
        "ssl-cert":          true,
        "http-title":        true,
        "http-headers":      true,
        "dns-zone-transfer": true,
        "banner":            true,
        "smtp-commands":     true,
}

func handleNmapScan(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
                return
        }

        var req struct {
                Host    string   `json:"host"`
                Ports   string   `json:"ports"`
                Scripts []string `json:"scripts"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: host required"})
                return
        }

        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hostname"})
                return
        }

        if req.Ports == "" {
                req.Ports = "25,80,443,465,587"
        }
        for _, ch := range req.Ports {
                if ch != ',' && (ch < '0' || ch > '9') && ch != '-' {
                        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid port specification"})
                        return
                }
        }

        var validScripts []string
        var rejectedScripts []string
        for _, s := range req.Scripts {
                s = strings.TrimSpace(s)
                if allowedNSEScripts[s] {
                        validScripts = append(validScripts, s)
                } else if s != "" {
                        rejectedScripts = append(rejectedScripts, s)
                }
        }
        if len(validScripts) == 0 {
                validScripts = []string{"ssl-cert", "http-title", "banner"}
        }

        nmapPath, err := exec.LookPath("nmap")
        if err != nil {
                writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "nmap not installed"})
                return
        }

        ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
        defer cancel()

        args := []string{
                "-Pn",
                "-sV",
                "--open",
                "-p", req.Ports,
                "--script", strings.Join(validScripts, ","),
                "-oX", "-",
                "--host-timeout", "60s",
                "--max-retries", "2",
                req.Host,
        }

        slog.Info("Nmap scan requested", "host", req.Host, "ports", req.Ports, "scripts", validScripts)

        cmd := exec.CommandContext(ctx, nmapPath, args...)
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err = cmd.Run()

        response := map[string]any{
                "probe_host":       hostname,
                "version":          probeVersion,
                "host":             req.Host,
                "ports":            req.Ports,
                "scripts_run":      validScripts,
                "elapsed_seconds":  time.Since(start).Seconds(),
        }

        if len(rejectedScripts) > 0 {
                response["rejected_scripts"] = rejectedScripts
        }

        xmlOutput := stdout.String()
        if err != nil {
                response["status"] = "error"
                response["error"] = fmt.Sprintf("nmap failed: %s", truncate(err.Error(), 200))
                if xmlOutput != "" {
                        response["partial_xml"] = truncate(xmlOutput, 8192)
                }
                stderrStr := strings.TrimSpace(stderr.String())
                if stderrStr != "" {
                        response["stderr"] = truncate(stderrStr, 1024)
                }
        } else {
                response["status"] = "ok"
                response["xml"] = xmlOutput
                parsed := parseNmapXML(xmlOutput)
                if parsed != nil {
                        response["parsed"] = parsed
                }
        }

        writeJSON(w, http.StatusOK, response)
}

func parseNmapXML(xmlData string) map[string]any {
        type NmapPort struct {
                Protocol string `xml:"protocol,attr"`
                PortID   int    `xml:"portid,attr"`
                State    struct {
                        State  string `xml:"state,attr"`
                        Reason string `xml:"reason,attr"`
                } `xml:"state"`
                Service struct {
                        Name    string `xml:"name,attr"`
                        Product string `xml:"product,attr"`
                        Version string `xml:"version,attr"`
                        Tunnel  string `xml:"tunnel,attr"`
                } `xml:"service"`
                Scripts []struct {
                        ID     string `xml:"id,attr"`
                        Output string `xml:"output,attr"`
                        Tables []struct {
                                Key  string `xml:"key,attr"`
                                Elems []struct {
                                        Key   string `xml:"key,attr"`
                                        Value string `xml:",chardata"`
                                } `xml:"elem"`
                        } `xml:"table"`
                } `xml:"script"`
        }

        type NmapHost struct {
                Status struct {
                        State string `xml:"state,attr"`
                } `xml:"status"`
                Addresses []struct {
                        Addr     string `xml:"addr,attr"`
                        AddrType string `xml:"addrtype,attr"`
                } `xml:"address"`
                Hostnames []struct {
                        Name string `xml:"name,attr"`
                        Type string `xml:"type,attr"`
                } `xml:"hostnames>hostname"`
                Ports []NmapPort `xml:"ports>port"`
        }

        type NmapRun struct {
                Scanner   string     `xml:"scanner,attr"`
                StartStr  string     `xml:"startstr,attr"`
                Version   string     `xml:"version,attr"`
                Hosts     []NmapHost `xml:"host"`
                RunStats  struct {
                        Finished struct {
                                TimeStr string `xml:"timestr,attr"`
                                Elapsed string `xml:"elapsed,attr"`
                        } `xml:"finished"`
                } `xml:"runstats"`
        }

        var nmapRun NmapRun
        if err := xml.Unmarshal([]byte(xmlData), &nmapRun); err != nil {
                return nil
        }

        result := map[string]any{
                "scanner":   nmapRun.Scanner,
                "version":   nmapRun.Version,
                "start":     nmapRun.StartStr,
                "elapsed":   nmapRun.RunStats.Finished.Elapsed,
        }

        var hosts []map[string]any
        for _, h := range nmapRun.Hosts {
                host := map[string]any{
                        "status": h.Status.State,
                }

                var addrs []map[string]string
                for _, a := range h.Addresses {
                        addrs = append(addrs, map[string]string{
                                "addr": a.Addr,
                                "type": a.AddrType,
                        })
                }
                host["addresses"] = addrs

                var names []string
                for _, hn := range h.Hostnames {
                        names = append(names, hn.Name)
                }
                if len(names) > 0 {
                        host["hostnames"] = names
                }

                var ports []map[string]any
                for _, p := range h.Ports {
                        port := map[string]any{
                                "port":     p.PortID,
                                "protocol": p.Protocol,
                                "state":    p.State.State,
                                "service":  p.Service.Name,
                        }
                        if p.Service.Product != "" {
                                port["product"] = p.Service.Product
                        }
                        if p.Service.Version != "" {
                                port["version"] = p.Service.Version
                        }
                        if p.Service.Tunnel != "" {
                                port["tunnel"] = p.Service.Tunnel
                        }

                        var scripts []map[string]any
                        for _, s := range p.Scripts {
                                script := map[string]any{
                                        "id":     s.ID,
                                        "output": s.Output,
                                }
                                scripts = append(scripts, script)
                        }
                        if len(scripts) > 0 {
                                port["scripts"] = scripts
                        }

                        ports = append(ports, port)
                }
                host["ports"] = ports
                hosts = append(hosts, host)
        }
        result["hosts"] = hosts

        return result
}
