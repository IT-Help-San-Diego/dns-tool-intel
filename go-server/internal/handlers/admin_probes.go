// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "os"
        "os/exec"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

const (
        mapKeyAction  = "action"
        mapKeyAudit   = "audit"
        mapKeyHealth  = "health"
        mapKeyRestart = "restart"
        mapKeyUpdate  = "update"
        strProbe01    = "probe-01"
        strProbe02    = "probe-02"
)

type ProbeAdminHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewProbeAdminHandler(database *db.Database, cfg *config.Config) *ProbeAdminHandler {
        return &ProbeAdminHandler{DB: database, Config: cfg}
}

type probeInfo struct {
        ID    string
        Label string
        URL   string
}

type probeActionResult struct {
        Probe   probeInfo
        Action  string
        Success bool
        Output  string
        Elapsed float64
}

func (h *ProbeAdminHandler) configuredProbes() []probeInfo {
        var probes []probeInfo
        if url := os.Getenv("PROBE_API_URL"); url != "" {
                label := os.Getenv("PROBE_LABEL")
                if label == "" {
                        label = "US-East (Boston)"
                }
                probes = append(probes, probeInfo{ID: strProbe01, Label: label, URL: url})
        }
        if url := os.Getenv("PROBE_API_URL_2"); url != "" {
                label := os.Getenv("PROBE_LABEL_2")
                if label == "" {
                        label = "US-East (Kali/02)"
                }
                probes = append(probes, probeInfo{ID: strProbe02, Label: label, URL: url})
        }
        return probes
}

func (h *ProbeAdminHandler) ProbeDashboard(c *gin.Context) {
        probes := h.configuredProbes()

        var healthResults []probeActionResult
        for _, p := range probes {
                result := checkProbeHealth(p)
                healthResults = append(healthResults, result)
        }

        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                "CsrfToken":       csrfToken,
                keyActivePage:      "admin",
                "Probes":          probes,
                "HealthResults":   healthResults,
        }
        mergeAuthData(c, h.Config, data)

        if actionResult, ok := c.Get("probeActionResult"); ok {
                data["ActionResult"] = actionResult
        }

        c.HTML(http.StatusOK, "admin_probes.html", data)
}

func (h *ProbeAdminHandler) RunProbeAction(c *gin.Context) {
        probeID := c.Param("id")
        action := c.Param(mapKeyAction)

        probes := h.configuredProbes()
        var target *probeInfo
        for i := range probes {
                if probes[i].ID == probeID {
                        target = &probes[i]
                        break
                }
        }
        if target == nil {
                c.String(http.StatusNotFound, "Probe not found")
                return
        }

        slog.Info("Admin: probe action requested", "probe", probeID, mapKeyAction, action)

        var result probeActionResult
        switch action {
        case mapKeyHealth:
                result = checkProbeHealth(*target)
        case mapKeyUpdate:
                result = runProbeSSH(*target, mapKeyUpdate)
        case mapKeyRestart:
                result = runProbeSSH(*target, mapKeyRestart)
        case mapKeyAudit:
                result = runProbeSSH(*target, mapKeyAudit)
        default:
                c.String(http.StatusBadRequest, "Unknown action")
                return
        }

        slog.Info("Admin: probe action completed", "probe", probeID, mapKeyAction, action, "success", result.Success)

        c.Set("probeActionResult", result)
        h.ProbeDashboard(c)
}

func checkProbeHealth(p probeInfo) probeActionResult {
        start := time.Now()
        client := &http.Client{
                Timeout: 10 * time.Second,
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
                },
        }

        resp, err := client.Get(p.URL + "/health")
        elapsed := time.Since(start).Seconds()

        if err != nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  mapKeyHealth,
                        Success: false,
                        Output:  fmt.Sprintf("Connection failed: %v", err),
                        Elapsed: elapsed,
                }
        }
        defer safeClose(resp.Body, "probe-health-response")

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

        var pretty bytes.Buffer
        if json.Indent(&pretty, body, "", "  ") == nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  mapKeyHealth,
                        Success: resp.StatusCode == 200,
                        Output:  pretty.String(),
                        Elapsed: elapsed,
                }
        }

        return probeActionResult{
                Probe:   p,
                Action:  mapKeyHealth,
                Success: resp.StatusCode == 200,
                Output:  string(body),
                Elapsed: elapsed,
        }
}

func runProbeSSH(p probeInfo, action string) probeActionResult {
        start := time.Now()

        sshConfig, err := resolveProbeSSH(p.ID)
        if err != nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  action,
                        Success: false,
                        Output:  fmt.Sprintf("SSH config error: %v", err),
                        Elapsed: time.Since(start).Seconds(),
                }
        }

        var script string
        switch action {
        case mapKeyUpdate:
                script = probeUpdateScript()
        case mapKeyRestart:
                script = probeRestartScript()
        case mapKeyAudit:
                script = probeAuditScript()
        default:
                return probeActionResult{
                        Probe:   p,
                        Action:  action,
                        Success: false,
                        Output:  "Unknown action: " + action,
                        Elapsed: time.Since(start).Seconds(),
                }
        }

        ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
        defer cancel()

        output, err := executeSSH(ctx, sshConfig, script)
        elapsed := time.Since(start).Seconds()

        if err != nil {
                slog.Error("Probe SSH action failed",
                        "probe", p.ID,
                        mapKeyAction, action,
                        "error", err.Error(),
                        "output", output,
                        "elapsed_s", elapsed)
                if output == "" {
                        output = fmt.Sprintf("SSH error: %v", err)
                }
        }

        return probeActionResult{
                Probe:   p,
                Action:  action,
                Success: err == nil,
                Output:  output,
                Elapsed: elapsed,
        }
}

type sshTarget struct {
        host    string
        user    string
        keyFile string
}

func resolveProbeSSH(probeID string) (*sshTarget, error) {
        switch probeID {
        case strProbe01:
                host := os.Getenv("PROBE_SSH_HOST")
                user := os.Getenv("PROBE_SSH_USER")
                keyB64 := os.Getenv("PROBE_SSH_PRIVATE_KEY")
                if host == "" || user == "" || keyB64 == "" {
                        return nil, fmt.Errorf("probe-01 SSH credentials not configured (PROBE_SSH_HOST, PROBE_SSH_USER, PROBE_SSH_PRIVATE_KEY)")
                }
                keyFile, err := writeKeyFile(keyB64, strProbe01)
                if err != nil {
                        return nil, err
                }
                return &sshTarget{host: host, user: user, keyFile: keyFile}, nil
        case strProbe02:
                host := os.Getenv("PROBE_SSH_HOST_2")
                user := os.Getenv("PROBE2_SSH_USER")
                keyB64 := os.Getenv("PROBE_SSH_PRIVATE_KEY_2")
                if host == "" || user == "" || keyB64 == "" {
                        return nil, fmt.Errorf("probe-02 SSH credentials not configured (PROBE_SSH_HOST_2, PROBE2_SSH_USER, PROBE_SSH_PRIVATE_KEY_2)")
                }
                keyFile, err := writeKeyFile(keyB64, strProbe02)
                if err != nil {
                        return nil, err
                }
                return &sshTarget{host: host, user: user, keyFile: keyFile}, nil
        default:
                return nil, fmt.Errorf("unknown probe: %s", probeID)
        }
}

func writeKeyFile(b64Key, label string) (string, error) {
        decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Key))
        if err != nil {
                raw := strings.TrimSpace(b64Key)
                if strings.HasPrefix(raw, "-----BEGIN") {
                        decoded = []byte(raw)
                } else {
                        return "", fmt.Errorf("failed to decode SSH key for %s: %w", label, err)
                }
        }

        tmpFile, err := os.CreateTemp("", "probe-ssh-*.key")
        if err != nil {
                return "", fmt.Errorf("failed to create temp key file: %w", err)
        }
        if _, err := tmpFile.Write(decoded); err != nil {
                tmpFile.Close()
                os.Remove(tmpFile.Name())
                return "", err
        }
        tmpFile.Close()
        if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
                os.Remove(tmpFile.Name())
                return "", fmt.Errorf("failed to set key file permissions: %w", err)
        }
        return tmpFile.Name(), nil
}

func executeSSH(ctx context.Context, target *sshTarget, script string) (string, error) {
        defer os.Remove(target.keyFile)

        cmd := exec.CommandContext(ctx, "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes",
                "-i", target.keyFile,
                fmt.Sprintf("%s@%s", target.user, target.host),
                "bash", "-s",
        )
        cmd.Stdin = strings.NewReader(script)

        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        err := cmd.Run()
        output := strings.TrimSpace(stdout.String())
        errOutput := strings.TrimSpace(stderr.String())

        if errOutput != "" && !strings.HasPrefix(errOutput, "Warning:") {
                if output != "" {
                        output += "\n" + errOutput
                } else {
                        output = errOutput
                }
        }

        return output, err
}

func probeUpdateScript() string {
        return `set -e
export DEBIAN_FRONTEND=noninteractive
echo ">>> Starting system update on $(hostname)..."
apt-get update -qq 2>&1 | tail -5
echo ">>> Upgrading packages..."
apt-get -y -qq full-upgrade 2>&1 | tail -10
echo ">>> Removing unused packages..."
apt-get -y -qq autoremove 2>&1 | tail -5
echo ">>> Cleaning cache..."
apt-get clean
echo ">>> Services check:"
systemctl is-active dns-probe && echo "  Probe: running" || echo "  Probe: NOT running"
systemctl is-active nginx && echo "  Nginx: running" || echo "  Nginx: NOT running"
systemctl is-active fail2ban 2>/dev/null && echo "  Fail2ban: running" || echo "  Fail2ban: not installed"
echo ">>> Disk:"
df -h / | tail -1
echo ">>> UPDATE COMPLETE on $(hostname)"
`
}

func probeRestartScript() string {
        return `set -e
echo ">>> Restarting dns-probe on $(hostname)..."
systemctl restart dns-probe
sleep 2
systemctl is-active dns-probe && echo "Probe: running" || echo "Probe: FAILED TO START"
curl -s http://localhost:8443/health 2>/dev/null || echo "Health endpoint not responding"
echo ">>> RESTART COMPLETE on $(hostname)"
`
}

func probeAuditScript() string {
        return `echo "=== Security Audit: $(hostname) ==="
echo ""
echo "--- SSH Configuration ---"
sshd -T 2>/dev/null | grep -E 'passwordauthentication|permitrootlogin|maxauthtries|x11forwarding|permitemptypasswords' | sort
echo ""
echo "--- Fail2ban ---"
if systemctl is-active fail2ban >/dev/null 2>&1; then
  fail2ban-client status sshd 2>/dev/null || echo "fail2ban running but sshd jail not configured"
else
  echo "fail2ban: not active"
fi
echo ""
echo "--- Firewall (UFW) ---"
ufw status 2>/dev/null || echo "UFW not installed"
echo ""
echo "--- Listening Ports ---"
ss -tlnp | grep -v '127.0.0' | grep -v '::1'
echo ""
echo "--- Services ---"
systemctl is-active dns-probe && echo "dns-probe: active" || echo "dns-probe: INACTIVE"
systemctl is-active nginx && echo "nginx: active" || echo "nginx: INACTIVE"
echo ""
echo "--- TLS Certificate ---"
certbot certificates 2>/dev/null | grep -E 'Certificate Name|Expiry|Domains' || echo "certbot not available"
echo ""
echo "--- System ---"
uname -r
uptime
df -h / | tail -1
echo ""
echo "--- Recent Auth Failures ---"
journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed\|Invalid" | xargs -I{} echo "SSH auth failures (24h): {}"
echo ""
echo "=== AUDIT COMPLETE ==="
`
}
