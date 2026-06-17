// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "strings"
        "testing"
        "time"

        "codeberg.org/miekg/dns"

        "dnstool/go-server/internal/dnsclient"
)

type mockDNSForNmap struct {
        nsRecords map[string][]string
}

func (m *mockDNSForNmap) QueryDNS(_ context.Context, recordType, domain string) []string {
        if recordType == "NS" {
                return m.nsRecords[domain]
        }
        return nil
}

func (m *mockDNSForNmap) QueryDNSWithTTL(context.Context, string, string) dnsclient.RecordWithTTL {
        return dnsclient.RecordWithTTL{}
}
func (m *mockDNSForNmap) QueryDNSWithTTLStatus(context.Context, string, string) (dnsclient.RecordWithTTL, dnsclient.LookupStatus) {
        return dnsclient.RecordWithTTL{}, dnsclient.LookupAbsent
}
func (m *mockDNSForNmap) QueryWithConsensus(context.Context, string, string) dnsclient.ConsensusResult {
        return dnsclient.ConsensusResult{}
}
func (m *mockDNSForNmap) QuerySpecificResolver(context.Context, string, string, string) ([]string, error) {
        return nil, nil
}
func (m *mockDNSForNmap) QueryWithTTLFromResolver(context.Context, string, string, string) dnsclient.RecordWithTTL {
        return dnsclient.RecordWithTTL{}
}
func (m *mockDNSForNmap) CheckDNSSECADFlag(context.Context, string) dnsclient.ADFlagResult {
        return dnsclient.ADFlagResult{}
}
func (m *mockDNSForNmap) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
        return nil, nil
}
func (m *mockDNSForNmap) ValidateResolverConsensus(context.Context, string) map[string]any {
        return nil
}
func (m *mockDNSForNmap) ProbeExists(context.Context, string) (bool, string) {
        return false, ""
}

type mockCmdExec struct {
        lookPathResult string
        lookPathErr    error
        outputs        map[string]mockCmdResult
        allCalls       []string
}

type mockCmdResult struct {
        output []byte
        err    error
}

func (m *mockCmdExec) LookPath(file string) (string, error) {
        return m.lookPathResult, m.lookPathErr
}

func (m *mockCmdExec) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
        key := ""
        for _, a := range args {
                if strings.HasPrefix(a, "dns-") {
                        key = a
                        break
                }
        }
        m.allCalls = append(m.allCalls, key)
        if r, ok := m.outputs[key]; ok {
                return r.output, r.err
        }
        return []byte(""), nil
}

func newTestAnalyzerWithNmap(dns *mockDNSForNmap, cmd *mockCmdExec) *Analyzer {
        return &Analyzer{
                DNS:     dns,
                CmdExec: cmd,
        }
}

func TestAnalyzeNmapDNS_NilCmdExec_GracefulFallback(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        a := &Analyzer{
                DNS: dns,
        }
        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        msg, _ := result[mapKeyMessage].(string)
        if msg != "Nmap not available" {
                t.Errorf("nil CmdExec: expected 'Nmap not available', got %q", msg)
        }
}

func TestAnalyzeNmapDNS_NmapNotFound(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{lookPathErr: fmt.Errorf("exec: \"nmap\": executable file not found in $PATH")}
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        msg, _ := result[mapKeyMessage].(string)
        if msg != "Nmap not available" {
                t.Errorf("expected 'Nmap not available', got %q", msg)
        }
        status, _ := result[mapKeyStatus].(string)
        if status != "info" {
                t.Errorf("expected status 'info', got %q", status)
        }
}

func TestAnalyzeNmapDNS_NoNameservers(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{}}
        cmd := &mockCmdExec{lookPathResult: "/usr/bin/nmap"}
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        msg, _ := result[mapKeyMessage].(string)
        if msg != "No nameservers found" {
                t.Errorf("expected 'No nameservers found', got %q", msg)
        }
}

func TestAnalyzeNmapDNS_NoValidNameservers(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"; DROP TABLE", "bad;host"}}}
        cmd := &mockCmdExec{lookPathResult: "/usr/bin/nmap"}
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        msg, _ := result[mapKeyMessage].(string)
        if msg != "No valid nameservers" {
                t.Errorf("expected 'No valid nameservers', got %q", msg)
        }
}

func TestAnalyzeNmapDNS_AllClean(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com."}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("Nmap done: no transfer")},
                        "dns-recursion":     {output: []byte("Nmap done: no recursion info")},
                        "dns-nsid":          {output: []byte("Nmap done: no version info")},
                        "dns-cache-snoop":   {output: []byte("Nmap done: no snooping")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        status, _ := result[mapKeyStatus].(string)
        if status != "good" {
                t.Errorf("expected status 'good', got %q", status)
        }
        issues, _ := result[mapKeyIssues].([]string)
        if len(issues) != 0 {
                t.Errorf("expected 0 issues, got %d: %v", len(issues), issues)
        }
        nameservers, _ := result["nameservers"].([]string)
        if len(nameservers) != 1 || nameservers[0] != "ns1.example.com" {
                t.Errorf("unexpected nameservers: %v", nameservers)
        }
}

func TestAnalyzeNmapDNS_ZoneTransferVulnerable(t *testing.T) {
        ztOutput := `Starting Nmap 7.94
Nmap scan report for ns1.vulnerable.com
PORT   STATE SERVICE
53/tcp open  domain
| dns-zone-transfer:
vulnerable.com. SOA ns1.vulnerable.com. admin.vulnerable.com.
vulnerable.com. NS ns1.vulnerable.com.
vulnerable.com. NS ns2.vulnerable.com.
vulnerable.com. A 10.0.0.1
vulnerable.com. MX 10 mail.vulnerable.com.
mail.vulnerable.com. A 10.0.0.2
www.vulnerable.com. A 10.0.0.3
Transfer zone size: 7 records`

        dns := &mockDNSForNmap{nsRecords: map[string][]string{"vulnerable.com": {"ns1.vulnerable.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte(ztOutput)},
                        "dns-recursion":     {output: []byte("no recursion")},
                        "dns-nsid":          {output: []byte("no info")},
                        "dns-cache-snoop":   {output: []byte("no snoop")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "vulnerable.com")
        status, _ := result[mapKeyStatus].(string)
        if status != "warning" {
                t.Errorf("expected status 'warning', got %q", status)
        }
        issues, _ := result[mapKeyIssues].([]string)
        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "Zone transfer") {
                        found = true
                }
        }
        if !found {
                t.Errorf("expected zone transfer issue in issues list: %v", issues)
        }
        zt, _ := result["zone_transfer"].(map[string]any)
        if zt[mapKeyVulnerable] != true {
                t.Error("expected zone_transfer.vulnerable = true")
        }
}

func TestAnalyzeNmapDNS_RecursionOpen(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("no transfer")},
                        "dns-recursion":     {output: []byte("|_dns-recursion: Recursion appears to be enabled")},
                        "dns-nsid":          {output: []byte("no info")},
                        "dns-cache-snoop":   {output: []byte("no snoop")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        rec, _ := result[mapKeyRecursion].(map[string]any)
        if rec[mapKeyOpen] != true {
                t.Error("expected recursion.open = true")
        }
        issues, _ := result[mapKeyIssues].([]string)
        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "Open recursion") {
                        found = true
                }
        }
        if !found {
                t.Errorf("expected open recursion issue: %v", issues)
        }
}

func TestAnalyzeNmapDNS_NSIDDisclosed(t *testing.T) {
        nsidOutput := `| dns-nsid:
|   bind.version: 9.18.24-1~deb12u1-Debian
|_  id.server: ns1`
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("no transfer")},
                        "dns-recursion":     {output: []byte("no recursion")},
                        "dns-nsid":          {output: []byte(nsidOutput)},
                        "dns-cache-snoop":   {output: []byte("no snoop")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        nsid, _ := result[mapKeyNsid].(map[string]any)
        if nsid[mapKeyFound] != true {
                t.Error("expected nsid.found = true")
        }
        version, _ := nsid["version"].(string)
        if version != "9.18.24-1~deb12u1-Debian" {
                t.Errorf("expected bind version, got %q", version)
        }
        id, _ := nsid["id"].(string)
        if id != "ns1" {
                t.Errorf("expected id.server = ns1, got %q", id)
        }
}

func TestAnalyzeNmapDNS_CacheSnoopVulnerable(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("no transfer")},
                        "dns-recursion":     {output: []byte("no recursion")},
                        "dns-nsid":          {output: []byte("no info")},
                        "dns-cache-snoop":   {output: []byte("| dns-cache-snoop: 3 of 100 tested domains are cached.\n|_  google.com - positive")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        cs, _ := result["cache_snoop"].(map[string]any)
        if cs[mapKeyVulnerable] != true {
                t.Error("expected cache_snoop.vulnerable = true")
        }
}

func TestAnalyzeNmapDNS_ScanError_Inconclusive(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: nil, err: fmt.Errorf("nmap error")},
                        "dns-recursion":     {output: nil, err: fmt.Errorf("nmap error")},
                        "dns-nsid":          {output: nil, err: fmt.Errorf("nmap error")},
                        "dns-cache-snoop":   {output: nil, err: fmt.Errorf("nmap error")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        zt, _ := result["zone_transfer"].(map[string]any)
        if zt[mapKeyMessage] != msgTestInconclusive {
                t.Errorf("zone_transfer message: got %q, want %q", zt[mapKeyMessage], msgTestInconclusive)
        }
        rec, _ := result[mapKeyRecursion].(map[string]any)
        if rec[mapKeyMessage] != msgTestInconclusive {
                t.Errorf("recursion message: got %q, want %q", rec[mapKeyMessage], msgTestInconclusive)
        }
}

func TestAnalyzeNmapDNS_NonzeroExitWithPartialOutput(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"example.com": {"ns1.example.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {
                                output: []byte("|_dns-recursion: Recursion appears to be enabled"),
                                err:    fmt.Errorf("exit status 1"),
                        },
                        "dns-recursion":   {output: []byte("|_dns-recursion: Recursion appears to be enabled"), err: fmt.Errorf("exit status 1")},
                        "dns-nsid":        {output: []byte("no info")},
                        "dns-cache-snoop": {output: []byte("no snoop")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "example.com")
        rec, _ := result[mapKeyRecursion].(map[string]any)
        if rec[mapKeyOpen] != true {
                t.Error("expected partial output from nonzero exit to still be parsed for recursion detection")
        }
}

func TestAnalyzeNmapDNS_MultipleIssues(t *testing.T) {
        ztOutput := `vulnerable.com. SOA ns1.vulnerable.com. admin.vulnerable.com.
vulnerable.com. NS ns1.vulnerable.com.
vulnerable.com. A 10.0.0.1
vulnerable.com. MX 10 mail.vulnerable.com.
mail.vulnerable.com. A 10.0.0.2
Transfer zone size: 5 records`

        dns := &mockDNSForNmap{nsRecords: map[string][]string{"vulnerable.com": {"ns1.vulnerable.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte(ztOutput)},
                        "dns-recursion":     {output: []byte("|_dns-recursion: Recursion appears to be enabled")},
                        "dns-nsid":          {output: []byte("no info")},
                        "dns-cache-snoop":   {output: []byte("| dns-cache-snoop: found positive matches\n|_  google.com - positive")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)

        result := a.AnalyzeNmapDNS(context.Background(), "vulnerable.com")
        issues, _ := result[mapKeyIssues].([]string)
        if len(issues) != 3 {
                t.Errorf("expected 3 issues (zt, recursion, cache), got %d: %v", len(issues), issues)
        }
        status, _ := result[mapKeyStatus].(string)
        if status != "warning" {
                t.Errorf("expected 'warning', got %q", status)
        }
}

func TestIsValidNmapTarget_ValidHostnames(t *testing.T) {
        valid := []string{
                "ns1.example.com",
                "a.b.c.d.example.org",
                "192.168.1.1",
                "10.0.0.1",
                "2001:db8::1",
                "ns-1.example.com",
        }
        for _, target := range valid {
                if !isValidNmapTarget(target) {
                        t.Errorf("expected %q to be valid", target)
                }
        }
}

func TestIsValidNmapTarget_InjectionAttempts(t *testing.T) {
        invalid := []string{
                "; rm -rf /",
                "example.com; whoami",
                "example.com | cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "example.com\nmalicious",
                strings.Repeat("a", 254),
                "",
                " ",
                "example .com",
                "exam$ple.com",
        }
        for _, target := range invalid {
                if isValidNmapTarget(target) {
                        t.Errorf("expected %q to be invalid (injection attempt)", target)
                }
        }
}

func TestRunNmapScript_InvalidTarget(t *testing.T) {
        cmd := &mockCmdExec{lookPathResult: "/usr/bin/nmap"}
        a := &Analyzer{CmdExec: cmd}

        _, err := a.runNmapScript(context.Background(), "; rm -rf /", "dns-recursion", "", 5*60*1000000000)
        if err == nil {
                t.Fatal("expected error for invalid target")
        }
        if !strings.Contains(err.Error(), "failed hostname/IP validation") {
                t.Errorf("expected validation error, got: %v", err)
        }
}

func TestRunNmapScript_LookPathFails(t *testing.T) {
        cmd := &mockCmdExec{lookPathErr: fmt.Errorf("not found")}
        a := &Analyzer{CmdExec: cmd}

        _, err := a.runNmapScript(context.Background(), "ns1.example.com", "dns-recursion", "", 10*1000000000)
        if err == nil {
                t.Fatal("expected error when nmap not found")
        }
        if !strings.Contains(err.Error(), "nmap binary not found") {
                t.Errorf("expected 'nmap binary not found' error, got: %v", err)
        }
}

func TestRunNmapScript_ContextTimeout(t *testing.T) {
        ctx, cancel := context.WithCancel(context.Background())
        cancel()

        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-recursion": {output: nil, err: fmt.Errorf("signal: killed")},
                },
        }
        a := &Analyzer{CmdExec: cmd}

        _, err := a.runNmapScript(ctx, "ns1.example.com", "dns-recursion", "", 1)
        if err == nil {
                t.Fatal("expected error on canceled context")
        }
}

func TestRunNmapScript_ContextCanceled_PropagatesError(t *testing.T) {
        var capturedCtx context.Context
        cmd := &contextCapturingExec{
                lookPathResult: "/usr/bin/nmap",
        }

        a := &Analyzer{CmdExec: cmd}
        ctx, cancel := context.WithCancel(context.Background())
        cancel()

        _, err := a.runNmapScript(ctx, "ns1.example.com", "dns-recursion", "", 1*1000000000)
        if err == nil {
                t.Fatal("expected error for canceled context")
        }

        capturedCtx = cmd.lastCtx
        if capturedCtx != nil {
                select {
                case <-capturedCtx.Done():
                default:
                        t.Error("context passed to CombinedOutput should be canceled")
                }
        }
}

type contextCapturingExec struct {
        lookPathResult string
        lastCtx        context.Context
}

func (c *contextCapturingExec) LookPath(file string) (string, error) {
        return c.lookPathResult, nil
}

func (c *contextCapturingExec) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
        c.lastCtx = ctx
        return nil, ctx.Err()
}

func TestContainsNSIDIndicators(t *testing.T) {
        tests := []struct {
                name   string
                output string
                want   bool
        }{
                {"bind version", "  bind.version: 9.18.24", true},
                {"id server", "  id.server: ns1", true},
                {"nsid keyword", "  NSID: something", true},
                {"no indicators", "Nmap done: 1 host up", false},
                {"empty", "", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := containsNSIDIndicators(tt.output); got != tt.want {
                                t.Errorf("containsNSIDIndicators(%q) = %v, want %v", tt.output, got, tt.want)
                        }
                })
        }
}

func TestParseNSIDFields(t *testing.T) {
        output := `| dns-nsid:
|   bind.version: 9.18.24-1~deb12u1-Debian
|_  id.server: ns1-primary`
        result := map[string]any{"version": "", "id": ""}
        parseNSIDFields(output, result)
        if result["version"] != "9.18.24-1~deb12u1-Debian" {
                t.Errorf("version = %q", result["version"])
        }
        if result["id"] != "ns1-primary" {
                t.Errorf("id = %q", result["id"])
        }
}

func TestParseNSIDFields_PipePrefixedLines(t *testing.T) {
        output := `|   bind.version: BIND-9.11
|_  id.server: myserver`
        result := map[string]any{"version": "", "id": ""}
        parseNSIDFields(output, result)
        if result["version"] != "BIND-9.11" {
                t.Errorf("pipe-prefixed version = %q, want BIND-9.11", result["version"])
        }
}

func TestContainsNSIDIndicators_PipePrefixed(t *testing.T) {
        output := `| dns-nsid:
|   bind.version: 9.18.24
|_  id.server: ns1`
        if !containsNSIDIndicators(output) {
                t.Error("expected containsNSIDIndicators to detect pipe-prefixed NSID output")
        }
}

func TestParseNSIDFields_NoIndicators(t *testing.T) {
        output := `Starting Nmap 7.94
Nmap done: 1 host up`
        result := map[string]any{"version": "", "id": ""}
        parseNSIDFields(output, result)
        if result["version"] != "" {
                t.Errorf("expected empty version, got %q", result["version"])
        }
        if result["id"] != "" {
                t.Errorf("expected empty id, got %q", result["id"])
        }
}

func TestAnalyzeNmapDNS_StatusGoodWhenNoIssues(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"clean.com": {"ns1.clean.com."}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("Nmap done: no transfer")},
                        "dns-recursion":     {output: []byte("Nmap done: no recursion")},
                        "dns-nsid":          {output: []byte("Nmap done: no nsid")},
                        "dns-cache-snoop":   {output: []byte("Nmap done: no snoop")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)
        result := a.AnalyzeNmapDNS(context.Background(), "clean.com")

        status, _ := result[mapKeyStatus].(string)
        if status != "good" {
                t.Errorf("expected 'good' for clean domain, got %q", status)
        }
        issues, _ := result[mapKeyIssues].([]string)
        if len(issues) != 0 {
                t.Errorf("expected 0 issues for clean domain, got %v", issues)
        }
}

func TestRunNmapScript_HungCommand_ContextCancelsIt(t *testing.T) {
        cmd := &hangingCmdExec{
                lookPathResult: "/usr/bin/nmap",
                hangDuration:   10 * time.Second,
        }
        a := &Analyzer{CmdExec: cmd}

        ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
        defer cancel()

        start := time.Now()
        _, err := a.runNmapScript(ctx, "ns1.example.com", "dns-recursion", "", 100*time.Millisecond)
        elapsed := time.Since(start)

        if err == nil {
                t.Fatal("expected error for hung command with context timeout")
        }
        if elapsed > 2*time.Second {
                t.Errorf("hung command took %v to return — context timeout not respected", elapsed)
        }
        if !cmd.contextWasCanceled {
                t.Error("context passed to CombinedOutput was never canceled — kill semantics broken")
        }
}

type hangingCmdExec struct {
        lookPathResult     string
        hangDuration       time.Duration
        contextWasCanceled bool
}

func (h *hangingCmdExec) LookPath(file string) (string, error) {
        return h.lookPathResult, nil
}

func (h *hangingCmdExec) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
        select {
        case <-time.After(h.hangDuration):
                return []byte("should not reach here"), nil
        case <-ctx.Done():
                h.contextWasCanceled = true
                return nil, ctx.Err()
        }
}

func TestAnalyzeNmapDNS_StatusWarningWhenIssuesPresent(t *testing.T) {
        dns := &mockDNSForNmap{nsRecords: map[string][]string{"dirty.com": {"ns1.dirty.com"}}}
        cmd := &mockCmdExec{
                lookPathResult: "/usr/bin/nmap",
                outputs: map[string]mockCmdResult{
                        "dns-zone-transfer": {output: []byte("dirty.com. SOA ns1.dirty.com.\nTransfer zone size: 3 records")},
                        "dns-recursion":     {output: []byte("|_dns-recursion: Recursion appears to be enabled")},
                        "dns-nsid":          {output: []byte("Nmap done")},
                        "dns-cache-snoop":   {output: []byte("Nmap done")},
                },
        }
        a := newTestAnalyzerWithNmap(dns, cmd)
        result := a.AnalyzeNmapDNS(context.Background(), "dirty.com")

        status, _ := result[mapKeyStatus].(string)
        if status != "warning" {
                t.Errorf("expected 'warning' when issues exist, got %q", status)
        }
        issues, _ := result[mapKeyIssues].([]string)
        if len(issues) < 1 {
                t.Errorf("expected at least 1 issue, got %d: %v", len(issues), issues)
        }
        foundRecursion := false
        for _, issue := range issues {
                if strings.Contains(issue, "recursion") || strings.Contains(issue, "Recursion") {
                        foundRecursion = true
                }
        }
        if !foundRecursion {
                t.Errorf("expected recursion issue in list: %v", issues)
        }
}
