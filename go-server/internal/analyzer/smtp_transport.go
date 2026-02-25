// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

type smtpServerResult struct {
        Host              string  `json:"host"`
        Reachable         bool    `json:"reachable"`
        StartTLS          bool    `json:"starttls"`
        TLSVersion        *string `json:"tls_version"`
        Cipher            *string `json:"cipher"`
        CipherBits        *int    `json:"cipher_bits"`
        CertValid         bool    `json:"cert_valid"`
        CertExpiry        *string `json:"cert_expiry"`
        CertDaysRemaining *int    `json:"cert_days_remaining"`
        CertIssuer        *string `json:"cert_issuer"`
        CertSubject       *string `json:"cert_subject"`
        Error             *string `json:"error"`
}

type smtpSummary struct {
        TotalServers    int `json:"total_servers"`
        Reachable       int `json:"reachable"`
        StartTLSSupport int `json:"starttls_supported"`
        TLS13           int `json:"tls_1_3"`
        TLS12           int `json:"tls_1_2"`
        ValidCerts      int `json:"valid_certs"`
        ExpiringSoon    int `json:"expiring_soon"`
}

type AnalysisInputs struct {
        MTASTSResult map[string]any
        TLSRPTResult map[string]any
        DANEResult   map[string]any
}

func (a *Analyzer) AnalyzeSMTPTransport(ctx context.Context, domain string, mxRecords []string, inputs ...AnalysisInputs) map[string]any {
        var ai AnalysisInputs
        if len(inputs) > 0 {
                ai = inputs[0]
        }

        mxHosts := extractMXHosts(mxRecords)

        result := buildMailTransportResult(a, ctx, domain, mxHosts, ai)

        return result
}

func buildMailTransportResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        result := map[string]any{
                "version": 2,
        }

        policy := buildPolicyAssessment(a, ctx, domain, mxHosts, ai)
        result["policy"] = policy

        telemetrySection := buildTelemetrySection(ai)
        result["telemetry"] = telemetrySection

        probe := buildProbeResult(a, ctx, domain, mxHosts)
        result["probe"] = probe

        result["status"] = derivePrimaryStatus(policy, probe)
        result["message"] = derivePrimaryMessage(policy, probe, mxHosts)

        result["dns_inferred"] = true
        result["inference_note"] = buildInferenceNote(probe)
        result["inference_signals"] = buildInferenceSignals(policy, telemetrySection)

        backfillLegacyFields(result, policy, probe)

        return result
}

func buildPolicyAssessment(a *Analyzer, ctx context.Context, domain string, mxHosts []string, ai AnalysisInputs) map[string]any {
        policy := map[string]any{
                "mta_sts":  map[string]any{"present": false, "mode": "none"},
                "dane":     map[string]any{"present": false},
                "tlsrpt":   map[string]any{"present": false},
                "provider": map[string]any{"identified": false},
                "verdict":  "none",
                "signals":  []string{},
        }

        var signals []string

        signals = assessMTASTS(a, ctx, domain, ai, policy, signals)
        signals = assessDANE(a, ctx, mxHosts, ai, policy, signals)
        signals = assessTLSRPT(a, ctx, domain, ai, policy, signals)
        signals = assessProvider(mxHosts, policy, signals)

        policy["signals"] = signals
        policy["verdict"] = computePolicyVerdict(policy, signals)

        return policy
}

func assessMTASTS(a *Analyzer, ctx context.Context, domain string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        mtaSts := ai.MTASTSResult
        if mtaSts == nil {
                mtaSts = a.AnalyzeMTASTS(ctx, domain)
        }
        if mode, ok := mtaSts["mode"].(string); ok && mode != "" && mode != "none" {
                policy["mta_sts"] = map[string]any{
                        "present": true,
                        "mode":    mode,
                        "status":  mapGetStrSafe(mtaSts, "status"),
                }
                if mode == "enforce" {
                        signals = append(signals, "MTA-STS policy in enforce mode requires encrypted transport (RFC 8461)")
                } else if mode == "testing" {
                        signals = append(signals, "MTA-STS policy in testing mode — monitoring transport security (RFC 8461)")
                }
        }
        return signals
}

func assessDANE(a *Analyzer, ctx context.Context, mxHosts []string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        hasTLSA := false
        daneResult := ai.DANEResult
        if daneResult != nil {
                if hasDane, ok := daneResult["has_dane"].(bool); ok && hasDane {
                        hasTLSA = true
                }
        }
        if !hasTLSA {
                for _, host := range mxHosts {
                        tlsaName := fmt.Sprintf("_25._tcp.%s", host)
                        tlsaRecords := a.DNS.QueryDNS(ctx, "TLSA", tlsaName)
                        if len(tlsaRecords) > 0 {
                                hasTLSA = true
                                break
                        }
                }
        }
        if hasTLSA {
                policy["dane"] = map[string]any{"present": true}
                signals = append(signals, "DANE/TLSA records published — mail servers pin TLS certificates via DNSSEC (RFC 7672)")
        }
        return signals
}

func assessTLSRPT(a *Analyzer, ctx context.Context, domain string, ai AnalysisInputs, policy map[string]any, signals []string) []string {
        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                tlsrpt = a.AnalyzeTLSRPT(ctx, domain)
        }
        if st, ok := tlsrpt["status"].(string); ok && st == "success" {
                policy["tlsrpt"] = map[string]any{
                        "present": true,
                        "status":  st,
                }
                signals = append(signals, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
        }
        return signals
}

func assessProvider(mxHosts []string, policy map[string]any, signals []string) []string {
        providerSignal := inferFromProvider(mxHosts)
        if providerSignal != "" {
                providerName := identifyProviderName(mxHosts)
                policy["provider"] = map[string]any{
                        "identified": true,
                        "name":       providerName,
                }
                signals = append(signals, providerSignal)
        }
        return signals
}

func computePolicyVerdict(policy map[string]any, signals []string) string {
        mtaStsMeta, _ := policy["mta_sts"].(map[string]any)
        mtaStsPresent, _ := mtaStsMeta["present"].(bool)
        mtaStsMode, _ := mtaStsMeta["mode"].(string)
        daneMeta, _ := policy["dane"].(map[string]any)
        danePresent, _ := daneMeta["present"].(bool)

        if mtaStsPresent && mtaStsMode == "enforce" {
                return "enforced"
        }
        if danePresent {
                return "enforced"
        }
        if mtaStsPresent && mtaStsMode == "testing" {
                return "monitored"
        }
        if len(signals) > 0 {
                return "opportunistic"
        }
        return "none"
}

func buildTelemetrySection(ai AnalysisInputs) map[string]any {
        section := map[string]any{
                "tlsrpt_configured": false,
                "reporting_uris":    []string{},
                "observability":     false,
        }

        tlsrpt := ai.TLSRPTResult
        if tlsrpt == nil {
                return section
        }

        if st, ok := tlsrpt["status"].(string); ok && st == "success" {
                section["tlsrpt_configured"] = true
                section["observability"] = true

                if record, ok := tlsrpt["record"].(string); ok && record != "" {
                        uris := extractTLSRPTURIs(record)
                        if len(uris) > 0 {
                                section["reporting_uris"] = uris
                        }
                }
        }

        return section
}

func extractTLSRPTURIs(record string) []string {
        var uris []string
        parts := strings.Split(record, ";")
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "rua=") {
                        rua := strings.TrimPrefix(part, "rua=")
                        for _, uri := range strings.Split(rua, ",") {
                                uri = strings.TrimSpace(uri)
                                if uri != "" {
                                        uris = append(uris, uri)
                                }
                        }
                }
        }
        return uris
}

func buildProbeResult(a *Analyzer, ctx context.Context, domain string, mxHosts []string) map[string]any {
        probe := map[string]any{
                "status":       "skipped",
                "reason":       "",
                "observations": []map[string]any{},
        }

        if len(mxHosts) == 0 {
                probe["reason"] = "No MX records found for this domain"
                probe["probe_method"] = "none"
                return probe
        }

        if a.SMTPProbeMode == "skip" || a.SMTPProbeMode == "" {
                probe["reason"] = "SMTP probe skipped — outbound TCP port 25 is blocked by cloud hosting provider. This is standard for all major cloud platforms (AWS, GCP, Azure, Replit) as an anti-spam measure. Transport security is assessed via DNS policy records above, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                probe["probe_method"] = "skip"
                slog.Info("SMTP probe skipped (mode=skip)", "domain", domain)
                return probe
        }

        if a.SMTPProbeMode == "remote" && len(a.Probes) > 0 {
                probe["probe_method"] = "remote"
                probe["probe_count"] = len(a.Probes)
                if len(a.Probes) == 1 {
                        return runRemoteProbe(ctx, a.Probes[0].URL, a.Probes[0].Key, mxHosts, probe)
                }
                return runMultiProbe(ctx, a.Probes, mxHosts, probe)
        }

        if a.SMTPProbeMode == "remote" && a.ProbeAPIURL != "" && len(a.Probes) == 0 {
                probe["probe_method"] = "remote"
                return runRemoteProbe(ctx, a.ProbeAPIURL, a.ProbeAPIKey, mxHosts, probe)
        }

        if a.SMTPProbeMode == "remote" && a.ProbeAPIURL == "" && len(a.Probes) == 0 {
                probe["reason"] = "Remote probe configured but PROBE_API_URL is not set — unable to reach external probe infrastructure."
                probe["probe_method"] = "remote_misconfigured"
                slog.Error("SMTP probe: mode=remote but PROBE_API_URL is empty", "domain", domain)
                return probe
        }

        if a.SMTPProbeMode == "force" {
                probe["probe_method"] = "local"
                return runLiveProbe(ctx, mxHosts, probe)
        }

        probe["probe_method"] = "unknown"
        probe["reason"] = fmt.Sprintf("Unrecognized SMTP probe mode: %s", a.SMTPProbeMode)
        slog.Warn("SMTP probe: unrecognized mode", "mode", a.SMTPProbeMode, "domain", domain)
        return probe
}

func remoteProbeFailover(ctx context.Context, mxHosts []string, probe map[string]any, remoteError string) map[string]any {
        slog.Warn("Remote probe failed, attempting local fallback", "remote_error", remoteError)
        probe["remote_attempted"] = true
        probe["remote_error"] = remoteError
        result := runLiveProbe(ctx, mxHosts, probe)
        if result["status"] == "skipped" {
                result["reason"] = fmt.Sprintf("Remote probe failed (%s) and local port 25 is blocked. Transport security is assessed via DNS policy records per NIST SP 800-177 Rev. 1.", remoteError)
        } else {
                result["probe_method"] = "local_fallback"
        }
        return result
}

func runRemoteProbe(ctx context.Context, apiURL string, apiKey string, mxHosts []string, probe map[string]any) map[string]any {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 5 {
                hostsToCheck = hostsToCheck[:5]
        }

        reqBody, err := json.Marshal(map[string]any{
                "hosts": hostsToCheck,
                "ports": []int{25, 465, 587},
        })
        if err != nil {
                slog.Error("Remote probe: failed to marshal request", "error", err)
                return remoteProbeFailover(ctx, mxHosts, probe, "request encoding error")
        }

        probeCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
        defer cancel()

        req, err := http.NewRequestWithContext(probeCtx, "POST", apiURL+"/probe/smtp", bytes.NewReader(reqBody))
        if err != nil {
                slog.Error("Remote probe: failed to create request", "error", err)
                return remoteProbeFailover(ctx, mxHosts, probe, "request creation error")
        }
        req.Header.Set("Content-Type", "application/json")
        if apiKey != "" {
                req.Header.Set("X-Probe-Key", apiKey)
        }

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                slog.Warn("Remote probe: request failed", "error", err)
                return remoteProbeFailover(ctx, mxHosts, probe, "connection failed — probe may be offline")
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusUnauthorized {
                slog.Error("Remote probe: authentication failed (401) — check PROBE_API_KEY")
                return remoteProbeFailover(ctx, mxHosts, probe, "authentication failed (401)")
        }
        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("Remote probe: rate limited (429)")
                return remoteProbeFailover(ctx, mxHosts, probe, "rate limited (429)")
        }
        if resp.StatusCode != http.StatusOK {
                slog.Warn("Remote probe: non-200 response", "status", resp.StatusCode)
                return remoteProbeFailover(ctx, mxHosts, probe, fmt.Sprintf("HTTP %d", resp.StatusCode))
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
        if err != nil {
                slog.Warn("Remote probe: failed to read response", "error", err)
                return remoteProbeFailover(ctx, mxHosts, probe, "response read error")
        }

        var apiResp struct {
                ProbeHost      string           `json:"probe_host"`
                Version        string           `json:"version"`
                ElapsedSeconds float64          `json:"elapsed_seconds"`
                Servers        []map[string]any `json:"servers"`
                AllPorts       []map[string]any `json:"all_ports"`
        }
        if err := json.Unmarshal(body, &apiResp); err != nil {
                slog.Warn("Remote probe: failed to parse response", "error", err)
                return remoteProbeFailover(ctx, mxHosts, probe, "response parse error")
        }

        if len(apiResp.Servers) == 0 {
                slog.Warn("Remote probe: no servers in response")
                return remoteProbeFailover(ctx, mxHosts, probe, "empty response from probe")
        }

        summary := &smtpSummary{TotalServers: len(apiResp.Servers)}
        for _, srv := range apiResp.Servers {
                updateSummary(summary, srv)
        }

        reachable := summary.Reachable
        if reachable == 0 {
                probe["status"] = "skipped"
                probe["reason"] = "SMTP port 25 not reachable from probe host — all MX servers rejected or timed out on port 25. Transport security assessed via DNS policy records."
                probe["probe_host"] = apiResp.ProbeHost
                probe["probe_elapsed"] = apiResp.ElapsedSeconds
                if len(apiResp.AllPorts) > 0 {
                        probe["multi_port"] = apiResp.AllPorts
                }
                return probe
        }

        probe["status"] = "observed"
        probe["reason"] = ""
        probe["observations"] = apiResp.Servers
        probe["summary"] = summaryToMap(summary)
        probe["probe_host"] = apiResp.ProbeHost
        probe["probe_elapsed"] = apiResp.ElapsedSeconds

        if len(apiResp.AllPorts) > 0 {
                probe["multi_port"] = apiResp.AllPorts
        }

        if summary.StartTLSSupport == reachable && summary.ValidCerts == summary.StartTLSSupport {
                probe["probe_verdict"] = "all_tls"
        } else if summary.StartTLSSupport > 0 {
                probe["probe_verdict"] = "partial_tls"
        } else {
                probe["probe_verdict"] = "no_tls"
        }

        slog.Info("Remote SMTP probe completed",
                "probe_host", apiResp.ProbeHost,
                "version", apiResp.Version,
                "servers", len(apiResp.Servers),
                "all_ports", len(apiResp.AllPorts),
                "reachable", reachable,
                "starttls", summary.StartTLSSupport,
                "elapsed", apiResp.ElapsedSeconds,
        )

        return probe
}

type smtpProbeResult struct {
        id    string
        label string
        data  map[string]any
}

func runMultiProbe(ctx context.Context, probes []ProbeEndpoint, mxHosts []string, probe map[string]any) map[string]any {
        results := make(chan smtpProbeResult, len(probes))
        for _, p := range probes {
                go func(ep ProbeEndpoint) {
                        single := make(map[string]any)
                        single = runRemoteProbe(ctx, ep.URL, ep.Key, mxHosts, single)
                        results <- smtpProbeResult{id: ep.ID, label: ep.Label, data: single}
                }(p)
        }

        multiResults, primaryResult := collectMultiProbeResults(probes, results)

        if primaryResult == nil {
                primaryResult = resolveMultiProbeFallback(ctx, probes, multiResults, mxHosts)
        }

        applyPrimaryResult(probe, primaryResult)

        probe["multi_probe"] = multiResults
        probe["probe_method"] = "multi_remote"
        probe["probe_count"] = len(probes)

        consensus := computeProbeConsensus(multiResults)
        probe["probe_consensus"] = consensus

        slog.Info("Multi-probe SMTP completed",
                "probe_count", len(probes),
                "results", len(multiResults),
                "consensus", consensus["agreement"],
        )

        return probe
}

func buildMultiProbeEntry(r smtpProbeResult) map[string]any {
        entry := map[string]any{
                "probe_id":    r.id,
                "probe_label": r.label,
                "status":      r.data["status"],
                "probe_host":  r.data["probe_host"],
                "elapsed":     r.data["probe_elapsed"],
        }
        if obs, ok := r.data["observations"]; ok {
                entry["observations"] = obs
        }
        if s, ok := r.data["summary"]; ok {
                entry["summary"] = s
        }
        if v, ok := r.data["probe_verdict"]; ok {
                entry["probe_verdict"] = v
        }
        return entry
}

func collectMultiProbeResults(probes []ProbeEndpoint, results <-chan smtpProbeResult) ([]map[string]any, map[string]any) {
        var multiResults []map[string]any
        var primaryResult map[string]any
        for range probes {
                r := <-results
                entry := buildMultiProbeEntry(r)
                multiResults = append(multiResults, entry)
                if primaryResult == nil && r.data["status"] == "observed" {
                        primaryResult = r.data
                }
        }
        return multiResults, primaryResult
}

func resolveMultiProbeFallback(ctx context.Context, probes []ProbeEndpoint, multiResults []map[string]any, mxHosts []string) map[string]any {
        if len(multiResults) == 0 {
                return nil
        }
        for _, mr := range multiResults {
                if mr["status"] == "observed" {
                        return nil
                }
        }
        if len(probes) > 0 {
                first := make(map[string]any)
                first = runRemoteProbe(ctx, probes[0].URL, probes[0].Key, mxHosts, first)
                return first
        }
        return nil
}

func applyPrimaryResult(probe, primaryResult map[string]any) {
        if primaryResult == nil {
                return
        }
        for k, v := range primaryResult {
                probe[k] = v
        }
}

func computeProbeConsensus(results []map[string]any) map[string]any {
        consensus := map[string]any{
                "total_probes": len(results),
                "agreement":    "unknown",
        }

        if len(results) == 0 {
                return consensus
        }

        observed := 0
        allTLS := 0
        partialTLS := 0
        noTLS := 0

        for _, r := range results {
                if r["status"] == "observed" {
                        observed++
                        switch r["probe_verdict"] {
                        case "all_tls":
                                allTLS++
                        case "partial_tls":
                                partialTLS++
                        case "no_tls":
                                noTLS++
                        }
                }
        }

        consensus["observed"] = observed
        consensus["all_tls"] = allTLS
        consensus["partial_tls"] = partialTLS
        consensus["no_tls"] = noTLS

        if observed == 0 {
                consensus["agreement"] = "no_data"
        } else if allTLS == observed {
                consensus["agreement"] = "unanimous_tls"
        } else if noTLS == observed {
                consensus["agreement"] = "unanimous_no_tls"
        } else if allTLS > 0 && partialTLS == 0 && noTLS == 0 {
                consensus["agreement"] = "unanimous_tls"
        } else {
                consensus["agreement"] = "split"
        }

        return consensus
}

func runLiveProbe(ctx context.Context, mxHosts []string, probe map[string]any) map[string]any {
        hostsToCheck := mxHosts
        if len(hostsToCheck) > 3 {
                hostsToCheck = hostsToCheck[:3]
        }

        summary := &smtpSummary{TotalServers: len(hostsToCheck)}
        servers := probeSMTPServers(ctx, hostsToCheck, summary)

        if summary.Reachable == 0 {
                probe["status"] = "skipped"
                probe["reason"] = "SMTP port 25 not reachable from this host — outbound port 25 is likely blocked by the hosting provider. Transport security is assessed via DNS policy records, which is the standards-aligned primary method per NIST SP 800-177 Rev. 1."
                return probe
        }

        probe["status"] = "observed"
        probe["reason"] = ""
        probe["observations"] = servers
        probe["summary"] = summaryToMap(summary)

        if summary.StartTLSSupport == summary.Reachable && summary.ValidCerts == summary.StartTLSSupport {
                probe["probe_verdict"] = "all_tls"
        } else if summary.StartTLSSupport > 0 {
                probe["probe_verdict"] = "partial_tls"
        } else {
                probe["probe_verdict"] = "no_tls"
        }

        return probe
}

func derivePrimaryStatus(policy, probe map[string]any) string {
        verdict, _ := policy["verdict"].(string)
        probeStatus, _ := probe["status"].(string)

        if probeStatus == "observed" {
                probeVerdict, _ := probe["probe_verdict"].(string)
                if probeVerdict == "all_tls" && (verdict == "enforced" || verdict == "monitored") {
                        return "success"
                }
                if probeVerdict == "all_tls" {
                        return "success"
                }
                if probeVerdict == "partial_tls" {
                        return "warning"
                }
                return "error"
        }

        switch verdict {
        case "enforced":
                return "success"
        case "monitored":
                return "info"
        case "opportunistic":
                return "inferred"
        default:
                return "info"
        }
}

func derivePrimaryMessage(policy, probe map[string]any, mxHosts []string) string {
        verdict, _ := policy["verdict"].(string)
        probeStatus, _ := probe["status"].(string)
        signals, _ := policy["signals"].([]string)

        if len(mxHosts) == 0 {
                return "No MX records found"
        }

        if probeStatus == "observed" {
                probeSummary, _ := probe["summary"].(map[string]any)
                if probeSummary != nil {
                        reachable := int(toFloat64Val(probeSummary["reachable"]))
                        starttls := int(toFloat64Val(probeSummary["starttls_supported"]))
                        if starttls == reachable && reachable > 0 {
                                return fmt.Sprintf("All %d server(s) verified: encrypted transport confirmed via direct SMTP probe and DNS policy", reachable)
                        }
                        return fmt.Sprintf("%d/%d servers support STARTTLS (direct probe)", starttls, reachable)
                }
        }

        switch verdict {
        case "enforced":
                return fmt.Sprintf("Transport encryption enforced via DNS policy (%d signal(s))", len(signals))
        case "monitored":
                return fmt.Sprintf("Transport security in monitoring mode (%d signal(s))", len(signals))
        case "opportunistic":
                return fmt.Sprintf("Transport security inferred from %d signal(s) — no enforcement policy active", len(signals))
        default:
                return "No transport encryption policy detected — mail delivery relies on opportunistic TLS"
        }
}

func buildInferenceNote(probe map[string]any) string {
        probeStatus, _ := probe["status"].(string)
        if probeStatus == "observed" {
                return ""
        }
        return "Transport security assessed via DNS policy records (MTA-STS, DANE, TLS-RPT) — the standards-aligned primary method per NIST SP 800-177 Rev. 1 and RFC 8461. Direct SMTP probing is a supplementary verification step."
}

func buildInferenceSignals(policy, telemetrySection map[string]any) []string {
        signals, _ := policy["signals"].([]string)
        result := make([]string, len(signals))
        copy(result, signals)

        if configured, ok := telemetrySection["tlsrpt_configured"].(bool); ok && configured {
                hasTLSRPTSignal := false
                for _, s := range result {
                        if strings.Contains(s, "TLS-RPT") {
                                hasTLSRPTSignal = true
                                break
                        }
                }
                if !hasTLSRPTSignal {
                        result = append(result, "TLS-RPT configured — domain monitors TLS delivery failures (RFC 8460)")
                }
        }

        return result
}

func backfillLegacyFields(result map[string]any, policy, probe map[string]any) {
        probeStatus, _ := probe["status"].(string)

        if probeStatus == "observed" {
                observations, _ := probe["observations"].([]map[string]any)
                result["servers"] = observations
                if probeSummary, ok := probe["summary"].(map[string]any); ok {
                        result["summary"] = probeSummary
                } else {
                        result["summary"] = emptyLegacySummary()
                }
        } else {
                result["servers"] = []map[string]any{}
                result["summary"] = emptyLegacySummary()
        }

        result["issues"] = []string{}
}

func emptyLegacySummary() map[string]any {
        return map[string]any{
                "total_servers":      0,
                "reachable":          0,
                "starttls_supported": 0,
                "tls_1_3":            0,
                "tls_1_2":            0,
                "valid_certs":        0,
                "expiring_soon":      0,
        }
}

func identifyProviderName(mxHosts []string) string {
        providerNames := map[string]string{
                "google.com":         "Google Workspace",
                "googlemail.com":     "Google Workspace",
                "outlook.com":        "Microsoft 365",
                "protection.outlook": "Microsoft 365",
                "pphosted.com":       "Proofpoint",
                "mimecast.com":       "Mimecast",
                "messagelabs.com":    "Broadcom/Symantec",
                "fireeyecloud.com":   "Trellix",
                "iphmx.com":          "Cisco Email Security",
                "protonmail.ch":      "Proton Mail",
                "registrar-servers":  "Namecheap",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, name := range providerNames {
                        if strings.Contains(hostLower, pattern) {
                                return name
                        }
                }
        }
        return ""
}

func mapGetStrSafe(m map[string]any, key string) string {
        if m == nil {
                return ""
        }
        v, ok := m[key].(string)
        if !ok {
                return ""
        }
        return v
}

func toFloat64Val(v any) float64 {
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        case int64:
                return float64(n)
        }
        return 0
}

func probeSMTPServers(ctx context.Context, hosts []string, summary *smtpSummary) []map[string]any {
        var (
                mu      sync.Mutex
                wg      sync.WaitGroup
                servers []map[string]any
        )

        for _, host := range hosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        sr := probeSingleSMTPServer(ctx, h)
                        mu.Lock()
                        servers = append(servers, sr)
                        updateSummary(summary, sr)
                        mu.Unlock()
                }(host)
        }
        wg.Wait()
        return servers
}

func probeSingleSMTPServer(ctx context.Context, host string) map[string]any {
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

        probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
        defer cancel()

        conn, err := dialSMTP(probeCtx, host)
        if err != nil {
                errStr := classifySMTPError(err)
                result["error"] = errStr
                return result
        }
        defer conn.Close()

        result["reachable"] = true

        banner, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(banner, "220") {
                errStr := "Unexpected SMTP banner"
                result["error"] = errStr
                return result
        }

        _, err = fmt.Fprintf(conn, "EHLO dnstool.local\r\n")
        if err != nil {
                errStr := "EHLO failed"
                result["error"] = errStr
                return result
        }

        ehloResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil {
                errStr := "EHLO response timeout"
                result["error"] = errStr
                return result
        }

        if !strings.Contains(strings.ToUpper(ehloResp), "STARTTLS") {
                errStr := "STARTTLS not supported"
                result["error"] = errStr
                return result
        }

        result["starttls"] = true

        _, err = fmt.Fprintf(conn, "STARTTLS\r\n")
        if err != nil {
                errStr := "STARTTLS command failed"
                result["error"] = errStr
                return result
        }

        starttlsResp, err := readSMTPResponse(conn, 2*time.Second)
        if err != nil || !strings.HasPrefix(starttlsResp, "220") {
                errStr := fmt.Sprintf("STARTTLS rejected: %s", truncate(starttlsResp, 50))
                result["error"] = errStr
                return result
        }

        negotiateTLS(conn, host, result)

        return result
}

func negotiateTLS(conn net.Conn, host string, result map[string]any) {
        tlsCfg := &tls.Config{ //nolint:gosec // Intentional: diagnostic tool must connect to servers with self-signed/expired/mismatched certs to inspect and report on their TLS configuration. Certificate validation is performed separately in verifyCert().
                ServerName:         host,
                InsecureSkipVerify: true, //NOSONAR — S4830/S5527: deliberate diagnostic probe; verifyCert() validates independently
        }
        tlsConn := tls.Client(conn, tlsCfg)
        defer tlsConn.Close()

        if err := tlsConn.Handshake(); err != nil {
                errStr := fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 80))
                result["error"] = errStr
                return
        }

        state := tlsConn.ConnectionState()
        tlsVer := tlsVersionString(state.Version)
        result["tls_version"] = tlsVer

        cipherName := tls.CipherSuiteName(state.CipherSuite)
        result["cipher"] = cipherName

        bits := cipherBits(state.CipherSuite)
        result["cipher_bits"] = bits

        verifyCert(host, result)
}

func verifyCert(host string, result map[string]any) {
        verifyCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
        defer cancel()

        dialer := &net.Dialer{Timeout: 2 * time.Second}
        verifyConn, err := dialSMTPWithDialer(verifyCtx, dialer, host)
        if err != nil {
                return
        }
        defer verifyConn.Close()

        banner, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(banner, "220") {
                return
        }
        fmt.Fprintf(verifyConn, "EHLO dnstool.local\r\n")
        readSMTPResponse(verifyConn, 1*time.Second)
        fmt.Fprintf(verifyConn, "STARTTLS\r\n")
        resp, _ := readSMTPResponse(verifyConn, 1*time.Second)
        if !strings.HasPrefix(resp, "220") {
                return
        }

        verifyCfg := &tls.Config{ServerName: host}
        verifyTLS := tls.Client(verifyConn, verifyCfg)
        defer verifyTLS.Close()

        if err := verifyTLS.Handshake(); err != nil {
                result["cert_valid"] = false
                errStr := fmt.Sprintf("Certificate invalid: %s", truncate(err.Error(), 100))
                result["error"] = errStr
                return
        }

        result["cert_valid"] = true
        certs := verifyTLS.ConnectionState().PeerCertificates
        if len(certs) > 0 {
                leaf := certs[0]
                expiry := leaf.NotAfter.Format("2006-01-02")
                result["cert_expiry"] = expiry
                daysRemaining := int(time.Until(leaf.NotAfter).Hours() / 24)
                result["cert_days_remaining"] = daysRemaining
                result["cert_subject"] = leaf.Subject.CommonName
                if leaf.Issuer.Organization != nil && len(leaf.Issuer.Organization) > 0 {
                        result["cert_issuer"] = leaf.Issuer.Organization[0]
                } else {
                        result["cert_issuer"] = leaf.Issuer.CommonName
                }
        }
}

func dialSMTP(ctx context.Context, host string) (net.Conn, error) {
        dialer := &net.Dialer{Timeout: 2 * time.Second}
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func dialSMTPWithDialer(ctx context.Context, dialer *net.Dialer, host string) (net.Conn, error) {
        return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "25"))
}

func readSMTPResponse(conn net.Conn, timeout time.Duration) (string, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := make([]byte, 4096)
        var response strings.Builder
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        response.Write(buf[:n])
                        if smtpResponseComplete(response.String()) {
                                break
                        }
                }
                if err != nil {
                        return handlePartialResponse(response, err)
                }
        }
        return response.String(), nil
}

func smtpResponseComplete(data string) bool {
        lines := strings.Split(data, "\n")
        lastLine := strings.TrimSpace(lines[len(lines)-1])
        if lastLine == "" && len(lines) > 1 {
                lastLine = strings.TrimSpace(lines[len(lines)-2])
        }
        return len(lastLine) >= 4 && lastLine[3] == ' '
}

func handlePartialResponse(response strings.Builder, err error) (string, error) {
        if response.Len() > 0 {
                return response.String(), nil
        }
        return "", err
}

func classifySMTPError(err error) string {
        errStr := err.Error()
        if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
                return "Connection timeout"
        }
        if strings.Contains(errStr, "refused") {
                return "Connection refused"
        }
        if strings.Contains(errStr, "unreachable") {
                return "Network unreachable"
        }
        if strings.Contains(errStr, "no such host") {
                return "DNS resolution failed"
        }
        return truncate(errStr, 80)
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

func updateSummary(s *smtpSummary, sr map[string]any) {
        if sr["reachable"] == true {
                s.Reachable++
        }
        if sr["starttls"] == true {
                s.StartTLSSupport++
        }
        if v, ok := sr["tls_version"].(string); ok {
                if v == "TLSv1.3" {
                        s.TLS13++
                } else if v == "TLSv1.2" {
                        s.TLS12++
                }
        }
        if sr["cert_valid"] == true {
                s.ValidCerts++
        }
        if dr, ok := sr["cert_days_remaining"].(int); ok && dr < 30 {
                s.ExpiringSoon++
        }
}

func summaryToMap(s *smtpSummary) map[string]any {
        return map[string]any{
                "total_servers":      s.TotalServers,
                "reachable":          s.Reachable,
                "starttls_supported": s.StartTLSSupport,
                "tls_1_3":            s.TLS13,
                "tls_1_2":            s.TLS12,
                "valid_certs":        s.ValidCerts,
                "expiring_soon":      s.ExpiringSoon,
        }
}

func inferFromProvider(mxHosts []string) string {
        providerMap := map[string]string{
                "google.com":         "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "googlemail.com":     "Google Workspace enforces TLS 1.2+ with valid certificates on all inbound/outbound mail",
                "outlook.com":        "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "protection.outlook": "Microsoft 365 enforces TLS 1.2+ with DANE (GA Oct 2024) and valid certificates",
                "pphosted.com":       "Proofpoint enforces TLS on managed mail transport",
                "mimecast.com":       "Mimecast enforces TLS on managed mail transport",
                "messagelabs.com":    "Broadcom/Symantec Email Security enforces TLS",
                "fireeyecloud.com":   "Trellix Email Security enforces TLS",
                "iphmx.com":          "Cisco Email Security enforces TLS",
                "protonmail.ch":      "Proton Mail enforces TLS 1.2+ with DANE support",
                "registrar-servers":  "Namecheap mail service supports TLS",
        }

        for _, host := range mxHosts {
                hostLower := strings.ToLower(host)
                for pattern, description := range providerMap {
                        if strings.Contains(hostLower, pattern) {
                                return description
                        }
                }
        }
        return ""
}

func getIssuesList(result map[string]any) []string {
        if issues, ok := result["issues"].([]string); ok {
                return issues
        }
        return []string{}
}
