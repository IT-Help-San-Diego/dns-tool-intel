// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "log/slog"
        "strconv"
        "strings"
        "sync"

        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/providers"
)

const (
        mapKeyAlternative    = "alternative"
        mapKeyDaneDeployable = "dane_deployable"
        mapKeyDaneInbound    = "dane_inbound"
        mapKeyDaneOutbound   = "dane_outbound"
        mapKeyMxHost         = "mx_host"
        mapKeyProviderName   = "provider_name"
        statusInfo           = "info"
        statusUnknown        = "unknown"

        // DANE tri-state. has_dane stays a derived boolean, but dane_state lets
        // every downstream (UI, drift) tell an authoritative "no TLSA" apart from
        // a transient lookup failure, so a timed-out probe never reads as removal.
        daneStatePresent       = "present"
        daneStateAbsentConf    = "absent_confirmed"
        daneStateIndeterminate = "indeterminate"
)

var daneUsageNames = map[int]string{
        0: "PKIX-TA (CA constraint)",
        1: "PKIX-EE (Certificate constraint)",
        2: "DANE-TA (Trust anchor)",
        3: "DANE-EE (Domain-issued certificate)",
}

var daneSelectorNames = map[int]string{
        0: "Full certificate",
        1: "Public key only (SubjectPublicKeyInfo)",
}

var daneMatchingNames = map[int]string{
        0: "Exact match",
        1: "SHA-256",
        2: "SHA-512",
}

func (a *Analyzer) detectMXDANECapability(mxHosts []string) map[string]any {
        mxStr := strings.ToLower(strings.Join(mxHosts, " "))
        for _, info := range providers.DANEMXCapability {
                for _, pattern := range info.Patterns {
                        if strings.Contains(mxStr, pattern) {
                                return map[string]any{
                                        mapKeyProviderName: info.Name,
                                        mapKeyDaneInbound:  info.DANEInbound,
                                        mapKeyDaneOutbound: info.DANEOutbound,
                                        "reason":           info.Reason,
                                        mapKeyAlternative:  info.Alternative,
                                }
                        }
                }
        }
        return nil
}

func parseTLSAEntry(entry string, mxHost, tlsaName string) (map[string]any, bool) {
        parts := strings.Fields(entry)
        if len(parts) < 4 {
                return nil, false
        }
        usage, _ := strconv.Atoi(parts[0])
        selector, _ := strconv.Atoi(parts[1])
        mtype, _ := strconv.Atoi(parts[2])
        certData := strings.Join(parts[3:], "")

        certDisplay := certData
        if len(certData) > 64 {
                certDisplay = certData[:64] + "..."
        }

        rec := map[string]any{
                mapKeyMxHost:       mxHost,
                "tlsa_name":        tlsaName,
                "usage":            usage,
                "usage_name":       lookupName(daneUsageNames, usage),
                "selector":         selector,
                "selector_name":    lookupName(daneSelectorNames, selector),
                "matching_type":    mtype,
                "matching_name":    lookupName(daneMatchingNames, mtype),
                "certificate_data": certDisplay,
                "full_record":      fmt.Sprintf("%d %d %d %s", usage, selector, mtype, certDisplay),
        }

        if usage == 0 || usage == 1 {
                rec["recommendation"] = "RFC 7672 §3.1 recommends usage 2 (DANE-TA) or 3 (DANE-EE) for SMTP"
        }

        return rec, true
}

// checkMXTLSA resolves the TLSA RRset for one MX host and classifies it into a
// DANE tri-state. A transient resolver failure (LookupError) returns
// daneStateIndeterminate — NOT absence — so a timed-out probe never reads as
// "DANE removed". An authoritative no-record (LookupAbsent) is absent_confirmed.
func (a *Analyzer) checkMXTLSA(ctx context.Context, mxHost string) (string, []map[string]any, bool, string) {
        tlsaName := fmt.Sprintf("_25._tcp.%s", mxHost)
        var found []map[string]any

        result, status := a.DNS.QueryDNSWithTTLStatus(ctx, "TLSA", tlsaName)
        switch status {
        case dnsclient.LookupResolved:
                for _, entry := range result.Records {
                        if rec, ok := parseTLSAEntry(entry, mxHost, tlsaName); ok {
                                rec["dnssec_authenticated"] = result.Authenticated
                                found = append(found, rec)
                        }
                }
                if len(found) == 0 {
                        // Records returned but none parsed as valid TLSA — treat as
                        // an authoritative absence of usable DANE material.
                        return mxHost, found, false, daneStateAbsentConf
                }
                return mxHost, found, result.Authenticated, daneStatePresent
        case dnsclient.LookupAbsent:
                return mxHost, found, false, daneStateAbsentConf
        default: // LookupError — indeterminate, must not be read as absence
                return mxHost, found, false, daneStateIndeterminate
        }
}

func lookupName(m map[int]string, key int) string {
        if name, ok := m[key]; ok {
                return name
        }
        return fmt.Sprintf("Unknown (%d)", key)
}

func extractMXHosts(mxRecords []string) []string {
        var mxHosts []string
        seen := make(map[string]bool)
        for _, mx := range mxRecords {
                parts := strings.Fields(strings.TrimSpace(mx))
                var host string
                if len(parts) >= 2 {
                        host = strings.TrimRight(parts[len(parts)-1], ".")
                } else if len(parts) == 1 {
                        host = strings.TrimRight(parts[0], ".")
                }
                if host != "" && host != "." && !seen[host] {
                        seen[host] = true
                        mxHosts = append(mxHosts, host)
                }
        }
        return mxHosts
}

func pluralSuffix(count int) string {
        if count > 1 {
                return "s"
        }
        return ""
}

func collectTLSAIssues(allTLSA []map[string]any) []string {
        var issues []string
        for _, rec := range allTLSA {
                usage := rec["usage"].(int)
                if usage == 0 || usage == 1 {
                        issues = append(issues, fmt.Sprintf("TLSA for %s: usage %d (PKIX-based) — RFC 7672 §3.1 recommends usage 2 or 3 for SMTP", rec[mapKeyMxHost], usage))
                }
                if rec["matching_type"].(int) == 0 {
                        issues = append(issues, fmt.Sprintf("TLSA for %s: exact match (type 0) — SHA-256 (type 1) is preferred for resilience", rec[mapKeyMxHost]))
                }
        }
        return issues
}

func findMissingHosts(mxHosts, hostsWithDANE []string) []string {
        daneSet := make(map[string]bool, len(hostsWithDANE))
        for _, dh := range hostsWithDANE {
                daneSet[dh] = true
        }
        var missing []string
        for _, h := range mxHosts {
                if !daneSet[h] {
                        missing = append(missing, h)
                }
        }
        if len(missing) > 3 {
                missing = missing[:3]
        }
        return missing
}

func buildDANEVerdictNoTLSA(mxHosts []string, mxCapability map[string]any) (string, string, []string) {
        if mxCapability != nil && !mxCapability[mapKeyDaneInbound].(bool) {
                providerName := mxCapability[mapKeyProviderName].(string)
                return statusInfo, fmt.Sprintf("DANE not available — %s does not support inbound DANE/TLSA on its MX infrastructure", providerName), nil
        }
        return statusInfo, fmt.Sprintf("No DANE/TLSA records found (checked %d MX host%s)", len(mxHosts), pluralSuffix(len(mxHosts))), nil
}

func buildDANEVerdict(allTLSA []map[string]any, hostsWithDANE, mxHosts []string, mxCapability map[string]any) (string, string, []string) {
        if len(allTLSA) == 0 {
                return buildDANEVerdictNoTLSA(mxHosts, mxCapability)
        }

        issues := collectTLSAIssues(allTLSA)
        suffix := pluralSuffix(len(mxHosts))

        if len(hostsWithDANE) == len(mxHosts) {
                return "success", fmt.Sprintf("DANE configured — TLSA records found for all %d MX host%s", len(mxHosts), suffix), issues
        }

        missing := findMissingHosts(mxHosts, hostsWithDANE)
        issues = append(issues, fmt.Sprintf("Missing DANE for: %s", strings.Join(missing, ", ")))

        return "warning", fmt.Sprintf("DANE partially configured — TLSA records on %d/%d MX hosts", len(hostsWithDANE), len(mxHosts)), issues
}

func buildTransportDescription(cap map[string]any) string {
        inbound, _ := cap[mapKeyDaneInbound].(bool)
        outbound, _ := cap[mapKeyDaneOutbound].(bool)
        provider, _ := cap[mapKeyProviderName].(string)
        alternative, _ := cap[mapKeyAlternative].(string)

        if inbound && outbound {
                return "Full DANE support — inbound and outbound SMTP protected"
        }
        if outbound {
                return "Outbound DANE verification supported; inbound requires alternative (e.g., MTA-STS)"
        }
        desc := fmt.Sprintf("%s does not support DANE.", provider)
        if alternative != "" {
                desc += fmt.Sprintf(" Consider %s as an alternative for transport security.", alternative)
        }
        return desc
}

func deploymentGuidance(mxCapability map[string]any) string {
        inbound, _ := mxCapability[mapKeyDaneInbound].(bool)
        if inbound {
                return "Your MX provider supports DANE. Publish TLSA records for your MX hosts to enable DANE protection."
        }
        alt, _ := mxCapability[mapKeyAlternative].(string)
        if alt != "" {
                return fmt.Sprintf("Your MX provider does not support DANE inbound. Consider deploying %s as an alternative for transport security.", alt)
        }
        return "Your MX provider does not support DANE inbound. Consider MTA-STS as an alternative for transport security."
}

func buildProviderContext(mxCapability map[string]any) map[string]any {
        providerContext := map[string]any{
                mapKeyProviderName:    mxCapability[mapKeyProviderName],
                mapKeyDaneInbound:     mxCapability[mapKeyDaneInbound],
                mapKeyDaneOutbound:    mxCapability[mapKeyDaneOutbound],
                "deployment_guidance": deploymentGuidance(mxCapability),
        }
        if alt, ok := mxCapability[mapKeyAlternative]; ok {
                providerContext["alternative_protection"] = alt
        }
        return providerContext
}

func applyMXCapability(baseResult map[string]any, mxCapability map[string]any, domain string) {
        baseResult["mx_provider"] = mxCapability
        baseResult[mapKeyDaneDeployable] = mxCapability[mapKeyDaneInbound]
        if !mxCapability[mapKeyDaneInbound].(bool) {
                slog.Info("MX provider does not support inbound DANE",
                        "provider", mxCapability[mapKeyProviderName], "domain", domain)
        }
        baseResult["transport_security"] = map[string]any{
                "smtp_inbound":  mxCapability[mapKeyDaneInbound],
                "smtp_outbound": mxCapability[mapKeyDaneOutbound],
                "description":   buildTransportDescription(mxCapability),
        }
        baseResult["provider_context"] = buildProviderContext(mxCapability)
}

// daneMXScan is the aggregate of the per-MX TLSA classification. The three host
// slices are mutually exclusive partitions of the checked MX set; their lengths
// drive the overall tri-state and verdict.
type daneMXScan struct {
        allTLSA            []map[string]any
        hostsWithDANE      []string
        absentHosts        []string
        indeterminateHosts []string
        authenticated      bool
}

func collectTLSAFromMXHosts(ctx context.Context, a *Analyzer, mxHosts []string) daneMXScan {
        var scan daneMXScan
        allAuthenticated := true
        anyFound := false
        var mu sync.Mutex
        var wg sync.WaitGroup

        for _, host := range mxHosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        mxHost, records, authenticated, state := a.checkMXTLSA(ctx, h)
                        mu.Lock()
                        defer mu.Unlock()
                        switch state {
                        case daneStatePresent:
                                scan.hostsWithDANE = append(scan.hostsWithDANE, mxHost)
                                scan.allTLSA = append(scan.allTLSA, records...)
                                anyFound = true
                                if !authenticated {
                                        allAuthenticated = false
                                }
                        case daneStateIndeterminate:
                                scan.indeterminateHosts = append(scan.indeterminateHosts, mxHost)
                        default: // daneStateAbsentConf
                                scan.absentHosts = append(scan.absentHosts, mxHost)
                        }
                }(host)
        }
        wg.Wait()

        scan.authenticated = anyFound && allAuthenticated
        return scan
}

// overallDANEState folds the per-MX partitions into the domain-level tri-state.
// Absence may ONLY be asserted from authoritative resolver answers (LookupAbsent),
// never from a failed probe or a provider heuristic (RFC 6698 §1 / Zero
// Fabrication). Any present host wins (DANE is deployed); otherwise any host whose
// TLSA lookup did not complete makes the whole verdict indeterminate ("could not
// verify"); only when every host returned an authoritative no-record is it a
// confirmed absence. Provider capability (e.g. Google Workspace / M365 cannot do
// inbound DANE) is retained as ADVISORY deployment context elsewhere — it must
// never override a failed measurement into a fabricated confirmed-absence verdict.
func overallDANEState(scan daneMXScan, _ map[string]any) string {
        switch {
        case len(scan.hostsWithDANE) > 0:
                return daneStatePresent
        case len(scan.indeterminateHosts) > 0:
                return daneStateIndeterminate
        default:
                return daneStateAbsentConf
        }
}

func cappedHostList(hosts []string) string {
        if len(hosts) > 3 {
                hosts = hosts[:3]
        }
        return strings.Join(hosts, ", ")
}

// buildDANEVerdictIndeterminate renders the honest "could not verify" verdict.
// It is explicitly NOT a finding: RFC 6698 absence of a TLSA record can only be
// asserted from an authoritative answer, never from a failed lookup.
func buildDANEVerdictIndeterminate(scan daneMXScan, mxHosts []string) (string, string, []string) {
        msg := fmt.Sprintf("DANE could not be verified — TLSA lookups for %d of %d MX host%s did not complete (transient resolver failure). This is not evidence that DANE is absent (RFC 6698 §1).",
                len(scan.indeterminateHosts), len(mxHosts), pluralSuffix(len(mxHosts)))
        issues := []string{
                fmt.Sprintf("Indeterminate TLSA lookup for: %s — re-run before drawing a conclusion", cappedHostList(scan.indeterminateHosts)),
        }
        return statusUnknown, msg, issues
}

// daneVerdict selects the verdict for the computed tri-state, delegating the
// present/absent cases to buildDANEVerdict (unchanged) and handling the
// indeterminate case and the present-with-unverified-hosts mix honestly.
func daneVerdict(scan daneMXScan, mxHosts []string, mxCapability map[string]any) (string, string, []string) {
        switch overallDANEState(scan, mxCapability) {
        case daneStateIndeterminate:
                return buildDANEVerdictIndeterminate(scan, mxHosts)
        case daneStateAbsentConf:
                return buildDANEVerdict(scan.allTLSA, scan.hostsWithDANE, mxHosts, mxCapability)
        default: // present (full or partial)
                if len(scan.indeterminateHosts) == 0 {
                        return buildDANEVerdict(scan.allTLSA, scan.hostsWithDANE, mxHosts, mxCapability)
                }
                // Present on some hosts, but others could not be verified. Do NOT
                // call the unverified hosts "missing" — report them as unverified.
                issues := collectTLSAIssues(scan.allTLSA)
                issues = append(issues, fmt.Sprintf("TLSA lookup did not complete for %d MX host%s (%s) — re-check before treating as missing",
                        len(scan.indeterminateHosts), pluralSuffix(len(scan.indeterminateHosts)), cappedHostList(scan.indeterminateHosts)))
                if len(scan.absentHosts) > 0 {
                        issues = append(issues, fmt.Sprintf("Missing DANE for: %s", cappedHostList(scan.absentHosts)))
                }
                msg := fmt.Sprintf("DANE partially configured — TLSA records on %d/%d MX hosts; %d unverified",
                        len(scan.hostsWithDANE), len(mxHosts), len(scan.indeterminateHosts))
                return "warning", msg, issues
        }
}

func newBaseDANEResult() map[string]any {
        return map[string]any{
                "status":               statusInfo,
                mapKeyMessage:          "No DANE/TLSA records found for mail servers",
                "has_dane":             false,
                "dane_state":           daneStateAbsentConf,
                "mx_hosts_checked":     0,
                "mx_hosts_with_dane":   0,
                "mx_hosts_indeterminate": 0,
                "indeterminate_hosts":  []string{},
                "tlsa_records":         []map[string]any{},
                "requires_dnssec":      true,
                "issues":               []string{},
                "mx_provider":          nil,
                mapKeyDaneDeployable:   true,
                "dnssec_chain_status":  "unknown",
                "dnssec_required_note": "DANE requires DNSSEC (RFC 6698 §1). TLSA records are only validated when the zone is DNSSEC-signed.",
        }
}

func (a *Analyzer) AnalyzeDANE(ctx context.Context, domain string, mxRecords []string) map[string]any {
        baseResult := newBaseDANEResult()

        if len(mxRecords) == 0 {
                baseResult[mapKeyMessage] = "No MX records available — DANE check skipped"
                return baseResult
        }

        mxHosts := extractMXHosts(mxRecords)

        if len(mxHosts) == 0 {
                baseResult[mapKeyMessage] = "No valid MX hosts — DANE check skipped"
                return baseResult
        }

        if len(mxHosts) > 10 {
                mxHosts = mxHosts[:10]
        }

        mxCapability := a.detectMXDANECapability(mxHosts)
        if mxCapability != nil {
                applyMXCapability(baseResult, mxCapability, domain)
        }

        scan := collectTLSAFromMXHosts(ctx, a, mxHosts)
        daneState := overallDANEState(scan, mxCapability)

        indetHosts := scan.indeterminateHosts
        if indetHosts == nil {
                indetHosts = []string{}
        }

        baseResult["mx_hosts_checked"] = len(mxHosts)
        baseResult["mx_hosts_with_dane"] = len(scan.hostsWithDANE)
        baseResult["mx_hosts_indeterminate"] = len(scan.indeterminateHosts)
        baseResult["indeterminate_hosts"] = indetHosts
        baseResult["tlsa_records"] = scan.allTLSA
        baseResult["dnssec_authenticated"] = scan.authenticated

        status, message, issues := daneVerdict(scan, mxHosts, mxCapability)
        baseResult["status"] = status
        baseResult["dane_state"] = daneState
        baseResult[mapKeyMessage] = message
        baseResult["has_dane"] = len(scan.hostsWithDANE) > 0
        if mxCapability != nil && !mxCapability[mapKeyDaneInbound].(bool) {
                baseResult[mapKeyDaneDeployable] = false
        }
        baseResult["issues"] = issues

        if len(scan.allTLSA) > 0 && !scan.authenticated {
                issues = append(issues, "TLSA records found but DNSSEC AD flag not set — DANE requires DNSSEC validation (RFC 6698 §1)")
                baseResult["issues"] = issues
        }

        return baseResult
}
