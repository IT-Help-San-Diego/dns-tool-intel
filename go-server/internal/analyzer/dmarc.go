// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"

        "dnstool/go-server/internal/dnsclient"
)

const (
        mapKeyDmarcLike    = "dmarc_like"
        mapKeyQuarantine   = "quarantine"
        mapKeyRecords      = "records"
        mapKeyReject       = "reject"
        mapKeyRelaxed      = "relaxed"
        mapKeyStatus       = "status"
        mapKeyValidRecords = "valid_records"
)

// DMARC presence tri-state (RFC 7489 §6.6.3: a Mail Receiver treats a DNS
// temporary error as "TempError", NOT as "no DMARC record / p=none"). mapKeyDmarcState
// distinguishes "no record published" (absent_confirmed) from "lookup did not
// complete" (indeterminate), mirroring spf_state / dane_state / dnssec_state.
const (
        mapKeyDmarcState        = "dmarc_state"
        dmarcStatePresent       = triStatePresent
        dmarcStateAbsentConf    = triStateAbsentConf
        dmarcStateIndeterminate = triStateIndeterminate
)

var (
        dmarcPolicyRe   = regexp.MustCompile(`(?i)\bp=(\w+)`)
        dmarcSPRe       = regexp.MustCompile(`(?i)\bsp=(\w+)`)
        dmarcPctRe      = regexp.MustCompile(`(?i)\bpct=(\d+)`)
        dmarcASPFRe     = regexp.MustCompile(`(?i)\baspf=([rs])`)
        dmarcADKIMRe    = regexp.MustCompile(`(?i)\badkim=([rs])`)
        dmarcRUARe      = regexp.MustCompile(`(?i)\brua=([^;\s]+)`)
        dmarcRUFRe      = regexp.MustCompile(`(?i)\bruf=([^;\s]+)`)
        dmarcNPRe       = regexp.MustCompile(`(?i)\bnp=(\w+)`)
        dmarcTRe        = regexp.MustCompile(`(?i)\bt=([yn])`)
        dmarcPSDRe      = regexp.MustCompile(`(?i)\bpsd=([yn])`)
        mailtoExtractRe = regexp.MustCompile(`(?i)mailto:([^,;\s]+)`)
)

type dmarcTags struct {
        policy          *string
        subdomainPolicy *string
        pct             int
        aspf            string
        adkim           string
        rua             *string
        ruf             *string
        npPolicy        *string
        tTesting        *string
        psdFlag         *string
        unknownTags     []string
}

var knownDMARCTags = map[string]bool{
        "v": true, "p": true, "sp": true, "pct": true,
        "aspf": true, "adkim": true, "rua": true, "ruf": true,
        "fo": true, "rf": true, "ri": true,
        "np": true, "t": true, "psd": true,
}

func parseDMARCTags(record string) dmarcTags {
        recordLower := strings.ToLower(record)
        tags := dmarcTags{pct: 100, aspf: mapKeyRelaxed, adkim: mapKeyRelaxed}

        if m := dmarcPolicyRe.FindStringSubmatch(recordLower); m != nil {
                tags.policy = &m[1]
        }
        if m := dmarcSPRe.FindStringSubmatch(recordLower); m != nil {
                tags.subdomainPolicy = &m[1]
        }
        if m := dmarcPctRe.FindStringSubmatch(recordLower); m != nil {
                fmt.Sscanf(m[1], "%d", &tags.pct)
        }
        if m := dmarcASPFRe.FindStringSubmatch(recordLower); m != nil {
                if m[1] == "s" {
                        tags.aspf = "strict"
                }
        }
        if m := dmarcADKIMRe.FindStringSubmatch(recordLower); m != nil {
                if m[1] == "s" {
                        tags.adkim = "strict"
                }
        }
        if m := dmarcRUARe.FindStringSubmatch(record); m != nil {
                tags.rua = &m[1]
        }
        if m := dmarcRUFRe.FindStringSubmatch(record); m != nil {
                tags.ruf = &m[1]
        }
        if m := dmarcNPRe.FindStringSubmatch(recordLower); m != nil {
                tags.npPolicy = &m[1]
        }
        if m := dmarcTRe.FindStringSubmatch(recordLower); m != nil {
                tags.tTesting = &m[1]
        }
        if m := dmarcPSDRe.FindStringSubmatch(recordLower); m != nil {
                tags.psdFlag = &m[1]
        }

        tags.unknownTags = detectUnknownDMARCTags(record)

        return tags
}

func detectUnknownDMARCTags(record string) []string {
        var unknown []string
        parts := strings.Split(record, ";")
        for _, part := range parts {
                part = strings.TrimSpace(part)
                if part == "" {
                        continue
                }
                eqIdx := strings.Index(part, "=")
                if eqIdx < 0 {
                        continue
                }
                tagName := strings.TrimSpace(strings.ToLower(part[:eqIdx]))
                if tagName == "" {
                        continue
                }
                if !knownDMARCTags[tagName] {
                        unknown = append(unknown, part)
                }
        }
        return unknown
}

func classifyDMARCPolicyVerdict(policy string, pct int) (string, string, []string) {
        var status, message string
        var issues []string

        switch policy {
        case "none":
                status = "warning"
                message = "DMARC in monitoring mode (p=none) - spoofed mail still delivered, no enforcement"
                issues = append(issues, "Policy p=none provides no protection - spoofed emails reach inboxes")
        case mapKeyReject:
                status, message, issues = classifyEnforcementLevel(mapKeyReject, pct, "excellent")
        case mapKeyQuarantine:
                status, message, issues = classifyEnforcementLevel(mapKeyQuarantine, pct, "good")
        default:
                status = "info"
                message = "DMARC record found but policy unclear"
        }

        return status, message, issues
}

func classifyEnforcementLevel(policy string, pct int, quality string) (string, string, []string) {
        if pct < 100 {
                return "warning",
                        fmt.Sprintf("DMARC %s but only %d%% enforced - partial protection", policy, pct),
                        []string{fmt.Sprintf("Only %d%% of mail subject to policy", pct)}
        }
        return "success", fmt.Sprintf("DMARC policy %s (100%%) - %s protection", policy, quality), nil
}

func checkDMARCSubdomainIssues(tags dmarcTags) []string {
        if tags.policy == nil {
                return nil
        }
        if *tags.policy != mapKeyReject && *tags.policy != mapKeyQuarantine {
                return nil
        }
        var issues []string
        if tags.subdomainPolicy != nil && *tags.subdomainPolicy == "none" {
                issues = append(issues, fmt.Sprintf("Subdomains unprotected (sp=none while p=%s)", *tags.policy))
        }
        if tags.npPolicy == nil && tags.subdomainPolicy == nil {
                issues = append(issues, "No np= tag (DMARCbis) — non-existent subdomains inherit p= policy but adding np=reject provides explicit protection against subdomain spoofing")
        }
        return issues
}

// dmarcNoRuaIssue is the single source of truth for the "no aggregate reporting"
// DMARC finding, shared by the producer (checkDMARCReportingIssues) and the
// no-mail suppressor (suppressNoMailDMARCReporting) so the two never drift.
const dmarcNoRuaIssue = "No aggregate reporting (rua) configured — you won't receive reports about authentication results and potential abuse"

func checkDMARCReportingIssues(tags dmarcTags) []string {
        var issues []string
        if tags.rua == nil {
                issues = append(issues, dmarcNoRuaIssue)
        }
        return issues
}

// suppressNoMailDMARCReporting drops the "no rua configured" DMARC finding for a
// domain that BOTH clearly does not handle mail — a published null MX (RFC 7505)
// or an SPF no-mail intent — AND has already locked DMARC down to an enforcing
// policy (p=reject / p=quarantine). Such a domain carries no legitimate mail
// flow, so DMARC aggregate reporting (rua) provides no email-authentication
// visibility and its absence is not a gap. A half-configured record (p=none,
// empty, or unknown policy) is still a real gap the operator should close, so
// the finding is kept — mirroring the posture guard at classifyDMARCSuccess
// (policy != none). It runs at orchestrator assembly time, where both no-mail
// signals are known (AnalyzeDMARC runs in parallel with SPF/MX and cannot see
// them itself). Mail-handling, ambiguous, or half-configured domains are left
// untouched so they still receive the finding.
func suppressNoMailDMARCReporting(results map[string]any) {
        isNoMail := results[mapKeyHasNullMx] == true || results[mapKeyIsNoMailDomain] == true
        if !isNoMail {
                return
        }
        dmarc, ok := results["dmarc_analysis"].(map[string]any)
        if !ok {
                return
        }
        // Only a no-mail domain that ALSO enforces DMARC (reject/quarantine) has
        // closed the loop; a p=none / empty / unknown policy is half-configured and
        // still warrants the finding.
        policyStr, _ := dmarc["policy"].(string)
        switch strings.ToLower(policyStr) {
        case mapKeyReject, mapKeyQuarantine:
        default:
                return
        }
        issues, ok := dmarc[mapKeyIssues].([]string)
        if !ok {
                return
        }
        filtered := make([]string, 0, len(issues))
        for _, issue := range issues {
                if issue == dmarcNoRuaIssue {
                        continue
                }
                filtered = append(filtered, issue)
        }
        dmarc[mapKeyIssues] = filtered
}

func buildRUFNote(tags dmarcTags) map[string]any {
        if tags.ruf != nil {
                return map[string]any{
                        mapKeyStatus: "present",
                        "summary":    "Forensic reporting (ruf) is configured, but most major providers do not send forensic reports.",
                        "detail":     "RFC 7489 §7.3 warns that forensic reports can expose PII (full message headers or bodies). Google, Microsoft, and Yahoo do not honour ruf= requests. The DMARCbis draft (draft-ietf-dmarc-dmarcbis) has formally removed ruf= from the specification. Consider removing this tag to simplify your record.",
                }
        }
        return map[string]any{
                mapKeyStatus: "absent",
                "summary":    "No forensic reporting (ruf) tag — this is correct.",
                "detail":     "The absence of ruf= is not a gap. RFC 7489 §7.3 warns that forensic reports can expose PII (full message headers or bodies). Google, Microsoft, and Yahoo do not honour ruf= requests regardless. The DMARCbis draft (draft-ietf-dmarc-dmarcbis) has formally removed ruf= from the specification, confirming its deprecation. Omitting ruf= is the recommended modern practice.",
        }
}

func evaluateDMARCPolicy(tags dmarcTags) (string, string, []string) {
        if tags.policy == nil {
                return "info", "DMARC record found but policy unclear", nil
        }

        status, message, issues := classifyDMARCPolicyVerdict(*tags.policy, tags.pct)
        issues = append(issues, checkDMARCSubdomainIssues(tags)...)
        issues = append(issues, checkDMARCReportingIssues(tags)...)
        issues = append(issues, checkDMARCUnknownTags(tags)...)

        return status, message, issues
}

func checkDMARCUnknownTags(tags dmarcTags) []string {
        if len(tags.unknownTags) == 0 {
                return nil
        }
        var issues []string
        for _, tag := range tags.unknownTags {
                eqIdx := strings.Index(tag, "=")
                tagName := strings.TrimSpace(tag[:eqIdx])
                issues = append(issues, fmt.Sprintf("Unrecognized DMARC tag '%s' — per RFC 7489 §6.3, mail receivers will silently ignore this tag. If this is a typo, your intended policy is not being enforced", tagName))
        }
        return issues
}

func classifyDMARCRecords(records []string) (validDMARC, dmarcLike []string) {
        for _, record := range records {
                if record == "" {
                        continue
                }
                lower := strings.ToLower(strings.TrimSpace(record))
                if lower == "v=dmarc1" || strings.HasPrefix(lower, "v=dmarc1;") || strings.HasPrefix(lower, "v=dmarc1 ") {
                        validDMARC = append(validDMARC, record)
                } else if strings.Contains(lower, "dmarc") {
                        dmarcLike = append(dmarcLike, record)
                }
        }
        return
}

func evaluateDMARCRecordSet(validDMARC []string) (string, string, []string, dmarcTags) {
        tags := dmarcTags{pct: 100, aspf: mapKeyRelaxed, adkim: mapKeyRelaxed}

        if len(validDMARC) == 0 {
                return "error", "No valid DMARC record found", nil, tags
        }
        if len(validDMARC) > 1 {
                return "error",
                        "Multiple DMARC records found — receivers must treat this as no DMARC (RFC 7489 §6.6.3)",
                        []string{"Multiple DMARC records cause PermError — only one record permitted per RFC 7489"},
                        tags
        }

        tags = parseDMARCTags(validDMARC[0])
        status, message, issues := evaluateDMARCPolicy(tags)
        return status, message, issues, tags
}

func buildDMARCbisTags(tags dmarcTags) map[string]string {
        dmarcbisTags := map[string]string{}
        if tags.npPolicy != nil {
                dmarcbisTags["np"] = *tags.npPolicy
        }
        if tags.tTesting != nil {
                dmarcbisTags["t"] = *tags.tTesting
        }
        if tags.psdFlag != nil {
                dmarcbisTags["psd"] = *tags.psdFlag
        }
        return dmarcbisTags
}

func ensureStringSlices(result map[string]any, keys ...string) {
        for _, key := range keys {
                if result[key] == nil {
                        result[key] = []string{}
                }
        }
}

func (a *Analyzer) AnalyzeDMARC(ctx context.Context, domain string) map[string]any {
        dmarcRecords, lookupStatus := a.resolveWithStatus(ctx, "TXT", fmt.Sprintf("_dmarc.%s", domain))

        baseResult := map[string]any{
                mapKeyStatus:       "missing",
                mapKeyMessage:      "No DMARC record found",
                mapKeyRecords:      []string{},
                mapKeyValidRecords: []string{},
                mapKeyDmarcLike:    []string{},
                "policy":           nil,
                "subdomain_policy": nil,
                "pct":              100,
                "aspf":             mapKeyRelaxed,
                "adkim":            mapKeyRelaxed,
                "rua":              nil,
                "ruf":              nil,
                "ruf_note":         map[string]any{},
                "np_policy":        nil,
                "t_testing":        nil,
                "psd_flag":         nil,
                "dmarcbis_tags":    map[string]string{},
                "unknown_tags":     []string(nil),
                mapKeyIssues:       []string{},
                mapKeyDmarcState:   dmarcStateAbsentConf,
                "org_domain_fallback":     false,
                "org_domain":              "",
                "effective_policy_source": "",
        }

        if len(dmarcRecords) == 0 {
                // RFC 7489 §6.6.3: a DNS temporary error is a TempError, never an
                // absence of policy. Reporting a transient SERVFAIL/timeout as
                // "No DMARC record found" is a false negative — flag it honestly
                // and ask for a re-run instead of asserting absence.
                if lookupStatus == dnsclient.LookupError || lookupStatus == dnsclient.LookupConflict {
                        baseResult[mapKeyStatus] = statusIndeterminate
                        baseResult[mapKeyMessage] = "DMARC could not be verified — the DNS lookup did not complete (transient SERVFAIL/timeout). This is not a finding that DMARC is absent; re-run before drawing a conclusion."
                        baseResult[mapKeyDmarcState] = dmarcStateIndeterminate
                        if lookupStatus == dnsclient.LookupConflict {
                                baseResult[mapKeyMessage] = "DMARC could not be confirmed: public resolvers returned different records with no majority winner (DNS in flux / mid-propagation). This is not a finding that DMARC is absent; re-run once the change has propagated."
                        }
                        return baseResult
                }
                // Authoritative absence at the exact name. Before asserting
                // "missing", complete RFC 7489 §6.6.3 policy discovery: Mail
                // Receivers fall back to the organizational domain's record and
                // apply its sp= (or p= when sp is absent) to subdomain mail.
                return a.applyOrgDomainDMARCFallback(ctx, domain, baseResult)
        }

        validDMARC, dmarcLike := classifyDMARCRecords(dmarcRecords)
        status, message, issues, tags := evaluateDMARCRecordSet(validDMARC)

        result := map[string]any{
                mapKeyStatus:       status,
                mapKeyMessage:      message,
                mapKeyRecords:      dmarcRecords,
                mapKeyValidRecords: validDMARC,
                mapKeyDmarcLike:    dmarcLike,
                "policy":           derefStr(tags.policy),
                "subdomain_policy": derefStr(tags.subdomainPolicy),
                "pct":              tags.pct,
                "aspf":             tags.aspf,
                "adkim":            tags.adkim,
                "rua":              derefStr(tags.rua),
                "ruf":              derefStr(tags.ruf),
                "ruf_note":         buildRUFNote(tags),
                "np_policy":        derefStr(tags.npPolicy),
                "t_testing":        derefStr(tags.tTesting),
                "psd_flag":         derefStr(tags.psdFlag),
                "dmarcbis_tags":    buildDMARCbisTags(tags),
                "unknown_tags":     tags.unknownTags,
                mapKeyIssues:       issues,
                mapKeyDmarcState:   dmarcStatePresent,
        }

        ensureStringSlices(result, mapKeyValidRecords, mapKeyDmarcLike, mapKeyIssues)

        return result
}

// applyOrgDomainDMARCFallback implements step 3 of RFC 7489 §6.6.3 policy
// discovery: when no DMARC record exists at the exact (sub)domain name, Mail
// Receivers query _dmarc.<organizational domain> and apply its sp= tag (or p=
// when sp is absent) to subdomain mail. Reporting a subdomain as "missing
// DMARC" while the organizational domain enforces sp=reject is a false
// finding — the subdomain IS covered. Honesty constraints:
//   - records/valid_records stay EMPTY (nothing is published at the subdomain
//     name); inherited coverage is disclosed via org_domain_fallback,
//     org_domain, org_records and the message text.
//   - If the org-domain lookup does not complete, the result is indeterminate,
//     never absent (a TempError is not an absence of policy).
//   - Multiple valid records at the org domain mean receivers treat it as no
//     DMARC (RFC 7489 §6.6.3), so absence stands.
func (a *Analyzer) applyOrgDomainDMARCFallback(ctx context.Context, domain string, baseResult map[string]any) map[string]any {
        org, orgIndeterminate := orgDomain(domain)
        if orgIndeterminate {
                // Tri-state honesty: the Public Suffix List could not derive an
                // organizational domain (unlisted/unknown suffix in the compiled-in
                // snapshot). Without it we cannot name the org-domain DMARC target,
                // so we cannot distinguish "no coverage" from "inherited coverage".
                // Indeterminate — never report absence from a lookup that did not
                // complete. Absence in the local snapshot is not absence in the world.
                baseResult[mapKeyStatus] = statusIndeterminate
                baseResult[mapKeyDmarcState] = dmarcStateIndeterminate
                baseResult[mapKeyMessage] = fmt.Sprintf("No DMARC record at _dmarc.%s, and the organizational domain could not be derived from the Public Suffix List (unlisted/unknown suffix) — subdomain coverage per RFC 7489 §6.6.3 could not be verified. This is not a finding that DMARC is absent; re-run before drawing a conclusion.", domain)
                return baseResult
        }
        if strings.EqualFold(org, strings.TrimRight(domain, ".")) {
                // Apex: there is no higher organizational domain to fall back to.
                return baseResult
        }

        orgRecords, orgStatus := a.resolveWithStatus(ctx, "TXT", fmt.Sprintf("_dmarc.%s", org))
        if orgStatus == dnsclient.LookupError || orgStatus == dnsclient.LookupConflict {
                // Tri-state honesty: without a completed org-domain lookup we cannot
                // distinguish "no coverage" from "inherited coverage".
                baseResult[mapKeyStatus] = statusIndeterminate
                baseResult[mapKeyDmarcState] = dmarcStateIndeterminate
                baseResult[mapKeyMessage] = fmt.Sprintf("No DMARC record at _dmarc.%s, and the organizational-domain lookup (_dmarc.%s) did not complete — subdomain coverage per RFC 7489 §6.6.3 could not be verified. This is not a finding that DMARC is absent; re-run before drawing a conclusion.", domain, org)
                return baseResult
        }

        validDMARC, _ := classifyDMARCRecords(orgRecords)
        if len(validDMARC) == 0 {
                // The organizational domain publishes no DMARC either — the
                // confirmed absence stands.
                return baseResult
        }
        if len(validDMARC) > 1 {
                baseResult[mapKeyMessage] = fmt.Sprintf("No DMARC record at _dmarc.%s; the organizational domain %s publishes multiple DMARC records, which receivers must treat as no DMARC (RFC 7489 §6.6.3) — no inherited coverage", domain, org)
                return baseResult
        }

        tags := parseDMARCTags(validDMARC[0])
        effective := ""
        source := "p"
        if tags.policy != nil {
                effective = *tags.policy
        }
        if tags.subdomainPolicy != nil {
                effective = *tags.subdomainPolicy
                source = "sp"
        }

        // classifyDMARCPolicyVerdict (not evaluateDMARCPolicy) on purpose: the
        // org-record-scoped advisories (sp=none-while-p=reject, np= advice, rua
        // reporting) belong to the org domain's own report, not the subdomain's.
        status, _, issues := classifyDMARCPolicyVerdict(effective, tags.pct)
        message := fmt.Sprintf("Covered by organizational-domain DMARC (RFC 7489 §6.6.3): _dmarc.%s applies %s=%s to this subdomain's mail; no subdomain-specific record is published", org, source, effective)
        if effective == "" {
                message = fmt.Sprintf("Organizational-domain DMARC record at _dmarc.%s found (RFC 7489 §6.6.3 fallback) but its policy is unclear; no subdomain-specific record is published", org)
        }

        baseResult[mapKeyStatus] = status
        baseResult[mapKeyMessage] = message
        baseResult["policy"] = effective
        baseResult["subdomain_policy"] = derefStr(tags.subdomainPolicy)
        baseResult["pct"] = tags.pct
        baseResult["aspf"] = tags.aspf
        baseResult["adkim"] = tags.adkim
        baseResult["rua"] = derefStr(tags.rua)
        baseResult["ruf"] = derefStr(tags.ruf)
        baseResult["ruf_note"] = buildRUFNote(tags)
        baseResult["np_policy"] = derefStr(tags.npPolicy)
        baseResult["t_testing"] = derefStr(tags.tTesting)
        baseResult["psd_flag"] = derefStr(tags.psdFlag)
        baseResult["dmarcbis_tags"] = buildDMARCbisTags(tags)
        baseResult["unknown_tags"] = tags.unknownTags
        baseResult[mapKeyIssues] = issues
        baseResult[mapKeyDmarcState] = dmarcStatePresent
        baseResult["org_domain_fallback"] = true
        baseResult["org_domain"] = org
        baseResult["org_records"] = orgRecords
        baseResult["org_valid_records"] = validDMARC
        baseResult["effective_policy_source"] = source

        ensureStringSlices(baseResult, mapKeyIssues)

        return baseResult
}

func DetectMisplacedDMARC(rootTXTRecords []string) map[string]any {
        var found []string
        for _, record := range rootTXTRecords {
                lower := strings.ToLower(strings.TrimSpace(record))
                if lower == "v=dmarc1" || strings.HasPrefix(lower, "v=dmarc1;") || strings.HasPrefix(lower, "v=dmarc1 ") {
                        found = append(found, record)
                }
        }
        if len(found) == 0 {
                return map[string]any{
                        "detected": false,
                }
        }
        tags := parseDMARCTags(found[0])
        policy := ""
        if tags.policy != nil {
                policy = *tags.policy
        }
        return map[string]any{
                "detected":    true,
                mapKeyRecords: found,
                "policy_hint": policy,
                mapKeyMessage: "DMARC record found in root TXT records — this is ignored by mail receivers. DMARC records must be published at _dmarc.<domain> per RFC 7489 §6.1.",
        }
}

func ExtractMailtoDomains(ruaString string) []string {
        if ruaString == "" {
                return nil
        }
        var domains []string
        matches := mailtoExtractRe.FindAllStringSubmatch(ruaString, -1)
        for _, m := range matches {
                addr := m[1]
                if idx := strings.Index(addr, "@"); idx >= 0 {
                        d := strings.TrimRight(strings.TrimSpace(addr[idx+1:]), ".")
                        if d != "" {
                                domains = append(domains, strings.ToLower(d))
                        }
                }
        }
        return domains
}
