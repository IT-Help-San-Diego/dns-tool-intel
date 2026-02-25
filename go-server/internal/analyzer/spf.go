// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"
)

const spfRecordNone = "(none)"

var (
        spfIncludeRe  = regexp.MustCompile(`(?i)include:([^\s]+)`)
        spfAMechRe    = regexp.MustCompile(`(?i)\ba[:/]`)
        spfMXMechRe   = regexp.MustCompile(`(?i)\bmx[:/\s]`)
        spfPTRMechRe  = regexp.MustCompile(`(?i)\bptr[:/\s]`)
        spfExistsRe   = regexp.MustCompile(`(?i)exists:`)
        spfRedirectRe = regexp.MustCompile(`(?i)redirect=([^\s]+)`)
        spfAllRe      = regexp.MustCompile(`(?i)([+\-~?]?)all\b`)
)

type spfMechanismResult struct {
        lookupCount      int
        lookupMechanisms []string
        includes         []string
        issues           []string
}

func countSPFLookupMechanisms(spfLower string) spfMechanismResult {
        var r spfMechanismResult

        includeMatches := spfIncludeRe.FindAllStringSubmatch(spfLower, -1)
        for _, m := range includeMatches {
                r.includes = append(r.includes, m[1])
                r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("include:%s", m[1]))
        }
        r.lookupCount += len(includeMatches)

        aMatches := spfAMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(aMatches)
        if len(aMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "a mechanism")
        }

        mxMatches := spfMXMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(mxMatches)
        if len(mxMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "mx mechanism")
        }

        ptrMatches := spfPTRMechRe.FindAllString(spfLower, -1)
        r.lookupCount += len(ptrMatches)
        if len(ptrMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "ptr mechanism (deprecated)")
                r.issues = append(r.issues, "PTR mechanism used (deprecated, slow)")
        }

        existsMatches := spfExistsRe.FindAllString(spfLower, -1)
        r.lookupCount += len(existsMatches)
        if len(existsMatches) > 0 {
                r.lookupMechanisms = append(r.lookupMechanisms, "exists mechanism")
        }

        redirectMatch := spfRedirectRe.FindStringSubmatch(spfLower)
        if redirectMatch != nil {
                r.lookupCount++
                r.lookupMechanisms = append(r.lookupMechanisms, fmt.Sprintf("redirect:%s", redirectMatch[1]))
        }

        return r
}

func classifyAllQualifier(spfLower string) (*string, *string, []string) {
        allMatch := spfAllRe.FindStringSubmatch(spfLower)
        if allMatch == nil {
                return nil, nil, nil
        }

        qualifier := allMatch[1]
        if qualifier == "" {
                qualifier = "+"
        }
        am := qualifier + "all"

        var issues []string
        var p string
        switch qualifier {
        case "+", "":
                p = "DANGEROUS"
                issues = append(issues, "+all allows anyone to send as your domain")
        case "?":
                p = "NEUTRAL"
                issues = append(issues, "?all provides no protection")
        case "~":
                p = "SOFT"
        case "-":
                p = "STRICT"
        }

        return &p, &am, issues
}

func parseSPFMechanisms(spfRecord string) (int, []string, []string, *string, *string, []string, bool) {
        spfLower := strings.ToLower(spfRecord)

        r := countSPFLookupMechanisms(spfLower)
        permissiveness, allMechanism, allIssues := classifyAllQualifier(spfLower)
        issues := append(r.issues, allIssues...)

        hasSenders := len(r.includes) > 0 || len(spfAMechRe.FindAllString(spfLower, -1)) > 0 || len(spfMXMechRe.FindAllString(spfLower, -1)) > 0
        if permissiveness != nil && *permissiveness == "STRICT" && hasSenders {
                issues = append(issues, "RFC 7489 §10.1: -all may cause rejection before DMARC evaluation, preventing DKIM from being checked")
        }

        noMailIntent := false
        normalized := strings.Join(strings.Fields(strings.TrimSpace(spfLower)), " ")
        if normalized == "v=spf1 -all" || normalized == "\"v=spf1 -all\"" {
                noMailIntent = true
        }

        return r.lookupCount, r.lookupMechanisms, r.includes, permissiveness, allMechanism, issues, noMailIntent
}

func buildSPFVerdict(lookupCount int, permissiveness *string, noMailIntent bool, validSPF, spfLike []string) (string, string) {
        if len(validSPF) > 1 {
                return "error", "Multiple SPF records found - this causes SPF to fail (RFC 7208)"
        }
        if len(validSPF) == 0 {
                if len(spfLike) > 0 {
                        return "warning", "SPF-like record found but not valid — check syntax"
                }
                return "missing", "No SPF record found"
        }

        if lookupCount > 10 {
                return "error", fmt.Sprintf("SPF exceeds 10 DNS lookup limit (%d/10) — PermError per RFC 7208 §4.6.4", lookupCount)
        }
        if lookupCount == 10 {
                return "warning", "SPF at lookup limit (10/10 lookups) - no room for growth"
        }
        if permissiveness != nil && *permissiveness == "DANGEROUS" {
                return "error", "SPF uses +all - anyone can send as this domain"
        }
        if permissiveness != nil && *permissiveness == "NEUTRAL" {
                return "warning", "SPF uses ?all - provides no protection"
        }

        if noMailIntent {
                return "success", "Valid SPF (no mail allowed) - domain declares it sends no email"
        }
        if permissiveness != nil && *permissiveness == "STRICT" {
                return "success", fmt.Sprintf("SPF valid with strict enforcement (-all), %d/10 lookups", lookupCount)
        }
        if permissiveness != nil && *permissiveness == "SOFT" {
                return "success", fmt.Sprintf("SPF valid with industry-standard soft fail (~all), %d/10 lookups", lookupCount)
        }
        return "success", fmt.Sprintf("SPF valid, %d/10 lookups", lookupCount)
}

func classifySPFRecords(records []string) (validSPF, spfLike []string) {
        for _, record := range records {
                if record == "" {
                        continue
                }
                lower := strings.ToLower(strings.TrimSpace(record))
                if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
                        validSPF = append(validSPF, record)
                } else if strings.Contains(lower, "spf") {
                        spfLike = append(spfLike, record)
                }
        }
        return
}

func evaluateSPFRecordSet(validSPF []string) (int, []string, []string, *string, *string, []string, bool) {
        var issues []string
        lookupCount := 0
        var lookupMechanisms []string
        var permissiveness *string
        var allMechanism *string
        var includes []string
        noMailIntent := false

        if len(validSPF) > 1 {
                issues = append(issues, "Multiple SPF records (hard fail)")
        }

        if len(validSPF) == 1 {
                lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent = parseSPFMechanisms(validSPF[0])
                if lookupCount > 10 {
                        issues = append(issues, fmt.Sprintf("Exceeds 10 DNS lookup limit (%d lookups)", lookupCount))
                } else if lookupCount == 10 {
                        issues = append(issues, "At lookup limit (10/10)")
                }
        }

        return lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent
}

func extractRedirectTarget(spfRecord string) string {
        m := spfRedirectRe.FindStringSubmatch(spfRecord)
        if m == nil {
                return ""
        }
        return strings.TrimRight(m[1], ".")
}

func hasAllMechanism(spfRecord string) bool {
        return spfAllRe.MatchString(spfRecord)
}

type spfRedirectHop struct {
        Domain    string `json:"domain"`
        SPFRecord string `json:"spf_record"`
}

func (a *Analyzer) processSPFRedirectHop(ctx context.Context, target string, cumulativeLookups int) (hop spfRedirectHop, hopLookups int, issues []string, hasMore bool) {
        targetTXT := a.DNS.QueryDNS(ctx, "TXT", target)
        targetValid, _ := classifySPFRecords(targetTXT)

        if len(targetValid) == 0 {
                issues = append(issues, fmt.Sprintf("SPF redirect target %s has no valid SPF record — results in PermError (RFC 7208 §6.1)", target))
                hop = spfRedirectHop{Domain: target, SPFRecord: spfRecordNone}
                return
        }
        if len(targetValid) > 1 {
                issues = append(issues, fmt.Sprintf("SPF redirect target %s has multiple SPF records — results in PermError", target))
        }

        resolvedRecord := targetValid[0]
        hop = spfRedirectHop{Domain: target, SPFRecord: resolvedRecord}

        targetMechs := countSPFLookupMechanisms(strings.ToLower(resolvedRecord))
        hopLookups = targetMechs.lookupCount

        hasMore = extractRedirectTarget(resolvedRecord) != "" && !hasAllMechanism(resolvedRecord)
        return
}

func checkRedirectTermination(currentRecord, target string, visited map[string]bool, cumulativeLookups int) (issue string, stop bool) {
        if target == "" {
                return "", true
        }
        if hasAllMechanism(currentRecord) {
                return "", true
        }
        if visited[strings.ToLower(target)] {
                return fmt.Sprintf("SPF redirect loop detected at %s", target), true
        }
        if cumulativeLookups > 10 {
                return "SPF redirect chain exceeds 10 DNS lookup limit", true
        }
        return "", false
}

func (a *Analyzer) followSPFRedirectChain(ctx context.Context, spfRecord string, totalLookups int) ([]spfRedirectHop, string, int, []string) {
        var chain []spfRedirectHop
        visited := map[string]bool{}
        var redirectIssues []string
        currentRecord := spfRecord
        cumulativeLookups := totalLookups

        for i := 0; i < 10; i++ {
                target := extractRedirectTarget(currentRecord)
                issue, stop := checkRedirectTermination(currentRecord, target, visited, cumulativeLookups)
                if issue != "" {
                        redirectIssues = append(redirectIssues, issue)
                }
                if stop {
                        break
                }
                visited[strings.ToLower(target)] = true

                hop, hopLookups, hopIssues, hasMore := a.processSPFRedirectHop(ctx, target, cumulativeLookups)
                chain = append(chain, hop)
                cumulativeLookups += hopLookups
                redirectIssues = append(redirectIssues, hopIssues...)

                if hop.SPFRecord == spfRecordNone {
                        break
                }

                if hasMore {
                        currentRecord = hop.SPFRecord
                        continue
                }

                return chain, hop.SPFRecord, cumulativeLookups, redirectIssues
        }

        if len(chain) > 0 {
                return chain, chain[len(chain)-1].SPFRecord, cumulativeLookups, redirectIssues
        }
        return chain, "", cumulativeLookups, redirectIssues
}

func redirectChainToMaps(chain []spfRedirectHop) []map[string]any {
        var maps []map[string]any
        for _, hop := range chain {
                maps = append(maps, map[string]any{
                        "domain":     hop.Domain,
                        "spf_record": hop.SPFRecord,
                })
        }
        return maps
}

type spfEvalState struct {
        lookupCount      int
        lookupMechanisms []string
        includes         []string
        permissiveness   *string
        allMechanism     *string
        noMailIntent     bool
        issues           []string
}

func mergeResolvedSPF(resolved string, s *spfEvalState) {
        _, resolvedMechs, resolvedIncludes, resolvedPerm, resolvedAll, _, resolvedNoMail := parseSPFMechanisms(resolved)
        s.lookupMechanisms = append(s.lookupMechanisms, resolvedMechs...)
        s.includes = append(s.includes, resolvedIncludes...)
        if resolvedPerm != nil {
                s.permissiveness = resolvedPerm
        }
        if resolvedAll != nil {
                s.allMechanism = resolvedAll
        }
        if resolvedNoMail {
                s.noMailIntent = true
        }
}

func (a *Analyzer) handleSPFRedirectChain(ctx context.Context, validSPF []string, s *spfEvalState) ([]map[string]any, string) {
        if len(validSPF) != 1 {
                return nil, ""
        }

        target := extractRedirectTarget(validSPF[0])
        if target == "" || hasAllMechanism(validSPF[0]) {
                return nil, ""
        }

        chain, resolved, totalLookups, redirectIssues := a.followSPFRedirectChain(ctx, validSPF[0], s.lookupCount)
        s.lookupCount = totalLookups
        s.issues = append(s.issues, redirectIssues...)
        redirectChainMaps := redirectChainToMaps(chain)

        if resolved != "" && resolved != spfRecordNone {
                mergeResolvedSPF(resolved, s)
                return redirectChainMaps, resolved
        }

        return redirectChainMaps, ""
}

func (a *Analyzer) AnalyzeSPF(ctx context.Context, domain string) map[string]any {
        txtRecords := a.DNS.QueryDNS(ctx, "TXT", domain)

        baseResult := map[string]any{
                "status":            "missing",
                "message":           "No SPF record found",
                "records":           []string{},
                "valid_records":     []string{},
                "spf_like":          []string{},
                "lookup_count":      0,
                "lookup_mechanisms": []string{},
                "permissiveness":    nil,
                "all_mechanism":     nil,
                "issues":            []string{},
                "includes":          []string{},
                "no_mail_intent":    false,
                "redirect_chain":    []map[string]any{},
                "resolved_spf":     "",
        }

        if len(txtRecords) == 0 {
                return baseResult
        }

        validSPF, spfLike := classifySPFRecords(txtRecords)
        lookupCount, lookupMechanisms, includes, permissiveness, allMechanism, issues, noMailIntent := evaluateSPFRecordSet(validSPF)

        s := &spfEvalState{
                lookupCount:      lookupCount,
                lookupMechanisms: lookupMechanisms,
                includes:         includes,
                permissiveness:   permissiveness,
                allMechanism:     allMechanism,
                noMailIntent:     noMailIntent,
                issues:           issues,
        }

        redirectChainMaps, resolvedSPF := a.handleSPFRedirectChain(ctx, validSPF, s)

        status, message := buildSPFVerdict(s.lookupCount, s.permissiveness, s.noMailIntent, validSPF, spfLike)

        if len(redirectChainMaps) > 0 && resolvedSPF != "" {
                chainDomains := make([]string, 0, len(redirectChainMaps))
                for _, hop := range redirectChainMaps {
                        chainDomains = append(chainDomains, hop["domain"].(string))
                }
                message = fmt.Sprintf("%s (via redirect: %s)", message, strings.Join(chainDomains, " → "))
        }

        if redirectChainMaps == nil {
                redirectChainMaps = []map[string]any{}
        }

        result := map[string]any{
                "status":            status,
                "message":           message,
                "records":           txtRecords,
                "valid_records":     validSPF,
                "spf_like":          spfLike,
                "lookup_count":      s.lookupCount,
                "lookup_mechanisms": s.lookupMechanisms,
                "permissiveness":    derefStr(s.permissiveness),
                "all_mechanism":     derefStr(s.allMechanism),
                "issues":            s.issues,
                "includes":          s.includes,
                "no_mail_intent":    s.noMailIntent,
                "redirect_chain":    redirectChainMaps,
                "resolved_spf":     resolvedSPF,
        }

        ensureStringSlices(result, "valid_records", "spf_like", "lookup_mechanisms", "issues", "includes")

        return result
}
