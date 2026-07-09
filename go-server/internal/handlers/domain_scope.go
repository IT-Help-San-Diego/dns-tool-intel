// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func extractRootDomain(domain string) (isSubdomain bool, root string) {
	domain = strings.TrimRight(domain, ".")
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, ""
	}
	if strings.EqualFold(domain, registrable) {
		return false, ""
	}
	return true, registrable
}

func isPublicSuffixDomain(domain string) bool {
	domain = strings.TrimRight(domain, ".")
	_, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err == nil {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	if strings.EqualFold(domain, suffix) {
		return true
	}
	return isTwoPartSuffix(domain)
}

func isTwoPartSuffix(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	joined := strings.Join(parts[len(parts)-2:], ".")
	if !strings.EqualFold(domain, joined) {
		return false
	}
	suffixCheck, _ := publicsuffix.PublicSuffix(domain)
	return strings.EqualFold(suffixCheck, domain)
}

type subdomainEmailScope struct {
	IsSubdomain   bool   `json:"is_subdomain"`
	ParentDomain  string `json:"parent_domain"`
	SPFScope      string `json:"spf_scope"`
	DMARCScope    string `json:"dmarc_scope"`
	SPFNote       string `json:"spf_note"`
	DMARCNote     string `json:"dmarc_note"`
	HasLocalEmail bool   `json:"has_local_email"`
}

func isActiveStatus(status string) bool {
	return status == mapKeySuccess || status == mapKeyWarning
}

func parseOrgDMARC(records []string) (bool, string) {
	for _, r := range records {
		lower := strings.ToLower(strings.TrimSpace(r))
		if lower != "v=dmarc1" && !strings.HasPrefix(lower, "v=dmarc1;") && !strings.HasPrefix(lower, "v=dmarc1 ") {
			continue
		}
		policy := ""
		if idx := strings.Index(lower, "p="); idx >= 0 {
			rest := lower[idx+2:]
			if semi := strings.IndexByte(rest, ';'); semi >= 0 {
				policy = strings.TrimSpace(rest[:semi])
			} else {
				policy = strings.TrimSpace(rest)
			}
		}
		return true, policy
	}
	return false, ""
}

func determineDMARCScope(subHasDMARC, orgHasDMARC bool, orgDMARCPolicy, rootDomain string) (string, string) {
	if subHasDMARC {
		return "local", "DMARC record published at this subdomain"
	}
	if orgHasDMARC {
		policyNote := ""
		if orgDMARCPolicy != "" {
			policyNote = fmt.Sprintf(" (p=%s)", orgDMARCPolicy)
		}
		return "inherited", fmt.Sprintf("No subdomain DMARC record — organizational domain policy from %s%s applies per RFC 7489 §6.6.3", rootDomain, policyNote)
	}
	return "none", fmt.Sprintf("No DMARC record at this subdomain or organizational domain %s", rootDomain)
}

type dnsQuerier interface {
	QueryDNS(ctx context.Context, recordType, domain string) []string
}

func computeSubdomainEmailScope(ctx context.Context, dns dnsQuerier, domain, rootDomain string, results map[string]any) subdomainEmailScope {
	scope := subdomainEmailScope{
		IsSubdomain:  true,
		ParentDomain: rootDomain,
	}

	spf, ok := results[mapKeySpfAnalysis].(map[string]any)
	if !ok {
		spf = map[string]any{}
	}
	dmarc, ok := results[mapKeyDmarcAnalysis].(map[string]any)
	if !ok {
		dmarc = map[string]any{}
	}

	spfStatus, ok := spf[mapKeyStatus].(string)
	if !ok {
		spfStatus = ""
	}
	dmarcStatus, ok := dmarc[mapKeyStatus].(string)
	if !ok {
		dmarcStatus = ""
	}

	scope.SPFScope, scope.SPFNote = determineSPFScope(isActiveStatus(spfStatus))

	orgDMARCRecords := dns.QueryDNS(ctx, "TXT", fmt.Sprintf("_dmarc.%s", rootDomain))
	orgHasDMARC, orgDMARCPolicy := parseOrgDMARC(orgDMARCRecords)
	scope.DMARCScope, scope.DMARCNote = determineDMARCScope(isActiveStatus(dmarcStatus), orgHasDMARC, orgDMARCPolicy, rootDomain)

	scope.HasLocalEmail = hasLocalMXRecords(results)

	return scope
}

func determineSPFScope(subHasSPF bool) (string, string) {
	if subHasSPF {
		return "local", "SPF record published at this subdomain"
	}
	return "none", "No SPF record at this subdomain — SPF does not inherit from parent domains"
}

func hasLocalMXRecords(results map[string]any) bool {
	basic, ok := results["basic_records"].(map[string]any)
	if !ok || basic == nil {
		return false
	}
	switch mx := basic["MX"].(type) {
	case []string:
		return len(mx) > 0
	case []any:
		return len(mx) > 0
	}
	return false
}
