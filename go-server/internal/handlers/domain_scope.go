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

// extractRootDomain reports whether domain is a subdomain of a registrable
// organizational domain, per the Public Suffix List.
//
// Tri-state (Zero-Fabrication): the PSL lookup either resolves or it does not.
// When EffectiveTLDPlusOne errors (unlisted/unknown suffix in the snapshot
// compiled into golang.org/x/net/publicsuffix), indeterminate is true and
// isSubdomain/root are NOT meaningful — the caller must not render
// "not a subdomain" from a lookup that never completed. Absence in the local
// snapshot is not absence in the world; isSubdomain=false would be a claim
// the code did not earn.
func extractRootDomain(domain string) (isSubdomain bool, root string, indeterminate bool) {
	domain = strings.TrimRight(domain, ".")
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, "", true
	}
	if strings.EqualFold(domain, registrable) {
		return false, "", false
	}
	return true, registrable, false
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
	// Indeterminate is true when the Public Suffix List could not resolve the
	// domain's organizational root (unlisted/unknown suffix in the compiled-in
	// snapshot). All other fields are then unset — rendering anything from them
	// would be a claim the lookup did not earn.
	Indeterminate bool `json:"indeterminate,omitempty"`
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

func inheritedDMARCScopeFromFallback(dmarc map[string]any, rootDomain string) (string, string) {
	orgDomain, _ := dmarc["org_domain"].(string)
	if orgDomain == "" {
		orgDomain = rootDomain
	}
	policy, _ := dmarc["policy"].(string)
	source, _ := dmarc["effective_policy_source"].(string)
	policyNote := ""
	if policy != "" {
		tag := "p"
		if source == "sp" {
			tag = "sp"
		}
		policyNote = fmt.Sprintf(" (%s=%s)", tag, policy)
	}
	return "inherited", fmt.Sprintf("No subdomain DMARC record — organizational domain policy from %s%s applies per RFC 7489 §6.6.3", orgDomain, policyNote)
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

	if orgFallback, _ := dmarc["org_domain_fallback"].(bool); orgFallback {
		// The analyzer already confirmed authoritative absence at the
		// subdomain and resolved the organizational-domain policy per
		// RFC 7489 §6.6.3 — reuse its provenance instead of re-querying,
		// and never render this as a "Local" record (nothing is
		// published at the subdomain name).
		scope.DMARCScope, scope.DMARCNote = inheritedDMARCScopeFromFallback(dmarc, rootDomain)
	} else {
		orgDMARCRecords := dns.QueryDNS(ctx, "TXT", fmt.Sprintf("_dmarc.%s", rootDomain))
		orgHasDMARC, orgDMARCPolicy := parseOrgDMARC(orgDMARCRecords)
		scope.DMARCScope, scope.DMARCNote = determineDMARCScope(isActiveStatus(dmarcStatus), orgHasDMARC, orgDMARCPolicy, rootDomain)
	}

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
