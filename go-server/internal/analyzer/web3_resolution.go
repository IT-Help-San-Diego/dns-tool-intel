// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "dnstool/go-server/internal/dnsclient"
        "fmt"
        "io"
        "log/slog"
        "regexp"
        "strings"
        "time"
)

const (
        ensGateway        = "eth.limo"
        hnsResolverDomain = "hnsdns.com"
        hnsResolverAlt    = "hdns.io"

        web3ResolutionTimeout = 8 * time.Second
        web3ResolutionBodyMax = 4096
)

var (
        ensNameRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.eth$`)

        knownHNSTLDs = map[string]bool{
                "hns": true, "c": true, "nb": true,
                "p": true, "d": true, "ix": true,
                "forever": true,
        }
)

type InputKind string

const (
        InputKindDNSDomain InputKind = "dns_domain"
        InputKindENSName   InputKind = "ens_name"
        InputKindHNSName   InputKind = "hns_name"
        // InputKindUDName is an Unstoppable Domains name: an on-chain registry
        // entry with NO DNS zone. Without this kind such a name classified as
        // InputKindDNSDomain and received the full DNS battery — SPF, DMARC and
        // DKIM queried against a name that cannot carry records, producing
        // "absent" findings about a namespace where absence is meaningless.
        // Scan scope must match registry type.
        InputKindUDName InputKind = "ud_name"
)

// udUnresolvableTLDs are TLDs Unstoppable Domains SOLD but does not list in
// any resolution producer: absent from its own catalogue
// (/resolve/supported_tlds) and absent from the IANA root zone. Measured
// 2026-07-31 against both.
//
// This is not a lookup failure and must never be reported as one. Two of
// these TLDs carry names in the operator's own portfolio — names on TLDs the
// vendor's resolution inventory does not contain. Recognising them lets the
// tool say precisely that, instead of emitting a generic "could not resolve"
// that blames the network for a vendor inventory gap.
var udUnresolvableTLDs = map[string]string{
        "agi":       "sold by Unstoppable Domains but absent from its resolution catalogue and from the IANA root zone",
        "robot":     "sold by Unstoppable Domains but absent from its resolution catalogue and from the IANA root zone",
        "metaverse": "absent from the Unstoppable Domains resolution catalogue and from the IANA root zone",
}

func tldOf(domain string) string {
        d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
        i := strings.LastIndexByte(d, '.')
        if i < 0 || i == len(d)-1 {
                return ""
        }
        return d[i+1:]
}

// IsUDName reports whether the input is an Unstoppable Domains name — either
// on a TLD UD actually resolves (the generated set, derived by subtracting the
// IANA root zone from UD's catalogue) or on one of the TLDs UD sold without
// listing. Both are UD names; only the first can resolve.
func IsUDName(domain string) bool {
        tld := tldOf(domain)
        if tld == "" {
                return false
        }
        if udWeb3TLDs[tld] {
                return true
        }
        _, unresolvable := udUnresolvableTLDs[tld]
        return unresolvable
}

// UDUnresolvableReason returns the recorded reason a UD name cannot resolve,
// or "" when its TLD is resolvable. The reason is a measurement about the
// vendor's inventory, not about this lookup.
func UDUnresolvableReason(domain string) string {
        return udUnresolvableTLDs[tldOf(domain)]
}

type AnalysisScope string

const (
        ScopeOwnedDNS       AnalysisScope = "owned_dns"
        ScopeGatewayDerived AnalysisScope = "gateway_derived"
        ScopeIdentityOnly   AnalysisScope = "identity_only"
)

type Web3ResolutionResult struct {
        IsWeb3Input        bool          `json:"is_web3_input"`
        InputDomain        string        `json:"input_domain"`
        ResolvedDomain     string        `json:"resolved_domain"`
        ResolutionType     string        `json:"resolution_type"`
        Gateway            string        `json:"gateway"`
        Error              string        `json:"error,omitempty"`
        InputKind          InputKind     `json:"input_kind"`
        AnalysisScope      AnalysisScope `json:"analysis_scope"`
        IsGatewayDomain    bool          `json:"is_gateway_domain"`
        AttributionWarning string        `json:"attribution_warning,omitempty"`
}

func DefaultWeb3Resolution() map[string]any {
        return map[string]any{
                "is_web3_input":        false,
                "input_domain":         "",
                "resolved_domain":      "",
                "resolution_type":      "",
                "gateway":              "",
                "error":                "",
                "input_kind":           string(InputKindDNSDomain),
                "analysis_scope":       string(ScopeOwnedDNS),
                "is_gateway_domain":    false,
                "attribution_warning":  "",
        }
}

func ClassifyInput(domain string) InputKind {
        if IsENSName(domain) {
                return InputKindENSName
        }
        if IsHNSName(domain) {
                return InputKindHNSName
        }
        if IsUDName(domain) {
                return InputKindUDName
        }
        return InputKindDNSDomain
}

func IsENSName(domain string) bool {
        return ensNameRe.MatchString(domain)
}

func IsHNSName(domain string) bool {
        parts := strings.Split(strings.ToLower(domain), ".")
        if len(parts) < 2 {
                return false
        }
        tld := parts[len(parts)-1]
        return knownHNSTLDs[tld]
}

func IsWeb3Input(domain string) bool {
        return IsENSName(domain) || IsHNSName(domain) || IsUDName(domain)
}

func (a *Analyzer) ResolveWeb3Domain(ctx context.Context, domain string) Web3ResolutionResult {
        if IsENSName(domain) {
                return a.resolveENS(ctx, domain)
        }
        if IsHNSName(domain) {
                return a.resolveHNS(ctx, domain)
        }
        if IsUDName(domain) {
                return udClassificationResult(domain)
        }
        return Web3ResolutionResult{
                IsWeb3Input: false,
                InputDomain: domain,
        }
}

// udClassificationResult classifies a UD name WITHOUT resolving it. On-chain
// resolution (GET /profile/public/<name>) is deliberately not performed here
// yet: classification is what stops the DNS battery running against a zoneless
// name, and it is correct on its own. Returning a fabricated or empty
// resolution would assert something unmeasured, so this reports scope
// identity-only and says why.
func udClassificationResult(domain string) Web3ResolutionResult {
        result := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    domain,
                ResolutionType: "ud",
                InputKind:      InputKindUDName,
                AnalysisScope:  ScopeIdentityOnly,
        }
        if reason := UDUnresolvableReason(domain); reason != "" {
                // Not a lookup failure: the vendor's own inventory omits this
                // TLD. Say that, rather than blaming the network.
                result.AttributionWarning = "This name is on an Unstoppable Domains TLD that cannot resolve — " + reason +
                        ". Findings here describe the name's registry status only; no DNS zone exists to evaluate."
                return result
        }
        result.AttributionWarning = "Unstoppable Domains name resolved on-chain, not in DNS. It has no DNS zone, " +
                "so email-authentication and DNSSEC findings do not apply — their absence is the namespace, not a gap."
        return result
}

func (a *Analyzer) resolveENS(ctx context.Context, domain string) Web3ResolutionResult {
        result := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    domain,
                ResolutionType: "ens",
                Gateway:        ensGateway,
                InputKind:      InputKindENSName,
        }

        resolveCtx, cancel := context.WithTimeout(ctx, web3ResolutionTimeout)
        defer cancel()

        resolved, err := resolveViaGatewayRedirect(resolveCtx, domain, ensGateway)
        if err != nil {
                result.Error = fmt.Sprintf("ENS resolution failed: %s", err.Error())
                result.AnalysisScope = ScopeIdentityOnly
                slog.Warn("ENS resolution failed", "domain", domain, "error", err)
                return result
        }

        if resolved != "" && resolved != domain {
                result.ResolvedDomain = resolved
                result.IsGatewayDomain = isGatewayDomain(resolved, ensGateway)
                if result.IsGatewayDomain {
                        result.AnalysisScope = ScopeGatewayDerived
                        result.AttributionWarning = fmt.Sprintf(
                                "DNS analysis targets gateway domain %s, not the ENS identity %s. "+
                                        "Email security results (SPF/DKIM/DMARC/MTA-STS/TLSRPT/BIMI) reflect "+
                                        "the gateway operator's configuration, not the ENS owner's infrastructure.",
                                resolved, domain)
                } else {
                        result.AnalysisScope = ScopeOwnedDNS
                }
                slog.Info("ENS domain resolved", "input", domain, "resolved", resolved, "gateway", ensGateway, "is_gateway", result.IsGatewayDomain)
        } else if resolved == domain {
                result.ResolvedDomain = domain
                result.AnalysisScope = ScopeOwnedDNS
        } else {
                result.Error = "ENS name did not resolve to a traditional domain"
                result.AnalysisScope = ScopeIdentityOnly
        }

        return result
}

func (a *Analyzer) resolveHNS(ctx context.Context, domain string) Web3ResolutionResult {
        result := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    domain,
                ResolutionType: "hns",
                InputKind:      InputKindHNSName,
                AnalysisScope:  ScopeGatewayDerived,
        }

        for _, resolver := range []string{hnsResolverDomain, hnsResolverAlt} {
                records, err := a.DNS.QuerySpecificResolver(ctx, "A", domain, resolver+":53")
                if err == nil && len(records) > 0 {
                        result.ResolvedDomain = domain
                        result.Gateway = resolver
                        result.IsGatewayDomain = true
                        result.AttributionWarning = fmt.Sprintf(
                                "DNS analysis resolves %s through public HNS resolver %s. "+
                                        "DNS infrastructure results (NS/DNSSEC/CAA) and email security results "+
                                        "reflect the resolver's configuration, not the HNS owner's infrastructure.",
                                domain, resolver)
                        slog.Info("HNS domain resolved", "input", domain, "resolved", domain, "resolver", resolver)
                        return result
                }

                nsRecords, nsErr := a.DNS.QuerySpecificResolver(ctx, "NS", domain, resolver+":53")
                if nsErr == nil && len(nsRecords) > 0 {
                        result.ResolvedDomain = domain
                        result.Gateway = resolver
                        result.IsGatewayDomain = true
                        result.AttributionWarning = fmt.Sprintf(
                                "DNS analysis resolves %s through public HNS resolver %s. "+
                                        "DNS infrastructure results (NS/DNSSEC/CAA) and email security results "+
                                        "reflect the resolver's configuration, not the HNS owner's infrastructure.",
                                domain, resolver)
                        slog.Info("HNS domain resolved via NS", "input", domain, "resolver", resolver)
                        return result
                }

                slog.Warn("HNS resolution attempt failed", "domain", domain, "resolver", resolver, "error", err)
        }

        result.Error = "HNS name could not be resolved via public resolvers"
        result.AnalysisScope = ScopeIdentityOnly
        return result
}

func resolveViaGatewayRedirect(ctx context.Context, ensDomain, gateway string) (string, error) {
        name := strings.TrimSuffix(strings.ToLower(ensDomain), ".eth")
        targetURL := fmt.Sprintf("https://%s.%s/", name, gateway)

        safeClient := dnsclient.NewSafeHTTPClientWithTimeout(web3ResolutionTimeout)

        resp, err := safeClient.HeadNoRedirect(ctx, targetURL)
        if err != nil {
                if strings.Contains(err.Error(), "timeout") {
                        return "", fmt.Errorf("gateway timeout")
                }
                return "", fmt.Errorf("gateway unreachable: %w", err)
        }
        defer func() {
                _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, web3ResolutionBodyMax))
                _ = resp.Body.Close()
        }()

        if resp.StatusCode >= 300 && resp.StatusCode < 400 {
                if loc := resp.Header.Get("Location"); loc != "" {
                        resolved := extractDomainFromURL(loc)
                        if resolved != "" && dnsclient.ValidateURLTarget("https://"+resolved+"/") {
                                return resolved, nil
                        }
                        return "", fmt.Errorf("redirect target failed SSRF validation")
                }
                return "", fmt.Errorf("redirect with no Location header")
        }

        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
                gatewayDomain := strings.TrimSuffix(strings.ToLower(ensDomain), ".eth") + "." + gateway
                return gatewayDomain, nil
        }

        return "", fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
}

func isGatewayDomain(resolved, gateway string) bool {
        return strings.HasSuffix(strings.ToLower(resolved), "."+strings.ToLower(gateway))
}

func extractDomainFromURL(rawURL string) string {
        rawURL = strings.TrimPrefix(rawURL, "https://")
        rawURL = strings.TrimPrefix(rawURL, "http://")
        if idx := strings.Index(rawURL, "/"); idx > 0 {
                rawURL = rawURL[:idx]
        }
        if idx := strings.Index(rawURL, ":"); idx > 0 {
                rawURL = rawURL[:idx]
        }
        return strings.TrimSpace(rawURL)
}

func (r Web3ResolutionResult) ToMap() map[string]any {
        m := map[string]any{
                "is_web3_input":        r.IsWeb3Input,
                "input_domain":         r.InputDomain,
                "resolved_domain":      r.ResolvedDomain,
                "resolution_type":      r.ResolutionType,
                "gateway":              r.Gateway,
                "error":                r.Error,
                "input_kind":           string(r.InputKind),
                "analysis_scope":       string(r.AnalysisScope),
                "is_gateway_domain":    r.IsGatewayDomain,
                "attribution_warning":  r.AttributionWarning,
        }
        return m
}
