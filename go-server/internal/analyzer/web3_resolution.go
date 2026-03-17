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

type Web3ResolutionResult struct {
        IsWeb3Input    bool   `json:"is_web3_input"`
        InputDomain    string `json:"input_domain"`
        ResolvedDomain string `json:"resolved_domain"`
        ResolutionType string `json:"resolution_type"`
        Gateway        string `json:"gateway"`
        Error          string `json:"error,omitempty"`
}

func DefaultWeb3Resolution() map[string]any {
        return map[string]any{
                "is_web3_input":   false,
                "input_domain":    "",
                "resolved_domain": "",
                "resolution_type": "",
                "gateway":         "",
                "error":           "",
        }
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
        return IsENSName(domain) || IsHNSName(domain)
}

func (a *Analyzer) ResolveWeb3Domain(ctx context.Context, domain string) Web3ResolutionResult {
        if IsENSName(domain) {
                return a.resolveENS(ctx, domain)
        }
        if IsHNSName(domain) {
                return a.resolveHNS(ctx, domain)
        }
        return Web3ResolutionResult{
                IsWeb3Input: false,
                InputDomain: domain,
        }
}

func (a *Analyzer) resolveENS(ctx context.Context, domain string) Web3ResolutionResult {
        result := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    domain,
                ResolutionType: "ens",
                Gateway:        ensGateway,
        }

        resolveCtx, cancel := context.WithTimeout(ctx, web3ResolutionTimeout)
        defer cancel()

        resolved, err := resolveViaGatewayRedirect(resolveCtx, domain, ensGateway)
        if err != nil {
                result.Error = fmt.Sprintf("ENS resolution failed: %s", err.Error())
                slog.Warn("ENS resolution failed", "domain", domain, "error", err)
                return result
        }

        if resolved != "" && resolved != domain {
                result.ResolvedDomain = resolved
                slog.Info("ENS domain resolved", "input", domain, "resolved", resolved, "gateway", ensGateway)
        } else if resolved == domain {
                result.ResolvedDomain = domain
        } else {
                result.Error = "ENS name did not resolve to a traditional domain"
        }

        return result
}

func (a *Analyzer) resolveHNS(ctx context.Context, domain string) Web3ResolutionResult {
        result := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    domain,
                ResolutionType: "hns",
        }

        for _, resolver := range []string{hnsResolverDomain, hnsResolverAlt} {
                records, err := a.DNS.QuerySpecificResolver(ctx, "A", domain, resolver+":53")
                if err == nil && len(records) > 0 {
                        result.ResolvedDomain = domain
                        result.Gateway = resolver
                        slog.Info("HNS domain resolved", "input", domain, "resolved", domain, "resolver", resolver)
                        return result
                }

                nsRecords, nsErr := a.DNS.QuerySpecificResolver(ctx, "NS", domain, resolver+":53")
                if nsErr == nil && len(nsRecords) > 0 {
                        result.ResolvedDomain = domain
                        result.Gateway = resolver
                        slog.Info("HNS domain resolved via NS", "input", domain, "resolver", resolver)
                        return result
                }

                slog.Warn("HNS resolution attempt failed", "domain", domain, "resolver", resolver, "error", err)
        }

        result.Error = "HNS name could not be resolved via public resolvers"
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
                resp.Body.Close()
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
        return map[string]any{
                "is_web3_input":   r.IsWeb3Input,
                "input_domain":    r.InputDomain,
                "resolved_domain": r.ResolvedDomain,
                "resolution_type": r.ResolutionType,
                "gateway":         r.Gateway,
                "error":           r.Error,
        }
}
