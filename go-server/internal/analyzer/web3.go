// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "dnstool/go-server/internal/dnsclient"
        "fmt"
        "io"
        "regexp"
        "strings"
        "time"
)

const (
        mapKeyWeb3Analysis = "web3_analysis"

        web3StatusDetected    = "detected"
        web3StatusNotDetected = "not_detected"

        indicatorTypeDNSLink      = "dnslink"
        indicatorTypeCryptoWallet = "crypto_wallet"
        indicatorTypeENSRecord    = "ens_record"
        indicatorTypeIPFSHash     = "ipfs_hash"
        indicatorTypeIPNSName     = "ipns_name"

        ipfsGatewayDwebLink = "https://dweb.link"
        ipfsGatewayIPFSIO   = "https://ipfs.io"

        ipfsProbeTimeout  = 5 * time.Second
        ipfsProbeBodyMax  = 1024
)

var (
        dnslinkIPFSRe  = regexp.MustCompile(`(?i)^dnslink=/ipfs/([a-zA-Z0-9]+)`)
        dnslinkIPNSRe  = regexp.MustCompile(`(?i)^dnslink=/ipns/(.+)$`)
        cidV0Re        = regexp.MustCompile(`^Qm[1-9A-HJ-NP-Za-km-z]{44}$`)
        cidV1Re        = regexp.MustCompile(`^b[a-z2-7]{58,}$`)
        ethAddressRe   = regexp.MustCompile(`(?i)^(?:(?:ETH|eth\.addr|addr)[=:]\s*)?0x[0-9a-fA-F]{40}$`)
        btcAddressRe   = regexp.MustCompile(`(?i)^(?:(?:BTC|btc\.addr|addr)[=:]\s*)?([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$`)
        ensContentRe   = regexp.MustCompile(`(?i)(contenthash|_ens|eth\.addr)`)
)

var walletPatterns = []struct {
        name    string
        pattern *regexp.Regexp
}{
        {"Ethereum Address", ethAddressRe},
        {"Bitcoin Address", btcAddressRe},
}

type Web3Indicator struct {
        Type        string `json:"type"`
        Value       string `json:"value"`
        Description string `json:"description"`
        Link        string `json:"link,omitempty"`
}

type Web3Analysis struct {
        Detected       bool             `json:"detected"`
        Status         string           `json:"status"`
        Indicators     []Web3Indicator  `json:"indicators"`
        DNSLinkCID     string           `json:"dnslink_cid,omitempty"`
        DNSLinkIPNS    string           `json:"dnslink_ipns,omitempty"`
        IPFSReachable  *bool            `json:"ipfs_reachable,omitempty"`
        IPFSGatewayURL string           `json:"ipfs_gateway_url,omitempty"`
        IPFSError      string           `json:"ipfs_error,omitempty"`
        DNSSECTrust    string           `json:"dnssec_trust_note"`
        ResolutionInfo map[string]any   `json:"resolution_info,omitempty"`
        IndicatorCount int              `json:"indicator_count"`
}

func DefaultWeb3Analysis() map[string]any {
        return map[string]any{
                "detected":        false,
                "status":          web3StatusNotDetected,
                "indicators":      []Web3Indicator{},
                "indicator_count": 0,
                "dnssec_trust_note": "",
        }
}

func (a *Analyzer) AnalyzeWeb3(ctx context.Context, domain string, txtRecords []string, dnssecResult map[string]any) map[string]any {
        analysis := &Web3Analysis{
                Status:     web3StatusNotDetected,
                Indicators: []Web3Indicator{},
        }

        analysis.detectDNSLink(txtRecords)
        analysis.detectCryptoWallets(txtRecords)
        analysis.detectENSRecords(txtRecords)
        analysis.assessDNSSECTrust(dnssecResult)

        if len(analysis.Indicators) > 0 {
                analysis.Detected = true
                analysis.Status = web3StatusDetected
        }

        if analysis.DNSLinkCID != "" {
                analysis.verifyIPFSReachability(ctx)
        }

        analysis.IndicatorCount = len(analysis.Indicators)
        return analysis.toMap()
}

func AnalyzeWeb3Static(txtRecords []string, dnssecResult map[string]any) map[string]any {
        analysis := &Web3Analysis{
                Status:     web3StatusNotDetected,
                Indicators: []Web3Indicator{},
        }

        analysis.detectDNSLink(txtRecords)
        analysis.detectCryptoWallets(txtRecords)
        analysis.detectENSRecords(txtRecords)
        analysis.assessDNSSECTrust(dnssecResult)

        if len(analysis.Indicators) > 0 {
                analysis.Detected = true
                analysis.Status = web3StatusDetected
        }

        analysis.IndicatorCount = len(analysis.Indicators)
        return analysis.toMap()
}

func (w *Web3Analysis) detectDNSLink(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)

                if m := dnslinkIPFSRe.FindStringSubmatch(txt); m != nil {
                        cid := m[1]
                        w.DNSLinkCID = cid
                        gatewayURL := fmt.Sprintf("%s/ipfs/%s", ipfsGatewayDwebLink, cid)
                        w.IPFSGatewayURL = gatewayURL
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:        indicatorTypeDNSLink,
                                Value:       txt,
                                Description: fmt.Sprintf("IPFS content-addressed hosting via dnslink (CID: %s)", truncateCID(cid)),
                                Link:        gatewayURL,
                        })
                        continue
                }

                if m := dnslinkIPNSRe.FindStringSubmatch(txt); m != nil {
                        ipnsName := m[1]
                        w.DNSLinkIPNS = ipnsName
                        gatewayURL := fmt.Sprintf("%s/ipns/%s", ipfsGatewayDwebLink, ipnsName)
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:        indicatorTypeIPNSName,
                                Value:       txt,
                                Description: fmt.Sprintf("IPNS mutable naming via dnslink (name: %s)", truncateStr(ipnsName, 40)),
                                Link:        gatewayURL,
                        })
                }
        }
}

func (w *Web3Analysis) detectCryptoWallets(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)
                for _, wp := range walletPatterns {
                        if wp.pattern.MatchString(txt) {
                                w.Indicators = append(w.Indicators, Web3Indicator{
                                        Type:        indicatorTypeCryptoWallet,
                                        Value:       redactWalletAddress(txt),
                                        Description: fmt.Sprintf("%s found in DNS TXT record", wp.name),
                                })
                                break
                        }
                }
        }
}

func (w *Web3Analysis) detectENSRecords(txtRecords []string) {
        for _, txt := range txtRecords {
                txt = strings.TrimSpace(txt)
                if ensContentRe.MatchString(txt) {
                        w.Indicators = append(w.Indicators, Web3Indicator{
                                Type:        indicatorTypeENSRecord,
                                Value:       truncateStr(txt, 80),
                                Description: "ENS-related record detected in DNS TXT",
                        })
                }
        }
}

func (w *Web3Analysis) assessDNSSECTrust(dnssecResult map[string]any) {
        if dnssecResult == nil {
                w.DNSSECTrust = "DNSSEC status unknown — trustless Web3 resolution requires DNSSEC for DNS-based discovery"
                return
        }

        status, _ := dnssecResult["status"].(string)
        switch status {
        case "success":
                w.DNSSECTrust = "DNSSEC validated — DNS records are cryptographically signed, supporting trustless Web3 resolution"
        case "warning":
                w.DNSSECTrust = "DNSSEC partially configured — Web3 resolution trust is degraded without full chain validation"
        default:
                w.DNSSECTrust = "DNSSEC not configured — DNS records can be spoofed, undermining Web3 resolution trust"
        }
}

func (w *Web3Analysis) verifyIPFSReachability(ctx context.Context) {
        if w.DNSLinkCID == "" {
                return
        }

        if !IsValidCID(w.DNSLinkCID) {
                f := false
                w.IPFSReachable = &f
                w.IPFSError = "Invalid IPFS CID format"
                return
        }

        gateways := []string{ipfsGatewayDwebLink, ipfsGatewayIPFSIO}
        for _, gw := range gateways {
                probeURL := fmt.Sprintf("%s/ipfs/%s", gw, w.DNSLinkCID)
                reachable, err := probeIPFSGateway(ctx, probeURL)
                if reachable {
                        t := true
                        w.IPFSReachable = &t
                        w.IPFSGatewayURL = probeURL
                        return
                }
                if err != "" {
                        w.IPFSError = err
                }
        }

        f := false
        w.IPFSReachable = &f
        if w.IPFSError == "" {
                w.IPFSError = "Content not reachable via public IPFS gateways"
        }
}

func probeIPFSGateway(ctx context.Context, url string) (bool, string) {
        probeCtx, cancel := context.WithTimeout(ctx, ipfsProbeTimeout)
        defer cancel()

        client := dnsclient.NewSafeHTTPClientWithTimeout(ipfsProbeTimeout)

        resp, err := client.GetWithHeaders(probeCtx, url, map[string]string{
                "User-Agent": "DNS-Tool-Web3-Probe/1.0",
        })
        if err != nil {
                return false, fmt.Sprintf("Gateway unreachable: %s", classifyWeb3HTTPError(err))
        }
        defer func() {
                _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ipfsProbeBodyMax))
                resp.Body.Close()
        }()

        if resp.StatusCode >= 200 && resp.StatusCode < 400 {
                return true, ""
        }
        return false, fmt.Sprintf("Gateway returned HTTP %d", resp.StatusCode)
}

func classifyWeb3HTTPError(err error) string {
        errStr := err.Error()
        switch {
        case strings.Contains(errStr, "timeout"):
                return "timeout"
        case strings.Contains(errStr, "refused"):
                return "connection refused"
        case strings.Contains(errStr, "no such host"):
                return "DNS resolution failed"
        default:
                return "connection error"
        }
}

func IsValidCID(cid string) bool {
        if cid == "" {
                return false
        }
        return cidV0Re.MatchString(cid) || cidV1Re.MatchString(cid)
}

func truncateCID(cid string) string {
        if len(cid) <= 16 {
                return cid
        }
        return cid[:8] + "..." + cid[len(cid)-4:]
}

func truncateStr(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen-3] + "..."
}

func redactWalletAddress(addr string) string {
        if len(addr) <= 12 {
                return addr
        }
        return addr[:6] + "..." + addr[len(addr)-4:]
}

func (w *Web3Analysis) toMap() map[string]any {
        indicators := make([]map[string]any, len(w.Indicators))
        for i, ind := range w.Indicators {
                m := map[string]any{
                        "type":        ind.Type,
                        "value":       ind.Value,
                        "description": ind.Description,
                }
                if ind.Link != "" {
                        m["link"] = ind.Link
                }
                indicators[i] = m
        }

        result := map[string]any{
                "detected":          w.Detected,
                "status":            w.Status,
                "indicators":        indicators,
                "indicator_count":   w.IndicatorCount,
                "dnssec_trust_note": w.DNSSECTrust,
        }

        if w.DNSLinkCID != "" {
                result["dnslink_cid"] = w.DNSLinkCID
        }
        if w.DNSLinkIPNS != "" {
                result["dnslink_ipns"] = w.DNSLinkIPNS
        }
        if w.IPFSReachable != nil {
                result["ipfs_reachable"] = *w.IPFSReachable
        }
        if w.IPFSGatewayURL != "" {
                result["ipfs_gateway_url"] = w.IPFSGatewayURL
        }
        if w.IPFSError != "" {
                result["ipfs_error"] = w.IPFSError
        }
        if w.ResolutionInfo != nil {
                result["resolution_info"] = w.ResolutionInfo
        }

        return result
}

func ExtractTXTFromBasicRecords(basic map[string]any) []string {
        if basic == nil {
                return nil
        }
        switch v := basic["TXT"].(type) {
        case []string:
                return v
        case []any:
                result := make([]string, 0, len(v))
                for _, item := range v {
                        if s, ok := item.(string); ok {
                                result = append(result, s)
                        }
                }
                return result
        }
        return nil
}
