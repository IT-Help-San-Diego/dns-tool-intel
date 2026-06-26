// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package dnsclient

import (
        "context"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "syscall"
        "time"
)

const (
        headerUserAgent = "User-Agent"
        httpMethodGet   = "GET"
)

type SafeHTTPClient struct {
        client    *http.Client
        userAgent string
        SkipSSRF  bool
}

func NewSafeHTTPClient() *SafeHTTPClient {
        return NewSafeHTTPClientWithTimeout(10 * time.Second)
}

func NewSafeHTTPClientWithTimeout(timeout time.Duration) *SafeHTTPClient {
        s := &SafeHTTPClient{userAgent: UserAgent}
        dialer := &net.Dialer{
                Timeout:   10 * time.Second,
                KeepAlive: 30 * time.Second,
                Control:   s.ssrfDialControl,
        }
        s.client = &http.Client{
                Timeout: timeout,
                Transport: &http.Transport{
                        MaxIdleConns:        20,
                        IdleConnTimeout:     30 * time.Second,
                        DisableKeepAlives:   false,
                        MaxIdleConnsPerHost: 5,
                        DialContext:         dialer.DialContext,
                        ForceAttemptHTTP2:   true,
                },
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        if len(via) >= 5 {
                                return fmt.Errorf("too many redirects")
                        }
                        if !ValidateURLTarget(req.URL.String()) {
                                return fmt.Errorf("SSRF protection: redirect target resolves to private IP")
                        }
                        return nil
                },
        }
        return s
}

func NewRDAPHTTPClient() *SafeHTTPClient {
        s := &SafeHTTPClient{userAgent: UserAgent}
        dialer := &net.Dialer{
                Timeout:   10 * time.Second,
                KeepAlive: 30 * time.Second,
                Control:   s.ssrfDialControl,
        }
        s.client = &http.Client{
                Timeout: 25 * time.Second,
                Transport: &http.Transport{
                        MaxIdleConns:          10,
                        IdleConnTimeout:       60 * time.Second,
                        DisableKeepAlives:     true,
                        MaxIdleConnsPerHost:   2,
                        ResponseHeaderTimeout: 20 * time.Second,
                        DialContext:           dialer.DialContext,
                        ForceAttemptHTTP2:     true,
                },
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        if len(via) >= 5 {
                                return fmt.Errorf("too many redirects")
                        }
                        return nil
                },
        }
        return s
}

// ssrfDialControl is the dial-time SSRF guard. net.Dialer invokes Control after
// DNS resolution with the CONCRETE IP it is about to connect to (per attempt,
// including Happy-Eyeballs candidates), so re-checking the IP here closes the
// TOCTOU / DNS-rebinding window left by the pre-flight ValidateURLTarget check:
// a hostname that resolved to a public IP during validation but flips to a
// private/reserved IP at connect time is refused at dial. SkipSSRF clients
// (intentional internal diagnostic probes, e.g. CT-log fetches) bypass the
// guard so their probing behavior is preserved unchanged.
func (s *SafeHTTPClient) ssrfDialControl(_, address string, _ syscall.RawConn) error {
        if s.SkipSSRF {
                return nil
        }
        host, _, err := net.SplitHostPort(address)
        if err != nil {
                return fmt.Errorf("SSRF protection: cannot parse dial address %q: %w", address, err)
        }
        if IsPrivateIP(host) {
                return fmt.Errorf("SSRF protection: refusing to connect to private/reserved IP %s", host)
        }
        return nil
}

var rdapAllowedHosts = map[string]bool{
        "rdap.verisign.com":               true,
        "rdap.publicinterestregistry.net": true,
        "rdap.nic.io":                     true,
        "rdap.nic.google":                 true,
        "rdap.nominet.uk":                 true,
        "rdap.eu":                         true,
        "rdap.sidn.nl":                    true,
        "rdap.auda.org.au":                true,
        "rdap.centralnic.com":             true,
        "rdap.nic.co":                     true,
        "rdap.nic.me":                     true,
        "rdap.nic.ai":                     true,
        "rdap.afilias.net":                true,
        "rdap.nic.biz":                    true,
        "rdap.nic.mobi":                   true,
        "rdap.nic.pro":                    true,
        "rdap.nic.top":                    true,
        "rdap.org":                        true,
}

func IsRDAPAllowedHost(hostname string) bool {
        return rdapAllowedHosts[hostname]
}

func (s *SafeHTTPClient) GetDirect(ctx context.Context, rawURL string) (*http.Response, error) {
        parsed, err := url.Parse(rawURL)
        if err != nil {
                return nil, fmt.Errorf("invalid RDAP URL: %w", err)
        }
        if parsed.Scheme != "https" {
                return nil, fmt.Errorf("RDAP requires HTTPS, got %q", parsed.Scheme)
        }
        hostname := parsed.Hostname()
        if !rdapAllowedHosts[hostname] {
                if !ValidateURLTarget(rawURL) {
                        return nil, fmt.Errorf("RDAP host %q not in allowlist and resolves to private IP", hostname)
                }
        }

        req, err := http.NewRequestWithContext(ctx, httpMethodGet, rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set(headerUserAgent, s.userAgent)
        req.Header.Set("Accept", "application/rdap+json, application/json")

        return s.client.Do(req)
}

func (s *SafeHTTPClient) Get(ctx context.Context, rawURL string) (*http.Response, error) {
        if !s.SkipSSRF && !ValidateURLTarget(rawURL) {
                return nil, fmt.Errorf("SSRF protection: URL target resolves to private/reserved IP")
        }

        req, err := http.NewRequestWithContext(ctx, httpMethodGet, rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set(headerUserAgent, s.userAgent)

        return s.client.Do(req)
}

func (s *SafeHTTPClient) GetWithHeaders(ctx context.Context, rawURL string, headers map[string]string) (*http.Response, error) {
        if !s.SkipSSRF && !ValidateURLTarget(rawURL) {
                return nil, fmt.Errorf("SSRF protection: URL target resolves to private/reserved IP range")
        }

        req, err := http.NewRequestWithContext(ctx, httpMethodGet, rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set(headerUserAgent, s.userAgent)
        for k, v := range headers {
                req.Header.Set(k, v)
        }

        return s.client.Do(req)
}

func (s *SafeHTTPClient) HeadNoRedirect(ctx context.Context, rawURL string) (*http.Response, error) {
        if !s.SkipSSRF && !ValidateURLTarget(rawURL) {
                return nil, fmt.Errorf("SSRF protection: URL target resolves to private/reserved IP")
        }

        noRedirectClient := *s.client
        noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set(headerUserAgent, s.userAgent)

        return noRedirectClient.Do(req)
}

func safeClose(c io.Closer, label string) {
        if err := c.Close(); err != nil {
                slog.Debug("close error", "resource", label, "error", err)
        }
}

func (s *SafeHTTPClient) ReadBody(resp *http.Response, maxBytes int64) ([]byte, error) {
        defer safeClose(resp.Body, "http-read-body")
        return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func IsPrivateIP(ipStr string) bool {
        ip := net.ParseIP(ipStr)
        if ip == nil {
                return false
        }

        if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
                ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
                return true
        }

        if ip4 := ip.To4(); ip4 != nil {
                if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
                        return true
                }
                if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
                        return true
                }
                if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
                        return true
                }
        }

        return false
}

func ValidateURLTarget(rawURL string) bool {
        parsed, err := url.Parse(rawURL)
        if err != nil {
                return false
        }
        hostname := parsed.Hostname()
        if hostname == "" {
                return false
        }

        addrs, err := net.LookupHost(hostname)
        if err != nil {
                return true
        }
        if len(addrs) == 0 {
                return true
        }

        for _, addr := range addrs {
                if IsPrivateIP(addr) {
                        return false
                }
        }
        return true
}
