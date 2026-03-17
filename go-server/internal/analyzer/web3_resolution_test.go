// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "testing"
        "time"
)

func TestIsENSName_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"vitalik.eth", true},
                {"my-domain.eth", true},
                {"a.eth", true},
                {"example.com", false},
                {".eth", false},
                {"", false},
                {"VITALIK.ETH", true},
                {"-bad.eth", false},
                {"bad-.eth", false},
                {"hello.world.eth", false},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := IsENSName(tt.input); got != tt.want {
                                t.Errorf("IsENSName(%q) = %v, want %v", tt.input, got, tt.want)
                        }
                })
        }
}

func TestIsHNSName_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"mysite.hns", true},
                {"example.forever", true},
                {"test.nb", true},
                {"site.c", true},
                {"example.com", false},
                {"hello.eth", false},
                {"", false},
                {"singlepart", false},
        }
        for _, tt := range tests {
                t.Run(tt.input, func(t *testing.T) {
                        if got := IsHNSName(tt.input); got != tt.want {
                                t.Errorf("IsHNSName(%q) = %v, want %v", tt.input, got, tt.want)
                        }
                })
        }
}

func TestIsWeb3Input_B14(t *testing.T) {
        tests := []struct {
                input string
                want  bool
        }{
                {"vitalik.eth", true},
                {"mysite.hns", true},
                {"example.com", false},
                {"", false},
        }
        for _, tt := range tests {
                if got := IsWeb3Input(tt.input); got != tt.want {
                        t.Errorf("IsWeb3Input(%q) = %v, want %v", tt.input, got, tt.want)
                }
        }
}

func TestDefaultWeb3Resolution_B14(t *testing.T) {
        r := DefaultWeb3Resolution()
        if r["is_web3_input"] != false {
                t.Error("expected is_web3_input=false")
        }
        if r["input_domain"] != "" {
                t.Error("expected empty input_domain")
        }
}

func TestWeb3ResolutionResult_ToMap_B14(t *testing.T) {
        r := Web3ResolutionResult{
                IsWeb3Input:    true,
                InputDomain:    "vitalik.eth",
                ResolvedDomain: "vitalik.eth",
                ResolutionType: "ens",
                Gateway:        "eth.limo",
        }
        m := r.ToMap()
        if m["is_web3_input"] != true {
                t.Error("expected is_web3_input=true")
        }
        if m["input_domain"] != "vitalik.eth" {
                t.Error("expected input_domain=vitalik.eth")
        }
        if m["resolution_type"] != "ens" {
                t.Error("expected resolution_type=ens")
        }
}

func TestResolveWeb3Domain_NotWeb3_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        result := a.ResolveWeb3Domain(context.Background(), "example.com")
        if result.IsWeb3Input {
                t.Error("example.com should not be Web3 input")
        }
}

func TestResolveWeb3Domain_ENS_FieldsPopulated_B14(t *testing.T) {
        a := &Analyzer{DNS: NewMockDNSClient()}
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        result := a.resolveENS(ctx, "vitalik.eth")
        if !result.IsWeb3Input {
                t.Error("expected IsWeb3Input=true")
        }
        if result.ResolutionType != "ens" {
                t.Errorf("expected resolution_type=ens, got %s", result.ResolutionType)
        }
        if result.Gateway != "eth.limo" {
                t.Errorf("expected gateway=eth.limo, got %s", result.Gateway)
        }
}

func TestResolveWeb3Domain_HNS_NoRecords_B14(t *testing.T) {
        mock := NewMockDNSClient()
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if !result.IsWeb3Input {
                t.Error("expected IsWeb3Input=true")
        }
        if result.ResolutionType != "hns" {
                t.Errorf("expected resolution_type=hns, got %s", result.ResolutionType)
        }
        if result.Error == "" {
                t.Error("expected an error when no records found")
        }
}

func TestResolveWeb3Domain_HNS_WithRecords_B14(t *testing.T) {
        mock := NewMockDNSClient()
        mock.AddSpecificResolverResponse("A", "mysite.hns", hnsResolverDomain+":53", []string{"1.2.3.4"})
        a := &Analyzer{DNS: mock}

        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        result := a.resolveHNS(ctx, "mysite.hns")
        if result.Error != "" {
                t.Errorf("expected no error, got %s", result.Error)
        }
        if result.ResolvedDomain != "mysite.hns" {
                t.Errorf("expected resolved=mysite.hns, got %s", result.ResolvedDomain)
        }
        if result.Gateway != hnsResolverDomain {
                t.Errorf("expected gateway=%s, got %s", hnsResolverDomain, result.Gateway)
        }
}

func TestExtractDomainFromURL_B14(t *testing.T) {
        tests := []struct {
                input string
                want  string
        }{
                {"https://example.com/path", "example.com"},
                {"http://test.org:8080/", "test.org"},
                {"example.com/foo", "example.com"},
                {"https://sub.domain.io", "sub.domain.io"},
                {"", ""},
        }
        for _, tt := range tests {
                if got := extractDomainFromURL(tt.input); got != tt.want {
                        t.Errorf("extractDomainFromURL(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestResolveViaGatewayRedirect_SSRFBlock_B14(t *testing.T) {
        _, err := resolveViaGatewayRedirect(context.Background(), "127-0-0-1.eth", "evil.local")
        if err == nil {
                t.Error("expected SSRF block error")
        }
}
