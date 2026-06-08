// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Golden-rule integration tests — live-network behavioral guarantees that query
// real DNS infrastructure and external discovery tooling.
// Run manually: cd go-server && go test -tags=integration -run TestGoldenRule ./internal/analyzer/ -v -timeout 120s
// NOT part of the default test suite and never run in the pre-ship quality gate.

//go:build integration

package analyzer

import (
        "context"
        "strings"
        "testing"
        "time"
)

func TestGoldenRuleSubdomainDiscoveryUnder60s(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping network-dependent test in short mode")
        }

        a := New(WithInitialIANAFetch(false))
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()

        start := time.Now()
        result := a.DiscoverSubdomains(ctx, "it-help.tech")
        elapsed := time.Since(start)

        if elapsed >= 60*time.Second {
                t.Fatalf("subdomain discovery took %s — must complete under 60 seconds", elapsed)
        }

        status, _ := result["status"].(string)
        if status != "success" {
                t.Errorf("subdomain discovery status must be 'success', got %q", status)
        }

        subs, _ := result["subdomains"].([]map[string]any)
        if len(subs) == 0 {
                t.Fatal("subdomain discovery must find at least one subdomain for it-help.tech")
        }

        for _, sd := range subs {
                name, _ := sd["name"].(string)
                if name == "" {
                        t.Error("subdomain entry has empty or missing name")
                }
                if !strings.HasSuffix(name, ".it-help.tech") {
                        t.Errorf("subdomain %q does not belong to it-help.tech", name)
                }
        }

        t.Logf("subdomain discovery completed in %s — found %d subdomains", elapsed, len(subs))
}
