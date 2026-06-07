// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Default-suite test bootstrap. Several analyzer paths reach the live network by
// design and intermittently overran the package's quality-gate timeout when run
// on a networked host:
//   - external subdomain tooling (subfinder/amass/hackertarget) shells out to
//     real binaries and the network, up to 45s per call (externalToolsFn).
//   - reverse-DNS hosting detection calls net.LookupAddr, which takes no context
//     and is therefore unbounded, on every real IP fed through the orchestrator,
//     commands and infrastructure tests (lookupAddrFn).
// Neutralize both for every non-integration test run so the default suite is
// deterministic and network-free. Live behavior is exercised only by
// integration-tagged tests (golden_rules_integration_test.go,
// live_integration_test.go), which exclude this file via the !integration tag.

//go:build !integration

package analyzer

import (
        "context"
        "net"
        "os"
        "testing"
)

func TestMain(m *testing.M) {
        prevExternalTools := externalToolsFn
        prevLookupAddr := lookupAddrFn
        externalToolsFn = func(context.Context, string) []string { return nil }
        lookupAddrFn = func(string) ([]string, error) { return nil, &net.DNSError{Err: "test stub: live reverse DNS disabled", IsNotFound: true} }
        code := m.Run()
        externalToolsFn = prevExternalTools
        lookupAddrFn = prevLookupAddr
        os.Exit(code)
}
