// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// Default-suite test bootstrap. Live external subdomain tooling (subfinder,
// amass, hackertarget) shells out to real binaries and the network, taking up
// to 45s per call and intermittently overrunning the analyzer package's
// quality-gate timeout. Neutralize it for every non-integration test run so the
// default suite is deterministic and network-free. Live behavior is exercised
// only by integration-tagged tests (golden_rules_integration_test.go,
// live_integration_test.go), which exclude this file via the !integration tag.

//go:build !integration

package analyzer

import (
        "context"
        "os"
        "testing"
)

func TestMain(m *testing.M) {
        prev := externalToolsFn
        externalToolsFn = func(context.Context, string) []string { return nil }
        code := m.Run()
        externalToolsFn = prev
        os.Exit(code)
}
