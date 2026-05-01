// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// testing.go is the test-only constructors / method wrappers half of the
// sub-package test seam. Any unexported method or test-only factory in this
// sub-package that is referenced by a test in a sibling package (typically
// the parent `handlers` package, including its build-tagged suites) MUST be
// re-exported here as a thin wrapper. Constant/variable/function wrappers
// belong in the paired exports.go file.
//
// See replit.md § "Test Build Tags (CRITICAL)" → "Sub-Package Test Seam
// Pattern" for the full rule and the audit checklist that must be run before
// splitting code into a new sub-package.
package agentpkg

import (
	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
)

// NewAgentHandlerWithStore is a test-helper constructor that allows callers
// to inject a LookupStore directly without supplying a full analyzer/config/tdf.
func NewAgentHandlerWithStore(store LookupStore) *AgentHandler {
	return &AgentHandler{
		Config:      &config.Config{},
		Analyzer:    (*analyzer.Analyzer)(nil),
		lookupStore: store,
	}
}
