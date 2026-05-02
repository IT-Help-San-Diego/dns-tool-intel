// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// exports.go is the sub-package test seam for adminpkg. Any unexported
// identifier (constant, variable, function) in this sub-package that is
// referenced by a test in a sibling package — typically the parent
// `handlers` package, including its build-tagged suites such as
// `//go:build scientific` or `//go:build coverage` — MUST be re-exported
// here as a thin wrapper. If/when adminpkg also needs a paired testing.go
// for unexported method wrappers or test-only constructors, follow the same
// split convention used in authpkg and agentpkg.
//
// See replit.md § "Test Build Tags (CRITICAL)" → "Sub-Package Test Seam
// Pattern" for the full rule and the audit checklist that must be run before
// splitting code into a new sub-package.
package adminpkg

// FindPEMHeader is the exported test alias for findPEMHeader.
func FindPEMHeader(tokens []string) (string, int, bool) {
	return findPEMHeader(tokens)
}

// FindPEMFooter is the exported test alias for findPEMFooter.
func FindPEMFooter(tokens []string, start int) (string, []string) {
	return findPEMFooter(tokens, start)
}

// NormalizePEM is the exported test alias for normalizePEM.
func NormalizePEM(s string) string {
	return normalizePEM(s)
}

// OpsTaskList is the exported test alias for opsTaskList.
func OpsTaskList() []opsTask {
	return opsTaskList()
}

// OpsWhitelist exposes the unexported opsWhitelist map for tests.
var OpsWhitelist = opsWhitelist
