// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// exports.go is the constants/variables/functions half of the sub-package
// test seam. Any unexported identifier in this sub-package that is referenced
// by a test in a sibling package (typically the parent `handlers` package,
// including its build-tagged suites) MUST be re-exported here (or in the
// paired testing.go for test-only constructors and method wrappers).
//
// See replit.md § "Test Build Tags (CRITICAL)" → "Sub-Package Test Seam
// Pattern" for the full rule and the audit checklist that must be run before
// splitting code into a new sub-package.
package agentpkg

// ExtractDNSSECStatus is the exported test alias for extractDNSSECStatus.
func ExtractDNSSECStatus(results map[string]any) string {
	return extractDNSSECStatus(results)
}

// ExtractPosture is the exported test alias for extractPosture.
func ExtractPosture(results map[string]any) (int, string, string) {
	return extractPosture(results)
}

// SafeInternalURL is the exported test alias for safeInternalURL.
func SafeInternalURL(base, path string, params map[string]string) string {
	return safeInternalURL(base, path, params)
}
