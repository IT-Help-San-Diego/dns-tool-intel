// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
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
