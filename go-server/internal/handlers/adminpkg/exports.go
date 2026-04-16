// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
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
