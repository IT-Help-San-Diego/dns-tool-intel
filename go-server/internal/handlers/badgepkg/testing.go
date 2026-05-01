// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// testing.go is the functions/methods half of the sub-package test seam.
// Any unexported function or method in this sub-package that is referenced by
// a test in a sibling package (typically the parent `handlers` package,
// including its build-tagged suites such as `//go:build scientific` or
// `//go:build coverage`) MUST be re-exported here as a thin wrapper.
//
// Constant and package-level variable wrappers belong in the paired
// exports.go file.
//
// See replit.md § "Test Build Tags (CRITICAL)" → "Sub-Package Test Seam
// Pattern" for the full rule and the audit checklist that must be run before
// splitting code into a new sub-package.
package badgepkg

import (
	"time"

	"github.com/gin-gonic/gin"
)

func (h *BadgeHandler) ResolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, ok bool) {
	return h.resolveAnalysis(c)
}
