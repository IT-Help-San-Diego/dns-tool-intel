// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package badgepkg

import (
        "time"

        "github.com/gin-gonic/gin"
)

func (h *BadgeHandler) ResolveAnalysis(c *gin.Context) (domain string, results map[string]any, scanTime time.Time, scanID int32, postureHash string, ok bool) {
        return h.resolveAnalysis(c)
}
