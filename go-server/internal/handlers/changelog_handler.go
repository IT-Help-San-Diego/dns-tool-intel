// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ChangelogHandler struct {
        Config *config.Config
}

func NewChangelogHandler(cfg *config.Config) *ChangelogHandler {
        return &ChangelogHandler{Config: cfg}
}

func (h *ChangelogHandler) Changelog(c *gin.Context) {
        all := GetChangelog()
        recentCut := 20
        if recentCut > len(all) {
                recentCut = len(all)
        }

        data := NewTemplateData(c, h.Config, "changelog")
        data["RecentChangelog"] = all[:recentCut]
        data["ArchiveChangelog"] = all[recentCut:]
        data["ArchiveCount"] = len(all) - recentCut
        data["TotalCount"] = len(all)
        data["LegacyChangelog"] = GetLegacyChangelog()
        c.HTML(http.StatusOK, "changelog.html", data)
}
