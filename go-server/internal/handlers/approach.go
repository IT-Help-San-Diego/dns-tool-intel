// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ApproachHandler struct {
        Config *config.Config
}

func NewApproachHandler(cfg *config.Config) *ApproachHandler {
        return &ApproachHandler{Config: cfg}
}

func (h *ApproachHandler) Approach(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "approach")
        data["YouTubeID"] = h.Config.YouTubeVideoIDs["forgotten-domain"]
        c.HTML(http.StatusOK, "approach.html", data)
}
