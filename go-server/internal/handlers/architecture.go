// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ArchitectureHandler struct {
        Config *config.Config
}

func NewArchitectureHandler(cfg *config.Config) *ArchitectureHandler {
        return &ArchitectureHandler{Config: cfg}
}

func (h *ArchitectureHandler) Architecture(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "architecture")
        c.HTML(http.StatusOK, "architecture.html", data)
}
