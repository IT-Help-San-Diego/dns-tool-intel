// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type ManifestoHandler struct {
        Config *config.Config
}

func NewManifestoHandler(cfg *config.Config) *ManifestoHandler {
        return &ManifestoHandler{Config: cfg}
}

func (h *ManifestoHandler) Manifesto(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "manifesto")
        c.HTML(http.StatusOK, "manifesto.html", data)
}
