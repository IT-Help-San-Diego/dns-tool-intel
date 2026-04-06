// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type PrivacyHandler struct {
        Config *config.Config
}

func NewPrivacyHandler(cfg *config.Config) *PrivacyHandler {
        return &PrivacyHandler{Config: cfg}
}

func (h *PrivacyHandler) Privacy(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "privacy")
        c.HTML(http.StatusOK, "privacy.html", data)
}
