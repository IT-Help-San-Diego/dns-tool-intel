// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type AboutHandler struct {
        Config *config.Config
}

func NewAboutHandler(cfg *config.Config) *AboutHandler {
        return &AboutHandler{Config: cfg}
}

func (h *AboutHandler) About(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "about")
        c.HTML(http.StatusOK, "about.html", data)
}
