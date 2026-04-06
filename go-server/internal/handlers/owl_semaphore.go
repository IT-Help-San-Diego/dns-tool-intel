// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type OwlSemaphoreHandler struct {
        Config *config.Config
}

func NewOwlSemaphoreHandler(cfg *config.Config) *OwlSemaphoreHandler {
        return &OwlSemaphoreHandler{Config: cfg}
}

func (h *OwlSemaphoreHandler) OwlSemaphore(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "owl-semaphore")
        c.HTML(http.StatusOK, "owl_semaphore.html", data)
}

func (h *OwlSemaphoreHandler) OwlLayers(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "owl-layers")
        c.HTML(http.StatusOK, "owl_layers.html", data)
}
