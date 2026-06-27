// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package contentpkg

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

// EcosystemHandler serves the /ecosystem page describing the connected
// ecosystem: the published theory (www.intellectualresistance.com), the
// applied DNS intelligence implementation (DNS Tool), and the human-judgment
// consulting practice (organiccomputer.me).
type EcosystemHandler struct {
	Config       *config.Config
	TemplateData TemplateDataFunc
}

// NewEcosystemHandler constructs an EcosystemHandler.
func NewEcosystemHandler(cfg *config.Config, tdf TemplateDataFunc) *EcosystemHandler {
	return &EcosystemHandler{Config: cfg, TemplateData: tdf}
}

// Ecosystem renders the /ecosystem page.
func (h *EcosystemHandler) Ecosystem(c *gin.Context) {
	data := h.TemplateData(c, h.Config, "ecosystem")
	c.HTML(http.StatusOK, "ecosystem.html", data)
}
