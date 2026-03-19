// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type CommunicationStandardsHandler struct {
	Config *config.Config
}

func NewCommunicationStandardsHandler(cfg *config.Config) *CommunicationStandardsHandler {
	return &CommunicationStandardsHandler{Config: cfg}
}

func (h *CommunicationStandardsHandler) CommunicationStandards(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "communication-standards",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "communication_standards.html", data)
}
