// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type EDEHandler struct {
	Config *config.Config
}

func NewEDEHandler(cfg *config.Config) *EDEHandler {
	return &EDEHandler{Config: cfg}
}

func (h *EDEHandler) EDE(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	integrityData := loadIntegrityData()
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "ede",
		"IntegrityData":   integrityData,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "ede.html", data)
}
