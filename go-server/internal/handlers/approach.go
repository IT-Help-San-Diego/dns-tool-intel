// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
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
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "approach",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "approach.html", data)
}
