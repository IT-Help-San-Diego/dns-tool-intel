// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type VideoHandler struct {
	Config *config.Config
}

func NewVideoHandler(cfg *config.Config) *VideoHandler {
	return &VideoHandler{Config: cfg}
}

func (h *VideoHandler) ForgottenDomain(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "approach",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "video_forgotten_domain.html", data)
}
