// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type BlackSiteHandler struct {
	Config *config.Config
}

func NewBlackSiteHandler(cfg *config.Config) *BlackSiteHandler {
	return &BlackSiteHandler{Config: cfg}
}

func (h *BlackSiteHandler) BlackSite(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "black-site",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "black_site.html", data)
}
