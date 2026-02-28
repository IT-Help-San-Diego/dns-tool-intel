// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"net/http"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type TopologyHandler struct {
	Config *config.Config
}

func NewTopologyHandler(cfg *config.Config) *TopologyHandler {
	return &TopologyHandler{Config: cfg}
}

func (h *TopologyHandler) Topology(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"ActivePage":      "topology",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "topology.html", data)
}
