// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
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
        data := NewTemplateData(c, h.Config, "approach")
        data["YouTubeID"] = h.Config.YouTubeVideoIDs["forgotten-domain"]
        c.HTML(http.StatusOK, "video_forgotten_domain.html", data)
}

func (h *VideoHandler) Publications(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "publications")
        c.HTML(http.StatusOK, "publications.html", data)
}

func (h *VideoHandler) CaseStudyIndex(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "approach")
        c.HTML(http.StatusOK, "case_study_index.html", data)
}

func (h *VideoHandler) IntelligenceDMARC(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "approach")
        c.HTML(http.StatusOK, "case_study_intelligence_dmarc.html", data)
}
