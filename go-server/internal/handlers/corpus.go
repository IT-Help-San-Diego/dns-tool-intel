// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type CorpusHandler struct {
        Config *config.Config
}

func NewCorpusHandler(cfg *config.Config) *CorpusHandler {
        return &CorpusHandler{Config: cfg}
}

func (h *CorpusHandler) Corpus(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "corpus")
        c.HTML(http.StatusOK, "corpus.html", data)
}
