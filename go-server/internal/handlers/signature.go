// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "net/http"

        "dnstool/go-server/internal/config"

        "github.com/gin-gonic/gin"
)

type SignatureHandler struct {
        Config *config.Config
}

func NewSignatureHandler(cfg *config.Config) *SignatureHandler {
        return &SignatureHandler{Config: cfg}
}

func (h *SignatureHandler) SignaturePage(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")

        mode := c.DefaultQuery("mode", "page")

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "BetaPages":       h.Config.BetaPages,
                "CspNonce":        nonce,
                "ActivePage":      "signature",
                "RawMode":         mode == "raw",
        }
        mergeAuthData(c, h.Config, data)

        if mode == "raw" {
                c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https:; font-src 'self'; base-uri 'none'; form-action 'none'")
                c.HTML(http.StatusOK, "signature_raw.html", data)
                return
        }

        c.HTML(http.StatusOK, "signature.html", data)
}
