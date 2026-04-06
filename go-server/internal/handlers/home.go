// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "net/http"
        "sync"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"

        "github.com/gin-gonic/gin"
)

type HomeHandler struct {
        Config *config.Config
        DB     *db.Database

        mu          sync.RWMutex
        icaeCache   *icae.ReportMetrics
        icuaeCache  *icuae.RuntimeMetrics
        cacheExpiry time.Time
}

const metricsCacheTTL = 60 * time.Second

func NewHomeHandler(cfg *config.Config, database *db.Database) *HomeHandler {
        return &HomeHandler{Config: cfg, DB: database}
}

func (h *HomeHandler) cachedMetrics(ctx context.Context) (*icae.ReportMetrics, *icuae.RuntimeMetrics) {
        if h.DB == nil {
                return nil, nil
        }

        h.mu.RLock()
        if time.Now().Before(h.cacheExpiry) {
                icaeM, icuaeM := h.icaeCache, h.icuaeCache
                h.mu.RUnlock()
                return icaeM, icuaeM
        }
        h.mu.RUnlock()

        icaeM := icae.LoadReportMetrics(ctx, h.DB.Queries)
        icuaeM := icuae.LoadRuntimeMetrics(ctx, h.DB.Queries)

        h.mu.Lock()
        h.icaeCache = icaeM
        h.icuaeCache = icuaeM
        h.cacheExpiry = time.Now().Add(metricsCacheTTL)
        h.mu.Unlock()

        return icaeM, icuaeM
}

func applyWelcomeOrFlash(c *gin.Context, data gin.H) {
        if welcome := c.Query("welcome"); welcome != "" {
                name := welcome
                if len(name) > 100 {
                        name = name[:100]
                }
                data["WelcomeName"] = name
                return
        }
        applyFlashFromQuery(c, data)
}

func applyFlashFromQuery(c *gin.Context, data gin.H) {
        flash := c.Query("flash")
        if flash == "" {
                return
        }
        cat := c.DefaultQuery("flash_cat", "warning")
        if cat != "success" && cat != "danger" {
                cat = "warning"
        }
        msg := flash
        if len(msg) > 200 {
                msg = msg[:200]
        }
        data["FlashMessages"] = []FlashMessage{{Category: cat, Message: msg}}
        if domain := c.Query("domain"); domain != "" {
                d := domain
                if len(d) > 253 {
                        d = d[:253]
                }
                data["PrefillDomain"] = d
        }
}

func (h *HomeHandler) Index(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "home")
        data["BaseURL"] = h.Config.BaseURL
        data["WaitDomain"] = c.Query("wait_domain")
        data["WaitSeconds"] = c.Query("wait_seconds")
        data["WaitReason"] = c.DefaultQuery("wait_reason", "anti_repeat")
        data["Changelog"] = GetRecentChangelog(6)
        data["DKIMExpand"] = c.Query("dkim") != ""

        icaeM, icuaeM := h.cachedMetrics(c.Request.Context())
        if icaeM != nil {
                data["ICAEMetrics"] = icaeM
        }
        if icuaeM != nil && icuaeM.HasData {
                data["ICuAEMetrics"] = icuaeM
        }

        applyWelcomeOrFlash(c, data)

        c.HTML(http.StatusOK, "index.html", data)
}

func (h *HomeHandler) ScanTopologyFragment(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "")
        c.Header("Cache-Control", "public, max-age=86400")
        c.HTML(http.StatusOK, "scan_topology", data)
}

func (h *HomeHandler) IconsJS(c *gin.Context) {
        data := NewTemplateData(c, h.Config, "")
        c.Header("Content-Type", "application/javascript; charset=utf-8")
        c.Header("Cache-Control", "public, max-age=86400")
        c.HTML(http.StatusOK, "_icons_js.html", data)
}
