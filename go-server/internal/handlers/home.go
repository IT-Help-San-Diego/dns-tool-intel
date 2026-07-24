// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "log/slog"
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

        mu          sync.Mutex
        icaeCache   *icae.ReportMetrics
        icuaeCache  *icuae.RuntimeMetrics
        cacheExpiry time.Time
        loaded      bool
        refreshing  bool
}

const (
        metricsCacheTTL          = 60 * time.Second
        metricsRefreshTimeout    = 5 * time.Second
        metricsColdLoadTimeout   = 3 * time.Second
        metricsFailureRetryDelay = 5 * time.Second
)

// Injection seams so the stale-while-revalidate cache logic can be tested
// without a live database. Production always uses the real loaders.
var (
        loadReportMetricsFn  = icae.LoadReportMetrics
        loadRuntimeMetricsFn = icuae.LoadRuntimeMetrics
)

func NewHomeHandler(cfg *config.Config, database *db.Database) *HomeHandler {
        return &HomeHandler{Config: cfg, DB: database}
}

// cachedMetrics returns homepage metrics without blocking on the database
// once a first load has succeeded. Past the TTL, stale values are served
// immediately while a single background goroutine refreshes them
// (stale-while-revalidate). Only a cold cache performs a bounded
// synchronous load. This keeps "/" fast under database saturation — the
// deployment health check probes "/", so a slow homepage reads as an
// outage.
func (h *HomeHandler) cachedMetrics() (*icae.ReportMetrics, *icuae.RuntimeMetrics) {
        if h.DB == nil {
                return nil, nil
        }

        h.mu.Lock()
        icaeM, icuaeM := h.icaeCache, h.icuaeCache
        cold := !h.loaded
        doRefresh := !h.refreshing && !time.Now().Before(h.cacheExpiry)
        if doRefresh {
                h.refreshing = true
        }
        h.mu.Unlock()

        if !doRefresh {
                return icaeM, icuaeM
        }
        if cold {
                return h.refreshMetrics(metricsColdLoadTimeout)
        }
        go h.refreshMetrics(metricsRefreshTimeout)
        return icaeM, icuaeM
}

// refreshMetrics loads metrics on a context detached from any request so a
// client disconnect cannot cancel the shared cache refresh. On failure the
// last good values are kept and the next retry is delayed briefly instead
// of caching nil for a full TTL.
func (h *HomeHandler) refreshMetrics(timeout time.Duration) (*icae.ReportMetrics, *icuae.RuntimeMetrics) {
        // Insurance against a loader panic: recover so a background refresh
        // goroutine cannot crash the process, and clear the refreshing flag
        // so the cache can refresh again. A recovered panic is treated as a
        // failed refresh (stale values kept, short retry delay).
        completed := false
        defer func() {
                if r := recover(); r != nil {
                        slog.Error("Homepage metrics refresh panicked; serving stale values", "panic", r)
                }
                if !completed {
                        h.mu.Lock()
                        h.refreshing = false
                        h.cacheExpiry = time.Now().Add(metricsFailureRetryDelay)
                        h.mu.Unlock()
                }
        }()

        ctx, cancel := context.WithTimeout(context.Background(), timeout)
        defer cancel()

        icaeM := loadReportMetricsFn(ctx, h.DB.Queries)
        icuaeM := loadRuntimeMetricsFn(ctx, h.DB.Queries)

        h.mu.Lock()
        defer h.mu.Unlock()
        completed = true
        h.refreshing = false
        if icaeM != nil {
                h.icaeCache = icaeM
        }
        if icuaeM != nil {
                h.icuaeCache = icuaeM
        }
        if icaeM != nil || icuaeM != nil {
                h.loaded = true
                h.cacheExpiry = time.Now().Add(metricsCacheTTL)
        } else {
                h.cacheExpiry = time.Now().Add(metricsFailureRetryDelay)
        }
        return h.icaeCache, h.icuaeCache
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

        icaeM, icuaeM := h.cachedMetrics()
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
