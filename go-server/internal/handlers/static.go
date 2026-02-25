// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "fmt"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "time"

        "github.com/gin-gonic/gin"
)

const (
        headerContentType  = "Content-Type"
        headerCacheControl = "Cache-Control"
        cachePublicDay     = "public, max-age=86400"


	mapKeyMonthly = "monthly"
	mapKeyWeekly = "weekly"
)

type StaticHandler struct {
        StaticDir  string
        AppVersion string
        BaseURL    string
}

func NewStaticHandler(staticDir, appVersion, baseURL string) *StaticHandler {
        return &StaticHandler{StaticDir: staticDir, AppVersion: appVersion, BaseURL: baseURL}
}

func (h *StaticHandler) SecurityTxt(c *gin.Context) {
        c.Header(headerContentType, "text/plain; charset=utf-8")
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, ".well-known", "security.txt"))
}

func (h *StaticHandler) RobotsTxt(c *gin.Context) {
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, "robots.txt"))
}

func (h *StaticHandler) LLMsTxt(c *gin.Context) {
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, "llms.txt"))
}

func (h *StaticHandler) LLMsFullTxt(c *gin.Context) {
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, "llms-full.txt"))
}

func (h *StaticHandler) ManifestJSON(c *gin.Context) {
        c.Header(headerContentType, "application/manifest+json")
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, "manifest.json"))
}

func (h *StaticHandler) ServiceWorker(c *gin.Context) {
        swPath := filepath.Join(h.StaticDir, "sw.js")
        data, err := os.ReadFile(swPath)
        if err != nil {
                c.Status(http.StatusNotFound)
                return
        }
        body := strings.Replace(string(data), "SW_VERSION_PLACEHOLDER", h.AppVersion, 1)
        c.Header(headerContentType, "application/javascript")
        c.Header(headerCacheControl, "no-cache, no-store, must-revalidate")
        c.Header("Service-Worker-Allowed", "/")
        c.Data(http.StatusOK, "application/javascript", []byte(body))
}

func (h *StaticHandler) SitemapXML(c *gin.Context) {
        today := time.Now().Format("2006-01-02")

        pages := []struct {
                Loc        string
                Changefreq string
                Priority   string
        }{
                {h.BaseURL + "/", mapKeyWeekly, "1.0"},
                {h.BaseURL + "/investigate", mapKeyWeekly, "0.7"},
                {h.BaseURL + "/email-header", mapKeyWeekly, "0.7"},
                {h.BaseURL + "/toolkit", mapKeyWeekly, "0.7"},
                {h.BaseURL + "/sources", mapKeyMonthly, "0.6"},
                {h.BaseURL + "/history", "daily", "0.6"},
                {h.BaseURL + "/stats", "daily", "0.5"},
                {h.BaseURL + "/approach", mapKeyMonthly, "0.6"},
                {h.BaseURL + "/roadmap", mapKeyWeekly, "0.5"},
                {h.BaseURL + "/architecture", mapKeyMonthly, "0.5"},
                {h.BaseURL + "/security-policy", mapKeyMonthly, "0.4"},
                {h.BaseURL + "/changelog", mapKeyMonthly, "0.3"},
        }

        xml := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
        xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n"
        for _, page := range pages {
                xml += "  <url>\n"
                xml += fmt.Sprintf("    <loc>%s</loc>\n", page.Loc)
                xml += fmt.Sprintf("    <lastmod>%s</lastmod>\n", today)
                xml += fmt.Sprintf("    <changefreq>%s</changefreq>\n", page.Changefreq)
                xml += fmt.Sprintf("    <priority>%s</priority>\n", page.Priority)
                xml += "  </url>\n"
        }
        xml += "</urlset>\n"

        c.Header(headerCacheControl, "public, max-age=3600")
        c.Data(http.StatusOK, "application/xml", []byte(xml))
}
