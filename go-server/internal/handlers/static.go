// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "bytes"
        "fmt"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "time"

        staticembed "dnstool/go-server/static"

        "github.com/gin-gonic/gin"
)

const (
        headerContentType  = "Content-Type"
        headerCacheControl = "Cache-Control"
        cachePublicDay     = "public, max-age=86400"

        mapKeyMonthly = "monthly"
        mapKeyWeekly  = "weekly"

        sitemapPriorityHigh   = "0.7"
        sitemapPriorityMedium = "0.6"
        sitemapPriorityLow    = "0.5"
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

func (h *StaticHandler) BIMILogoSVG(c *gin.Context) {
        c.Header(headerContentType, "image/svg+xml")
        c.Header(headerCacheControl, cachePublicDay)
        c.File(filepath.Join(h.StaticDir, "bimi-logo.svg"))
}

// servePDFEmbedded serves a corpus PDF from the binary-embedded FS with the
// supplied Cache-Control header. Bytes are read from staticembed.DocsPDFs so
// the response can never be truncated by a deployment-filesystem race (see
// embed.go header comment for the regression that motivated this).
// http.ServeContent provides Range / If-Modified-Since handling required by
// browser PDF viewers (Chrome's viewer relies on range requests).
func (h *StaticHandler) servePDFEmbedded(c *gin.Context, filename, cacheControl string) {
        data, err := staticembed.DocsPDFs.ReadFile("docs/" + filename)
        if err != nil {
                c.Status(http.StatusNotFound)
                return
        }
        c.Header(headerContentType, "application/pdf")
        c.Header(headerCacheControl, cacheControl)
        c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))
        http.ServeContent(c.Writer, c.Request, filename, time.Time{}, bytes.NewReader(data))
}

func (h *StaticHandler) servePDF(c *gin.Context, filename string) {
        h.servePDFEmbedded(c, filename, cachePublicDay)
}

// versionedPDFAllowlist maps the canonical PDF filenames the corpus page may
// request via the /docs/v:appver/:filename versioned route. Filenames not in
// this set return 404. This narrow allowlist prevents arbitrary path access
// and keeps the route explicit for audit.
var versionedPDFAllowlist = map[string]bool{
        "dns-tool-methodology.pdf":      true,
        "philosophical-foundations.pdf": true,
        "founders-manifesto.pdf":        true,
        "communication-standards.pdf":   true,
        "owl-semaphore-system.pdf":      true,
        "owl-1-normative.pdf":           true,
        "owl-2-non-normative.pdf":       true,
        "owl-3-critical.pdf":            true,
        "owl-4-metacognitive.pdf":       true,
        "the-real-bot-manifesto.pdf":    true,
}

// VersionedPDF serves a PDF under a version-namespaced URL with immutable
// cache headers. Path: /docs/v:appver/:filename. The :appver segment is
// informational only — content addressing is by filename — but it gives the
// edge cache a fresh key per release, sidestepping any prior cache poisoning
// of legacy /docs/<file>.pdf entries.
func (h *StaticHandler) VersionedPDF(c *gin.Context) {
        filename := c.Param("filename")
        if !versionedPDFAllowlist[filename] {
                c.Status(http.StatusNotFound)
                return
        }
        h.servePDFEmbedded(c, filename, "public, max-age=31536000, immutable")
}

func (h *StaticHandler) MethodologyPDF(c *gin.Context) {
        h.servePDF(c, "dns-tool-methodology.pdf")
}

func (h *StaticHandler) FoundationsPDF(c *gin.Context) {
        h.servePDF(c, "philosophical-foundations.pdf")
}

func (h *StaticHandler) ManifestoPDF(c *gin.Context) {
        h.servePDF(c, "founders-manifesto.pdf")
}

func (h *StaticHandler) CommStandardsPDF(c *gin.Context) {
        h.servePDF(c, "communication-standards.pdf")
}

func (h *StaticHandler) OwlSemaphoreSystemPDF(c *gin.Context) {
        h.servePDF(c, "owl-semaphore-system.pdf")
}

func (h *StaticHandler) Owl1NormativePDF(c *gin.Context) {
        h.servePDF(c, "owl-1-normative.pdf")
}

func (h *StaticHandler) Owl2NonNormativePDF(c *gin.Context) {
        h.servePDF(c, "owl-2-non-normative.pdf")
}

func (h *StaticHandler) Owl3CriticalPDF(c *gin.Context) {
        h.servePDF(c, "owl-3-critical.pdf")
}

func (h *StaticHandler) Owl4MetacognitivePDF(c *gin.Context) {
        h.servePDF(c, "owl-4-metacognitive.pdf")
}

func (h *StaticHandler) RealBotManifestoPDF(c *gin.Context) {
        h.servePDF(c, "the-real-bot-manifesto.pdf")
}

func (h *StaticHandler) SitemapXML(c *gin.Context) {
        today := time.Now().Format("2006-01-02")

        pages := []struct {
                Loc        string
                Changefreq string
                Priority   string
        }{
                {h.BaseURL + "/", mapKeyWeekly, "1.0"},
                {h.BaseURL + "/investigate", mapKeyWeekly, sitemapPriorityHigh},
                {h.BaseURL + "/email-header", mapKeyWeekly, sitemapPriorityHigh},
                {h.BaseURL + "/toolkit", mapKeyWeekly, sitemapPriorityHigh},
                {h.BaseURL + "/about", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/sources", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/history", "daily", sitemapPriorityMedium},
                {h.BaseURL + "/stats", "daily", sitemapPriorityLow},
                {h.BaseURL + "/approach", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/confidence", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/roadmap", mapKeyWeekly, sitemapPriorityLow},
                {h.BaseURL + "/architecture", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/manifesto", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/communication-standards", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/ttl-tuner", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/ede", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/roe", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/contact", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/privacy", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/security-policy", mapKeyMonthly, "0.4"},
                {h.BaseURL + "/changelog", mapKeyMonthly, "0.3"},
                {h.BaseURL + "/video/forgotten-domain", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/reference-library", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/corpus", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/publications", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/case-study/", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/case-study/intelligence-dmarc", mapKeyMonthly, sitemapPriorityMedium},
                {h.BaseURL + "/owl-semaphore", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/cite", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/color-science", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/confidence/audit-log", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/remediation", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/faq/subdomains", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/topology", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/black-site", mapKeyMonthly, sitemapPriorityLow},
                {h.BaseURL + "/agent/plugin", mapKeyMonthly, sitemapPriorityLow},
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
