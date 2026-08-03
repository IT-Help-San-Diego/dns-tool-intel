// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"io"
	"net/http"
	"strings"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"

	"github.com/gin-gonic/gin"
)

// CloudHistoryHandler renders the PUBLIC instrument's history page INSIDE the
// local build as a same-origin top-level document, so the Local⇄Cloud flipper
// swaps between two local pages (/history = this machine, /cloud/history = the
// public instrument) without opening a new tab or fetching a database over the
// internet.
//
// Why a server-side proxy and not an iframe: both surfaces send
// `frame-ancestors 'none'`, `X-Frame-Options: DENY`, AND `frame-src 'none'`
// (clickjacking armor we do NOT weaken), so ANY frame — even a srcdoc frame —
// is refused. A same-origin top-level page hits no frame policy at all: the
// local app serves the website's HTML as the main document. It never
// re-implements the view — the content IS the website's own HTML, fetched on
// demand. Local scans stay local; this handler only ever reads the public
// instrument, and only when the user flips to Cloud.
type CloudHistoryHandler struct {
	DB     *db.Database
	Config *config.Config
	client *http.Client
}

func NewCloudHistoryHandler(database *db.Database, cfg *config.Config) *CloudHistoryHandler {
	return &CloudHistoryHandler{
		DB:     database,
		Config: cfg,
		client: &http.Client{Timeout: 12 * time.Second},
	}
}

// CloudHistory serves GET /cloud/history on a local build. On a cloud
// deployment it 404s — the cloud has no "local counterpart" to embed.
func (h *CloudHistoryHandler) CloudHistory(c *gin.Context) {
	if h.Config.IsCloudDeployment {
		c.Status(http.StatusNotFound)
		return
	}
	target := strings.TrimRight(h.Config.CanonicalBaseURL, "/") + "/history"
	if qs := c.Request.URL.RawQuery; qs != "" {
		target += "?" + qs
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		h.renderError(c, "Could not build request to the public instrument")
		return
	}
	// Identify honestly as the local instrument fetching its cloud counterpart.
	req.Header.Set("User-Agent", "DNS-Tool-Local/CloudFlipper")
	req.Header.Set("Accept", "text/html")

	resp, err := h.client.Do(req)
	if err != nil {
		h.renderError(c, "The public instrument is unreachable from here")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.renderError(c, "The public instrument returned an unexpected status")
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		h.renderError(c, "Could not read the public instrument's history")
		return
	}
	html := string(body)

	// The proxied document carries the CLOUD's CSP nonces; the local app stamps
	// its OWN CSP on the response, so those nonces would be blocked — and the
	// cloud page's critical-CSS lives in inline <style nonce> blocks (dark theme,
	// table layout), so blocking them renders the embedded view unstyled. Strip
	// the nonce attribute from inline <style> tags so the local CSP (style-src
	// 'self' + the document's own inline styles, which are already in the markup)
	// lets them apply. This is presentational CSS only — no script is touched, so
	// the cloud page's interactive JS stays off in the embedded read view, which
	// is the honest price of keeping the CSP armor intact rather than weakening it.
	html = stripStyleNonce(html)

	// Rewrite root-relative links so navigation inside the cloud view goes to
	// the PUBLIC instrument, not the local one. Absolute URLs are left alone.
	base := strings.TrimRight(h.Config.CanonicalBaseURL, "/")
	html = strings.ReplaceAll(html, `href="/`, `href="`+base+`/`)
	html = strings.ReplaceAll(html, `action="/`, `action="`+base+`/`)

	// Inject the Local⇄Cloud toggle as a fixed same-origin banner so the user
	// always has the way back to Local without a new tab. Placed right after
	// <body ...> if present, else prepended.
	toggle := h.toggleHTML(target)
	if i := strings.Index(html, "<body"); i >= 0 {
		if j := strings.Index(html[i:], ">"); j >= 0 {
			insert := i + j + 1
			html = html[:insert] + toggle + html[insert:]
		} else {
			html = toggle + html
		}
	} else {
		html = toggle + html
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// toggleHTML builds the same-origin banner. Inline styles are used because the
// proxied cloud document carries its own CSP with its own nonces — a <style>
// block from us would be blocked, but the document's CSP style-src 'self'
// permits styles already present in its markup. Keep it minimal and dark-theme
// neutral so it reads as the instrument, not an overlay.
func (h *CloudHistoryHandler) toggleHTML(sourceURL string) string {
	return `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:8px 14px;background:#161b22;border-bottom:1px solid #30363d;font:500 13px/1.4 system-ui,sans-serif;color:#9da7b3;position:sticky;top:0;z-index:9999;">` +
		`<span style="display:inline-flex;align-items:center;gap:8px;">` +
		`<strong style="color:#e6edf3;">Analysis History</strong>` +
		`<span style="color:#8b949e;">· the public instrument's view</span>` +
		`</span>` +
		`<span style="display:inline-flex;gap:6px;align-items:center;">` +
		`<a href="/history" style="padding:3px 12px;border-radius:6px;border:1px solid #30363d;background:transparent;color:#8b949e;text-decoration:none;font-weight:600;">Local</a>` +
		`<span style="padding:3px 12px;border-radius:6px;background:#3fb95022;color:#3fb950;border:1px solid #3fb95044;font-weight:600;">Cloud</span>` +
		`</span>` +
		`</div>`
}

// stripStyleNonce removes the nonce attribute from <style> tags only, so the
// proxied page's inline critical-CSS still applies under the local app's CSP
// (whose style-src does not know the cloud's nonce). <script nonce> is left
// untouched — those stay blocked in the embedded read view by design.
func stripStyleNonce(html string) string {
	var b strings.Builder
	rest := html
	for {
		i := strings.Index(rest, "<style")
		if i < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		seg := rest[i:]
		j := strings.Index(seg, ">")
		if j < 0 {
			b.WriteString(seg)
			break
		}
		open := seg[:j] // the <style ...> opening tag (attrs, no '>')
		// drop a nonce="..." attribute if present
		for {
			k := strings.Index(open, ` nonce="`)
			if k < 0 {
				break
			}
			end := strings.Index(open[k+8:], `"`)
			if end < 0 {
				open = open[:k]
				break
			}
			open = open[:k] + open[k+8+end+1:]
		}
		b.WriteString(open)
		rest = seg[j:]
	}
	return b.String()
}

func (h *CloudHistoryHandler) renderError(c *gin.Context, msg string) {
	data := NewTemplateData(c, h.Config, mapKeyHistory)
	data["FlashMessages"] = []FlashMessage{{Category: "warning", Message: msg + " — showing your local history instead."}}
	data["Analyses"] = []historyAnalysisItem{}
	data["Pagination"] = BuildPagination(1, 1, 0)
	data["SearchDomain"] = ""
	c.HTML(http.StatusOK, templateHistory, data)
}
