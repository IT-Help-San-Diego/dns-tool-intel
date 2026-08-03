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

	// The proxied document's inline critical-CSS (dark theme, table layout) lives
	// in <style nonce="CLOUD"> blocks. The local app stamps its OWN CSP on the
	// response, whose style-src requires the LOCAL nonce — so the cloud nonce is
	// rejected and the styles go inert (unstyled white page). Re-key those style
	// tags to the LOCAL nonce so the local CSP accepts them. <script nonce> is
	// left as-is (cloud interactive JS stays off in the read view, by design).
	localNonce, _ := c.Get("csp_nonce")
	if ns, ok := localNonce.(string); ok && ns != "" {
		html = rekeyStyleNonce(html, ns)
	}

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

// toggleHTML builds the same-origin banner. Inline styles are used (style="" is
// not CSP-blocked), and the two controls are separated by real markup so they
// never run together. Reads: "Analysis History · the public instrument's view"
// on the left, "Local | Cloud" toggle on the right.
func (h *CloudHistoryHandler) toggleHTML(sourceURL string) string {
	return `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:10px 16px;background:#161b22;border-bottom:1px solid #30363d;font-family:system-ui,sans-serif;position:sticky;top:0;z-index:9999;">` +
		`<span style="font-size:14px;font-weight:600;color:#e6edf3;">Analysis History <span style="font-weight:400;color:#8b949e;">· the public instrument&#8217;s view</span></span>` +
		`<span style="display:inline-flex;border:1px solid #30363d;border-radius:7px;overflow:hidden;font-size:13px;font-weight:600;">` +
		`<a href="/history" style="padding:5px 14px;background:transparent;color:#8b949e;text-decoration:none;">Local</a>` +
		`<span style="padding:5px 14px;background:rgba(63,185,80,.15);color:#3fb950;">Cloud</span>` +
		`</span>` +
		`</div>`
}

// rekeyStyleNonce rewrites the nonce attribute on <style> tags to the LOCAL
// app's CSP nonce, so the proxied page's inline critical-CSS is accepted by the
// local app's CSP (whose style-src requires the local nonce). <script nonce> is
// left untouched — those stay blocked in the embedded read view by design.
func rekeyStyleNonce(html, localNonce string) string {
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
		if k := strings.Index(open, ` nonce="`); k >= 0 {
			end := strings.Index(open[k+8:], `"`)
			if end >= 0 {
				open = open[:k] + ` nonce="` + localNonce + `"` + open[k+8+end+1:]
			} else {
				open = open[:k] + ` nonce="` + localNonce + `"`
			}
		} else {
			open += ` nonce="` + localNonce + `"`
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
