// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/dnsclient"

	"github.com/gin-gonic/gin"
)

type AgentHandler struct {
	Config   *config.Config
	Analyzer *analyzer.Analyzer
}

func NewAgentHandler(cfg *config.Config, a *analyzer.Analyzer) *AgentHandler {
	return &AgentHandler{Config: cfg, Analyzer: a}
}

func (h *AgentHandler) OpenSearchXML(c *gin.Context) {
	baseURL := h.Config.BaseURL
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>DNS Tool</ShortName>
  <Description>DNS Security Intelligence — RFC-grounded domain analysis by IT Help San Diego Inc.</Description>
  <Tags>dns security subdomain certificate transparency DMARC SPF DKIM</Tags>
  <Contact>security@it-help.tech</Contact>
  <Url type="text/html" method="get" template="` + baseURL + `/agent/search?q={searchTerms}"/>
  <Url type="application/json" method="get" template="` + baseURL + `/agent/api?q={searchTerms}"/>
  <Image height="48" width="48" type="image/png">` + baseURL + `/static/icons/favicon-48x48.png</Image>
  <LongName>DNS Tool — Engineer's DNS Intelligence Report</LongName>
  <Attribution>Copyright (c) 2024-2026 IT Help San Diego Inc. Concept DOI: 10.5281/zenodo.18854899</Attribution>
  <SyndicationRight>open</SyndicationRight>
  <AdultContent>false</AdultContent>
  <Language>en-us</Language>
  <OutputEncoding>UTF-8</OutputEncoding>
  <InputEncoding>UTF-8</InputEncoding>
</OpenSearchDescription>`

	c.Header(headerCacheControl, "public, max-age=86400")
	c.Data(http.StatusOK, "application/opensearchdescription+xml; charset=utf-8", []byte(xml))
}

func (h *AgentHandler) AgentSearch(c *gin.Context) {
	domain := strings.TrimSpace(strings.ToLower(c.Query("q")))
	if domain == "" {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8",
			[]byte(`<!DOCTYPE html><html><head><title>DNS Tool Agent — Error</title></head><body><h1>Error</h1><p>Missing query parameter: q (domain name required)</p></body></html>`))
		return
	}

	if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8",
			[]byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>DNS Tool Agent — Error</title></head><body><h1>Error</h1><p>Invalid domain: %s</p></body></html>`,
				template.HTMLEscapeString(domain))))
		return
	}

	asciiDomain, err := dnsclient.DomainToASCII(domain)
	if err != nil {
		asciiDomain = domain
	}

	results := h.Analyzer.AnalyzeDomain(c.Request.Context(), asciiDomain, nil, analyzer.AnalysisOptions{})

	analysisSuccess := true
	if s, ok := results["analysis_success"].(bool); ok {
		analysisSuccess = s
	}

	if !analysisSuccess {
		errMsg := "Analysis failed"
		if e, ok := results["error"].(string); ok {
			errMsg = e
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8",
			[]byte(fmt.Sprintf(`<!DOCTYPE html><html><head><title>DNS Tool Agent — %s</title></head><body><h1>DNS Tool — %s</h1><p>%s</p></body></html>`,
				template.HTMLEscapeString(asciiDomain),
				template.HTMLEscapeString(asciiDomain),
				template.HTMLEscapeString(errMsg))))
		return
	}

	html := h.buildAgentHTML(asciiDomain, results)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func (h *AgentHandler) AgentAPI(c *gin.Context) {
	domain := strings.TrimSpace(strings.ToLower(c.Query("q")))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing query parameter: q (domain name required)"})
		return
	}

	if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid domain format"})
		return
	}

	asciiDomain, err := dnsclient.DomainToASCII(domain)
	if err != nil {
		asciiDomain = domain
	}

	results := h.Analyzer.AnalyzeDomain(c.Request.Context(), asciiDomain, nil, analyzer.AnalysisOptions{})

	analysisSuccess := true
	if s, ok := results["analysis_success"].(bool); ok {
		analysisSuccess = s
	}

	if !analysisSuccess {
		errMsg := "Analysis failed"
		if e, ok := results["error"].(string); ok {
			errMsg = e
		}
		c.JSON(http.StatusOK, gin.H{
			"domain": asciiDomain,
			"error":  errMsg,
			"status": "failed",
		})
		return
	}

	response := h.buildAgentJSON(asciiDomain, results)
	c.JSON(http.StatusOK, response)
}

func safeString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func safeInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func safeBool(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func safeMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func (h *AgentHandler) buildAgentJSON(domain string, results map[string]any) gin.H {
	spf := safeMap(results, "spf_analysis")
	dmarc := safeMap(results, "dmarc_analysis")
	dkim := safeMap(results, "dkim_analysis")
	subdomains := safeMap(results, "subdomain_discovery")

	spfVerdict := "not found"
	if spf != nil {
		spfVerdict = safeString(spf, "verdict")
		if spfVerdict == "" {
			if safeBool(spf, "has_spf") {
				spfVerdict = "present"
			} else {
				spfVerdict = "missing"
			}
		}
	}

	dmarcVerdict := "not found"
	dmarcPolicy := "none"
	if dmarc != nil {
		dmarcVerdict = safeString(dmarc, "verdict")
		if dmarcVerdict == "" {
			if safeBool(dmarc, "has_dmarc") {
				dmarcVerdict = "present"
			} else {
				dmarcVerdict = "missing"
			}
		}
		dmarcPolicy = safeString(dmarc, "policy")
	}

	dkimVerdict := "not found"
	if dkim != nil {
		dkimVerdict = safeString(dkim, "verdict")
		if dkimVerdict == "" {
			if safeBool(dkim, "has_dkim") {
				dkimVerdict = "present"
			} else {
				dkimVerdict = "not detected"
			}
		}
	}

	subdomainCount := 0
	certCount := 0
	cnameCount := 0
	if subdomains != nil {
		subdomainCount = safeInt(subdomains, "unique_subdomains")
		certCount = safeInt(subdomains, "unique_certs")
		cnameCount = safeInt(subdomains, "cname_count")
	}

	riskLevel := safeString(results, "risk_level")
	domainExists := safeBool(results, "domain_exists")

	dnssec := safeMap(results, "dnssec_analysis")
	dnssecStatus := "unknown"
	if dnssec != nil {
		if safeBool(dnssec, "signed") {
			dnssecStatus = "signed"
		} else {
			dnssecStatus = "unsigned"
		}
	}

	mtaSTS := safeMap(results, "mta_sts_analysis")
	mtaSTSMode := "none"
	if mtaSTS != nil {
		mtaSTSMode = safeString(mtaSTS, "mode")
	}

	bimi := safeMap(results, "bimi_analysis")
	bimiPresent := false
	if bimi != nil {
		bimiPresent = safeBool(bimi, "has_bimi")
	}

	caa := safeMap(results, "caa_analysis")
	caaPresent := false
	if caa != nil {
		caaPresent = safeBool(caa, "has_caa")
	}

	return gin.H{
		"tool":       "DNS Tool",
		"version":    h.Config.AppVersion,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"domain":     domain,
		"report_url": fmt.Sprintf("%s/analyze?domain=%s", h.Config.BaseURL, domain),
		"badge_url":  fmt.Sprintf("%s/badge?domain=%s&style=detailed", h.Config.BaseURL, domain),
		"status":     "success",
		"summary": gin.H{
			"domain_exists": domainExists,
			"risk_level":    riskLevel,
		},
		"email_authentication": gin.H{
			"spf":   gin.H{"status": spfVerdict},
			"dkim":  gin.H{"status": dkimVerdict},
			"dmarc": gin.H{"status": dmarcVerdict, "policy": dmarcPolicy},
			"bimi":  gin.H{"present": bimiPresent},
		},
		"transport_security": gin.H{
			"mta_sts": gin.H{"mode": mtaSTSMode},
			"dnssec":  gin.H{"status": dnssecStatus},
			"caa":     gin.H{"present": caaPresent},
		},
		"subdomain_discovery": gin.H{
			"subdomains_found": subdomainCount,
			"certificates":     certCount,
			"cnames":           cnameCount,
		},
		"provenance": gin.H{
			"tool":        "DNS Tool by IT Help San Diego Inc.",
			"methodology": "RFC-grounded analysis with Bayesian confidence scoring",
			"concept_doi": "10.5281/zenodo.18854899",
			"license":     "BUSL-1.1",
		},
	}
}

func esc(s string) string {
	return template.HTMLEscapeString(s)
}

func (h *AgentHandler) buildAgentHTML(domain string, results map[string]any) string {
	j := h.buildAgentJSON(domain, results)

	riskLevel := "Unknown"
	if summary, ok := j["summary"].(gin.H); ok {
		if rl, ok := summary["risk_level"].(string); ok && rl != "" {
			riskLevel = rl
		}
	}

	emailAuth := j["email_authentication"].(gin.H)
	spfStatus := extractNestedStatus(emailAuth, "spf")
	dkimStatus := extractNestedStatus(emailAuth, "dkim")
	dmarcStatus := extractNestedStatus(emailAuth, "dmarc")
	dmarcPolicy := "none"
	if d, ok := emailAuth["dmarc"].(gin.H); ok {
		if p, ok := d["policy"].(string); ok && p != "" {
			dmarcPolicy = p
		}
	}
	bimiPresent := false
	if b, ok := emailAuth["bimi"].(gin.H); ok {
		bimiPresent, _ = b["present"].(bool)
	}

	transport := j["transport_security"].(gin.H)
	dnssecStatus := extractNestedStatus(transport, "dnssec")
	mtaSTSMode := "none"
	if m, ok := transport["mta_sts"].(gin.H); ok {
		if mode, ok := m["mode"].(string); ok && mode != "" {
			mtaSTSMode = mode
		}
	}
	caaPresent := false
	if ca, ok := transport["caa"].(gin.H); ok {
		caaPresent, _ = ca["present"].(bool)
	}

	subCount := 0
	certCountVal := 0
	cnameCountVal := 0
	if sd, ok := j["subdomain_discovery"].(gin.H); ok {
		subCount, _ = sd["subdomains_found"].(int)
		certCountVal, _ = sd["certificates"].(int)
		cnameCountVal, _ = sd["cnames"].(int)
	}

	ed := esc(domain)
	reportURL := fmt.Sprintf("%s/analyze?domain=%s", h.Config.BaseURL, esc(domain))
	badgeURL := fmt.Sprintf("%s/badge?domain=%s&amp;style=detailed", h.Config.BaseURL, esc(domain))

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DNS Tool — ` + ed + `</title>
  <meta name="description" content="DNS Security Intelligence Report for ` + ed + `">
  <meta name="generator" content="DNS Tool ` + esc(h.Config.AppVersion) + `">
  <link rel="search" type="application/opensearchdescription+xml" title="DNS Tool" href="` + esc(h.Config.BaseURL) + `/agent/opensearch.xml">
</head>
<body>
<h1>DNS Tool — ` + ed + `</h1>
<p><strong>Risk Level:</strong> ` + esc(riskLevel) + `</p>
<p><strong>Report:</strong> <a href="` + reportURL + `">` + reportURL + `</a></p>
<p><strong>Badge:</strong> <img src="` + badgeURL + `" alt="DNS Tool Security Badge"></p>

<h2>Email Authentication</h2>
<table>
  <tr><th>Control</th><th>Status</th></tr>
  <tr><td>SPF</td><td>` + esc(spfStatus) + `</td></tr>
  <tr><td>DKIM</td><td>` + esc(dkimStatus) + `</td></tr>
  <tr><td>DMARC</td><td>` + esc(dmarcStatus) + ` (policy: ` + esc(dmarcPolicy) + `)</td></tr>
  <tr><td>BIMI</td><td>` + boolToPresence(bimiPresent) + `</td></tr>
</table>

<h2>Transport Security</h2>
<table>
  <tr><th>Control</th><th>Status</th></tr>
  <tr><td>DNSSEC</td><td>` + esc(dnssecStatus) + `</td></tr>
  <tr><td>MTA-STS</td><td>` + esc(mtaSTSMode) + `</td></tr>
  <tr><td>CAA</td><td>` + boolToPresence(caaPresent) + `</td></tr>
</table>

<h2>Subdomain Discovery</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Subdomains Found</td><td>` + fmt.Sprintf("%d", subCount) + `</td></tr>
  <tr><td>Unique Certificates</td><td>` + fmt.Sprintf("%d", certCountVal) + `</td></tr>
  <tr><td>CNAME Records</td><td>` + fmt.Sprintf("%d", cnameCountVal) + `</td></tr>
</table>

<h2>Provenance</h2>
<p>
  <strong>Tool:</strong> DNS Tool by IT Help San Diego Inc.<br>
  <strong>Methodology:</strong> RFC-grounded analysis with Bayesian confidence scoring<br>
  <strong>Concept DOI:</strong> <a href="https://doi.org/10.5281/zenodo.18854899">10.5281/zenodo.18854899</a><br>
  <strong>Version:</strong> ` + esc(h.Config.AppVersion) + `<br>
  <strong>Timestamp:</strong> ` + time.Now().UTC().Format(time.RFC3339) + `
</p>
</body>
</html>`)

	return sb.String()
}

func extractNestedStatus(parent gin.H, key string) string {
	if m, ok := parent[key].(gin.H); ok {
		if s, ok := m["status"].(string); ok {
			return s
		}
	}
	return "unknown"
}

func boolToPresence(b bool) string {
	if b {
		return "present"
	}
	return "not found"
}
