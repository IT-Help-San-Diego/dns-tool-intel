// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "fmt"
        "html/template"
        "log/slog"
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

func extractAgentQuery(c *gin.Context) string {
        for _, key := range []string{"q", "domain", "query", "search", "searchTerms"} {
                if v := strings.TrimSpace(c.Query(key)); v != "" {
                        return strings.ToLower(v)
                }
        }
        return ""
}

func (h *AgentHandler) AgentSearch(c *gin.Context) {
        slog.Info("Agent search request",
                "raw_query", c.Request.URL.RawQuery,
                "full_url", c.Request.URL.String(),
                "remote_addr", c.ClientIP(),
                "user_agent", c.Request.UserAgent())

        domain := extractAgentQuery(c)
        if domain == "" {
                base := h.Config.BaseURL
                c.Data(http.StatusOK, "text/html; charset=utf-8",
                        []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>DNS Tool — Agent Search</title>`+
                                `<link rel="search" type="application/opensearchdescription+xml" title="DNS Tool" href="`+base+`/agent/opensearch.xml">`+
                                `</head><body><h1>DNS Tool — Agent Search</h1>`+
                                `<p>Usage: <code>`+base+`/agent/search?q=example.com</code></p>`+
                                `<ul>`+
                                `<li><a href="`+base+`/agent/search?q=it-help.tech">Analyze it-help.tech</a></li>`+
                                `<li><a href="`+base+`/agent/search?q=apple.com">Analyze apple.com</a></li>`+
                                `<li><a href="`+base+`/agent/search?q=red.com">Analyze red.com</a></li>`+
                                `<li><a href="`+base+`">DNS Tool Home</a></li>`+
                                `<li><a href="`+base+`/agent/opensearch.xml">OpenSearch Descriptor</a></li>`+
                                `</ul></body></html>`))
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
        domain := extractAgentQuery(c)
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

func safeFloat64(m map[string]any, key string) float64 {
        switch v := m[key].(type) {
        case float64:
                return v
        case int:
                return float64(v)
        case int64:
                return float64(v)
        }
        return 0
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

        postureScore := 0
        postureGrade := "N/A"
        postureLabel := ""
        if posture := safeMap(results, "posture"); posture != nil {
                postureScore = int(safeFloat64(posture, "score"))
                postureGrade = safeString(posture, "grade")
                postureLabel = safeString(posture, "label")
        }

        base := h.Config.BaseURL
        analyzeURL := fmt.Sprintf("%s/analyze?domain=%s", base, domain)
        waybackURL := fmt.Sprintf("https://web.archive.org/web/*/%s", analyzeURL)

        return gin.H{
                "tool":       "DNS Tool",
                "version":    h.Config.AppVersion,
                "timestamp":  time.Now().UTC().Format(time.RFC3339),
                "domain":     domain,
                "status":     "success",
                "summary": gin.H{
                        "domain_exists":  domainExists,
                        "risk_level":     riskLevel,
                        "posture_score":  postureScore,
                        "posture_grade":  postureGrade,
                        "posture_label":  postureLabel,
                },
                "links": gin.H{
                        "report":          analyzeURL,
                        "snapshot":        fmt.Sprintf("%s/snapshot/%s", base, domain),
                        "topology":        fmt.Sprintf("%s/topology?domain=%s", base, domain),
                        "wayback_archive": waybackURL,
                        "api_json":        fmt.Sprintf("%s/agent/api?q=%s", base, domain),
                },
                "badges": gin.H{
                        "detailed_svg": fmt.Sprintf("%s/badge?domain=%s&style=detailed", base, domain),
                        "covert_svg":   fmt.Sprintf("%s/badge?domain=%s&style=covert", base, domain),
                        "flat_svg":     fmt.Sprintf("%s/badge?domain=%s", base, domain),
                        "shields_io":   fmt.Sprintf("%s/badge/shields?domain=%s", base, domain),
                        "animated_svg": fmt.Sprintf("%s/badge/animated?domain=%s", base, domain),
                        "embed_page":   fmt.Sprintf("%s/badge/embed", base),
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
                        "tool":           "DNS Tool by IT Help San Diego Inc.",
                        "methodology":    "RFC-grounded analysis with Bayesian confidence scoring",
                        "concept_doi":    "10.5281/zenodo.18854899",
                        "doi_url":        "https://doi.org/10.5281/zenodo.18854899",
                        "license":        "BUSL-1.1",
                        "publisher":      "IT Help San Diego Inc.",
                        "publisher_url":  "https://it-help.tech",
                        "issn":           "",
                },
        }
}

func esc(s string) string {
        return template.HTMLEscapeString(s)
}

func (h *AgentHandler) buildAgentHTML(domain string, results map[string]any) string {
        j := h.buildAgentJSON(domain, results)

        riskLevel := "Unknown"
        postureScore := 0
        postureGrade := "N/A"
        postureLabel := ""
        if summary, ok := j["summary"].(gin.H); ok {
                if rl, ok := summary["risk_level"].(string); ok && rl != "" {
                        riskLevel = rl
                }
                if ps, ok := summary["posture_score"].(int); ok {
                        postureScore = ps
                }
                if pg, ok := summary["posture_grade"].(string); ok {
                        postureGrade = pg
                }
                if pl, ok := summary["posture_label"].(string); ok {
                        postureLabel = pl
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

        links := j["links"].(gin.H)
        badges := j["badges"].(gin.H)

        ed := esc(domain)
        base := h.Config.BaseURL
        reportURL := esc(links["report"].(string))
        snapshotURL := esc(links["snapshot"].(string))
        topologyURL := esc(links["topology"].(string))
        waybackURL := esc(links["wayback_archive"].(string))
        apiURL := esc(links["api_json"].(string))
        badgeDetailed := esc(badges["detailed_svg"].(string))
        badgeCovert := esc(badges["covert_svg"].(string))
        badgeFlat := esc(badges["flat_svg"].(string))

        now := time.Now().UTC()
        isoDate := now.Format("2006-01-02")
        isoTimestamp := now.Format(time.RFC3339)

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns# DC: http://purl.org/dc/elements/1.1/ DCTERMS: http://purl.org/dc/terms/">
<head>
  <meta charset="UTF-8">
  <title>DNS Tool — ` + ed + ` — DNS Security Intelligence Report</title>
  <meta name="description" content="DNS Security Intelligence Report for ` + ed + ` — Risk: ` + esc(riskLevel) + `, Posture: ` + fmt.Sprintf("%d", postureScore) + `/100 (` + esc(postureGrade) + `)">
  <meta name="generator" content="DNS Tool ` + esc(h.Config.AppVersion) + `">
  <meta name="robots" content="noindex, noarchive">
  <link rel="search" type="application/opensearchdescription+xml" title="DNS Tool" href="` + esc(base) + `/agent/opensearch.xml">

  <!-- Dublin Core metadata (Zotero, Mendeley, citation managers) -->
  <meta name="DC.title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="DC.creator" content="DNS Tool by IT Help San Diego Inc.">
  <meta name="DC.publisher" content="IT Help San Diego Inc.">
  <meta name="DC.date" content="` + isoDate + `">
  <meta name="DC.type" content="Dataset">
  <meta name="DC.format" content="text/html">
  <meta name="DC.identifier" content="` + reportURL + `">
  <meta name="DC.relation" content="https://doi.org/10.5281/zenodo.18854899">
  <meta name="DC.rights" content="BUSL-1.1">
  <meta name="DC.subject" content="DNS; email security; SPF; DKIM; DMARC; DNSSEC; subdomain discovery; certificate transparency">
  <meta name="DC.language" content="en">
  <meta name="DCTERMS.issued" content="` + isoDate + `">

  <!-- Highwire Press tags (Google Scholar, Zotero) -->
  <meta name="citation_title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="citation_author" content="IT Help San Diego Inc.">
  <meta name="citation_publication_date" content="` + isoDate + `">
  <meta name="citation_online_date" content="` + isoDate + `">
  <meta name="citation_doi" content="10.5281/zenodo.18854899">
  <meta name="citation_publisher" content="IT Help San Diego Inc.">
  <meta name="citation_technical_report_institution" content="IT Help San Diego Inc.">
  <meta name="citation_public_url" content="` + reportURL + `">

  <!-- Open Graph (social sharing, DEVONthink) -->
  <meta property="og:title" content="DNS Tool — ` + ed + `">
  <meta property="og:description" content="Risk: ` + esc(riskLevel) + ` | Posture: ` + fmt.Sprintf("%d", postureScore) + `/100 (` + esc(postureGrade) + `) | ` + fmt.Sprintf("%d", subCount) + ` subdomains">
  <meta property="og:type" content="article">
  <meta property="og:url" content="` + reportURL + `">
  <meta property="og:image" content="` + badgeDetailed + `">
  <meta property="og:site_name" content="DNS Tool">
  <meta property="article:published_time" content="` + isoTimestamp + `">
</head>
<body>

<!-- COinS span for Zotero one-click capture -->
<span class="Z3988" title="ctx_ver=Z39.88-2004&amp;rft_val_fmt=info%3Aofi%2Ffmt%3Akev%3Amtx%3Adc&amp;rft.type=Dataset&amp;rft.title=DNS+Security+Intelligence+Report%3A+` + esc(domain) + `&amp;rft.creator=IT+Help+San+Diego+Inc.&amp;rft.date=` + isoDate + `&amp;rft.identifier=` + esc(reportURL) + `&amp;rft.relation=https%3A%2F%2Fdoi.org%2F10.5281%2Fzenodo.18854899&amp;rft.publisher=IT+Help+San+Diego+Inc.&amp;rft.rights=BUSL-1.1&amp;rft.subject=DNS+security&amp;rft.format=text%2Fhtml"></span>

<h1>DNS Tool — ` + ed + `</h1>

<h2>Summary</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Risk Level</td><td>` + esc(riskLevel) + `</td></tr>
  <tr><td>Posture Score</td><td>` + fmt.Sprintf("%d/100", postureScore) + `</td></tr>
  <tr><td>Posture Grade</td><td>` + esc(postureGrade) + `</td></tr>
  <tr><td>Posture Label</td><td>` + esc(postureLabel) + `</td></tr>
</table>

<h2>Security Badges</h2>
<p><strong>Detailed Badge:</strong><br><img src="` + badgeDetailed + `" alt="DNS Tool Detailed Security Badge for ` + ed + `"></p>
<p><strong>Covert Badge:</strong><br><img src="` + badgeCovert + `" alt="DNS Tool Covert Security Badge for ` + ed + `"></p>
<p><strong>Flat Badge:</strong><br><img src="` + badgeFlat + `" alt="DNS Tool Flat Security Badge for ` + ed + `"></p>

<h2>Downloads &amp; Archives</h2>
<ul>
  <li><a href="` + reportURL + `">Full Analysis Report</a> (HTML)</li>
  <li><a href="` + snapshotURL + `">Observed Records Snapshot</a> (TXT, SHA-3-512 integrity hash included)</li>
  <li><a href="` + topologyURL + `">DNS Topology Map</a> (interactive network visualization)</li>
  <li><a href="` + apiURL + `">Machine-Readable API Response</a> (JSON)</li>
  <li><a href="` + waybackURL + `">Internet Archive — Wayback Machine</a> (third-party permanent record)</li>
</ul>

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

<h2>Provenance &amp; Citation</h2>
<p>
  <strong>Tool:</strong> DNS Tool by <a href="https://it-help.tech">IT Help San Diego Inc.</a><br>
  <strong>Methodology:</strong> RFC-grounded analysis with Bayesian confidence scoring<br>
  <strong>Concept DOI:</strong> <a href="https://doi.org/10.5281/zenodo.18854899">10.5281/zenodo.18854899</a><br>
  <strong>Version:</strong> ` + esc(h.Config.AppVersion) + `<br>
  <strong>License:</strong> BUSL-1.1<br>
  <strong>Timestamp:</strong> <time datetime="` + isoTimestamp + `">` + isoTimestamp + `</time>
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
