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
        Config      *config.Config
        Analyzer    *analyzer.Analyzer
        lookupStore LookupStore
}

func NewAgentHandler(cfg *config.Config, a *analyzer.Analyzer, store ...LookupStore) *AgentHandler {
        h := &AgentHandler{Config: cfg, Analyzer: a}
        if len(store) > 0 {
                h.lookupStore = store[0]
        }
        return h
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
                        return cleanAgentQuery(v)
                }
        }
        return ""
}

func cleanAgentQuery(q string) string {
        q = strings.ToLower(strings.TrimSpace(q))
        q = strings.Trim(q, "_ \t")
        q = strings.Trim(q, `"'`)
        q = strings.Trim(q, "_ \t")
        return q
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
                spfVerdict = safeString(spf, "status")
                if spfVerdict == "" {
                        spfVerdict = safeString(spf, "verdict")
                }
                if spfVerdict == "" {
                        spfVerdict = "missing"
                }
        }

        dmarcVerdict := "not found"
        dmarcPolicy := "none"
        if dmarc != nil {
                dmarcVerdict = safeString(dmarc, "status")
                if dmarcVerdict == "" {
                        dmarcVerdict = safeString(dmarc, "verdict")
                }
                if dmarcVerdict == "" {
                        dmarcVerdict = "missing"
                }
                dmarcPolicy = safeString(dmarc, "policy")
                if dmarcPolicy == "" {
                        dmarcPolicy = "none"
                }
        }

        dkimVerdict := "not found"
        if dkim != nil {
                dkimVerdict = safeString(dkim, "status")
                if dkimVerdict == "" {
                        dkimVerdict = safeString(dkim, "verdict")
                }
                if dkimVerdict == "" {
                        dkimVerdict = "not detected"
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
                        "report_page":     fmt.Sprintf("%s/agent/report?domain=%s", base, domain),
                        "snapshot":        fmt.Sprintf("%s/snapshot/%s", base, domain),
                        "topology":        fmt.Sprintf("%s/topology?domain=%s", base, domain),
                        "wayback_archive": waybackURL,
                        "wayback_page":    fmt.Sprintf("%s/agent/wayback?domain=%s", base, domain),
                        "api_json":        fmt.Sprintf("%s/agent/api?q=%s", base, domain),
                },
                "badges": gin.H{
                        "detailed_svg":  fmt.Sprintf("%s/badge?domain=%s&style=detailed", base, domain),
                        "covert_svg":    fmt.Sprintf("%s/badge?domain=%s&style=covert", base, domain),
                        "flat_svg":      fmt.Sprintf("%s/badge?domain=%s", base, domain),
                        "shields_io":    fmt.Sprintf("%s/badge/shields?domain=%s", base, domain),
                        "animated_svg":  fmt.Sprintf("%s/badge/animated?domain=%s", base, domain),
                        "embed_page":    fmt.Sprintf("%s/badge/embed", base),
                        "detailed_page": fmt.Sprintf("%s/agent/badge-view?domain=%s&style=detailed", base, domain),
                        "covert_page":   fmt.Sprintf("%s/agent/badge-view?domain=%s&style=covert", base, domain),
                        "flat_page":     fmt.Sprintf("%s/agent/badge-view?domain=%s&style=flat", base, domain),
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
        apiURL := esc(links["api_json"].(string))
        waybackViewURL := esc(fmt.Sprintf("%s/agent/wayback?domain=%s", base, domain))
        reportPageURL := esc(fmt.Sprintf("%s/agent/report?domain=%s", base, domain))
        badgeDetailed := esc(badges["detailed_svg"].(string))
        badgeCovert := esc(badges["covert_svg"].(string))
        badgeFlat := esc(badges["flat_svg"].(string))
        badgeViewDetailed := esc(fmt.Sprintf("%s/agent/badge-view?domain=%s&style=detailed", base, domain))
        badgeViewCovert := esc(fmt.Sprintf("%s/agent/badge-view?domain=%s&style=covert", base, domain))
        badgeViewFlat := esc(fmt.Sprintf("%s/agent/badge-view?domain=%s&style=flat", base, domain))

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
<p><strong>Detailed Badge:</strong><br><a href="` + badgeViewDetailed + `" title="DNS Tool Detailed Security Badge for ` + ed + `"><img src="` + badgeDetailed + `" alt="DNS Tool Detailed Security Badge for ` + ed + `" width="400"></a></p>
<p><strong>Covert Badge:</strong><br><a href="` + badgeViewCovert + `" title="DNS Tool Covert Security Badge for ` + ed + `"><img src="` + badgeCovert + `" alt="DNS Tool Covert Security Badge for ` + ed + `" width="300"></a></p>
<p><strong>Flat Badge:</strong><br><a href="` + badgeViewFlat + `" title="DNS Tool Flat Security Badge for ` + ed + `"><img src="` + badgeFlat + `" alt="DNS Tool Flat Security Badge for ` + ed + `" width="200"></a></p>

<h2>Downloads &amp; Archives</h2>
<ul>
  <li><a href="` + reportPageURL + `">DNS Security Intelligence Report</a> (full engineer's report)</li>
  <li><a href="` + reportURL + `">Interactive Analysis</a> (live analysis with charts)</li>
  <li><a href="` + snapshotURL + `">Observed Records Snapshot</a> (TXT, SHA-3-512 integrity hash included)</li>
  <li><a href="` + topologyURL + `">Analysis Pipeline &amp; Protocol Map</a> (DNS Tool methodology — signal flow, RFC sources, and scoring pipeline)</li>
  <li><a href="` + apiURL + `">Machine-Readable API Response</a> (JSON)</li>
  <li><a href="` + waybackViewURL + `">Internet Archive — Wayback Machine</a> (third-party permanent record)</li>
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

func (h *AgentHandler) BadgeView(c *gin.Context) {
        domain := strings.TrimSpace(c.Query("q"))
        if domain == "" {
                domain = strings.TrimSpace(c.Query("domain"))
        }
        if domain == "" {
                c.String(http.StatusBadRequest, "missing domain parameter")
                return
        }
        domain = cleanAgentQuery(domain)
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, "invalid domain")
                return
        }

        style := strings.TrimSpace(c.Query("style"))
        if style == "" {
                style = "detailed"
        }
        switch style {
        case "detailed", "covert", "flat":
        default:
                style = "detailed"
        }

        base := h.Config.BaseURL
        ed := esc(domain)
        es := esc(style)

        badgeURL := fmt.Sprintf("%s/badge?domain=%s", base, domain)
        if style != "flat" {
                badgeURL += "&style=" + style
        }
        eb := esc(badgeURL)
        reportURL := esc(fmt.Sprintf("%s/analyze?domain=%s", base, domain))

        styleName := style
        if style == "flat" {
                styleName = "compact"
        }

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DNS Security Badge (` + es + `) — ` + ed + ` — DNS Tool</title>
  <meta name="description" content="` + es + ` DNS security posture badge for ` + ed + ` — generated by DNS Tool.">
  <meta name="robots" content="noindex, noarchive">
  <meta property="og:title" content="DNS Security Badge (` + es + `) — ` + ed + `">
  <meta property="og:description" content="DNS security posture badge for ` + ed + `.">
  <meta property="og:type" content="article">
  <meta property="og:image" content="` + eb + `">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 1.4rem; margin-bottom: .5rem; }
    .meta { color: #8b949e; font-size: .85rem; margin-bottom: 1.5rem; }
    .meta a { color: #58a6ff; text-decoration: none; }
    .meta a:hover { text-decoration: underline; }
    .badge-frame { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; text-align: center; }
    .badge-frame object { max-width: 100%; height: auto; pointer-events: none; }
    .badge-frame a { display: block; }
    .links { margin-top: 1.5rem; font-size: .9rem; }
    .links a { color: #58a6ff; text-decoration: none; margin-right: 1.5rem; }
    .links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>DNS Security Badge — ` + ed + `</h1>
    <p class="meta">Style: <strong>` + esc(styleName) + `</strong> · Generated by <a href="` + esc(base) + `">DNS Tool</a> · <a href="` + reportURL + `">View full report →</a></p>
    <div class="badge-frame">
      <a href="` + reportURL + `"><object type="image/svg+xml" data="` + eb + `" aria-label="DNS Tool ` + es + ` security badge for ` + ed + `">` + ed + ` DNS security badge</object></a>
    </div>
    <div class="links">
      <a href="` + reportURL + `">Full Analysis Report</a>
      <a href="` + eb + `">Direct Badge SVG</a>
      <a href="` + esc(fmt.Sprintf("%s/badge/embed", base)) + `">Badge Generator</a>
    </div>
  </div>
</body>
</html>`)

        c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(sb.String()))
}

func (h *AgentHandler) WaybackView(c *gin.Context) {
        domain := strings.TrimSpace(c.Query("q"))
        if domain == "" {
                domain = strings.TrimSpace(c.Query("domain"))
        }
        if domain == "" {
                c.String(http.StatusBadRequest, "missing domain parameter")
                return
        }
        domain = cleanAgentQuery(domain)
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, "invalid domain")
                return
        }

        base := h.Config.BaseURL
        ed := esc(domain)
        analyzeURL := fmt.Sprintf("%s/analyze?domain=%s", base, domain)
        calendarURL := fmt.Sprintf("https://web.archive.org/web/*/%s", analyzeURL)
        latestURL := fmt.Sprintf("https://web.archive.org/web/%s", analyzeURL)
        saveURL := fmt.Sprintf("https://web.archive.org/save/%s", analyzeURL)

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Wayback Machine Archive — ` + ed + ` — DNS Tool</title>
  <meta name="description" content="Internet Archive Wayback Machine snapshots for ` + ed + ` DNS security analysis by DNS Tool.">
  <meta name="robots" content="noindex, noarchive">
  <meta property="og:title" content="Wayback Machine Archive — ` + ed + `">
  <meta property="og:description" content="Third-party permanent record of DNS security analysis for ` + ed + `.">
  <meta property="og:type" content="article">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 1.4rem; margin-bottom: .5rem; }
    .meta { color: #8b949e; font-size: .85rem; margin-bottom: 1.5rem; }
    .meta a { color: #58a6ff; text-decoration: none; }
    .meta a:hover { text-decoration: underline; }
    .archive-links { list-style: none; padding: 0; }
    .archive-links li { margin-bottom: 1rem; padding: 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
    .archive-links a { color: #58a6ff; text-decoration: none; font-weight: 600; }
    .archive-links a:hover { text-decoration: underline; }
    .archive-links .desc { color: #8b949e; font-size: .85rem; margin-top: .25rem; }
    .footer-links { margin-top: 1.5rem; font-size: .9rem; }
    .footer-links a { color: #58a6ff; text-decoration: none; margin-right: 1.5rem; }
    .footer-links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Wayback Machine Archive — ` + ed + `</h1>
    <p class="meta">Third-party permanent record via the <a href="https://web.archive.org">Internet Archive</a> · Analysis by <a href="` + esc(base) + `">DNS Tool</a></p>
    <ul class="archive-links">
      <li>
        <a href="` + esc(calendarURL) + `">All Archived Snapshots (Calendar View)</a>
        <div class="desc">Browse every saved version of this analysis on the Wayback Machine timeline.</div>
      </li>
      <li>
        <a href="` + esc(latestURL) + `">Latest Archived Snapshot</a>
        <div class="desc">Jump directly to the most recent archived copy, if available.</div>
      </li>
      <li>
        <a href="` + esc(saveURL) + `">Save Current Analysis to Wayback Machine</a>
        <div class="desc">Request the Internet Archive to capture and preserve the current state of this report right now.</div>
      </li>
    </ul>
    <div class="footer-links">
      <a href="` + esc(analyzeURL) + `">Full Analysis Report</a>
      <a href="` + esc(base) + `">DNS Tool Home</a>
    </div>
  </div>
</body>
</html>`)

        c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(sb.String()))
}

func (h *AgentHandler) ReportView(c *gin.Context) {
        domain := strings.TrimSpace(c.Query("q"))
        if domain == "" {
                domain = strings.TrimSpace(c.Query("domain"))
        }
        if domain == "" {
                c.String(http.StatusBadRequest, "missing domain parameter")
                return
        }
        domain = cleanAgentQuery(domain)
        if !dnsclient.ValidateDomain(domain) {
                c.String(http.StatusBadRequest, "invalid domain")
                return
        }

        ascii, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                ascii = domain
        }

        var results map[string]any
        var scanTime time.Time

        if h.lookupStore != nil {
                analysis, dbErr := h.lookupStore.GetRecentAnalysisByDomain(c.Request.Context(), ascii)
                if dbErr == nil && !analysis.Private {
                        results = unmarshalResults(analysis.FullResults, "AgentReport")
                        if analysis.CreatedAt.Valid {
                                scanTime = analysis.CreatedAt.Time
                        }
                }
        }

        if results == nil && h.Analyzer != nil {
                results = h.Analyzer.AnalyzeDomain(c.Request.Context(), ascii, nil, analyzer.AnalysisOptions{})
                scanTime = time.Now().UTC()
        }
        if results == nil {
                results = map[string]any{"analysis_success": true}
                scanTime = time.Now().UTC()
        }

        html := h.buildReportHTML(ascii, results, scanTime)
        c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func extractRecordStrings(results map[string]any, section string) []string {
        sec, ok := results[section].(map[string]any)
        if !ok {
                return nil
        }
        for _, key := range []string{"records", "txt_records", "values", "mechanisms"} {
                if arr, ok := sec[key].([]any); ok {
                        out := make([]string, 0, len(arr))
                        for _, v := range arr {
                                if s, ok := v.(string); ok && s != "" {
                                        out = append(out, s)
                                }
                        }
                        if len(out) > 0 {
                                return out
                        }
                }
        }
        return nil
}

func extractMapField(results map[string]any, section, field string) string {
        sec, ok := results[section].(map[string]any)
        if !ok {
                return ""
        }
        v, ok := sec[field].(string)
        if ok {
                return v
        }
        return ""
}

func extractDKIMSelectors(results map[string]any) []string {
        sec, ok := results["dkim"].(map[string]any)
        if !ok {
                return nil
        }
        if sels, ok := sec["selectors"].([]any); ok {
                out := make([]string, 0, len(sels))
                for _, s := range sels {
                        switch v := s.(type) {
                        case string:
                                out = append(out, v)
                        case map[string]any:
                                if name, ok := v["selector"].(string); ok {
                                        out = append(out, name)
                                }
                        }
                }
                return out
        }
        return nil
}

func extractSubdomains(results map[string]any) []string {
        sec, ok := results["subdomains"].(map[string]any)
        if !ok {
                return nil
        }
        if subs, ok := sec["subdomains"].([]any); ok {
                out := make([]string, 0, len(subs))
                for _, s := range subs {
                        switch v := s.(type) {
                        case string:
                                out = append(out, v)
                        case map[string]any:
                                if name, ok := v["domain"].(string); ok {
                                        out = append(out, name)
                                } else if name, ok := v["name"].(string); ok {
                                        out = append(out, name)
                                }
                        }
                }
                return out
        }
        return nil
}

func (h *AgentHandler) buildReportHTML(domain string, results map[string]any, scanTime time.Time) string {
        base := h.Config.BaseURL
        ed := esc(domain)
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
        if sd, ok := j["subdomain_discovery"].(gin.H); ok {
                subCount, _ = sd["subdomains_found"].(int)
        }

        isoDate := scanTime.Format("2006-01-02")
        isoTimestamp := scanTime.Format(time.RFC3339)

        spfRecords := extractRecordStrings(results, "spf")
        dmarcRaw := extractMapField(results, "dmarc", "record")
        dkimSelectors := extractDKIMSelectors(results)
        subdomainList := extractSubdomains(results)

        mtaSTSPolicy := extractMapField(results, "mta_sts", "policy_body")
        if mtaSTSPolicy == "" {
                mtaSTSPolicy = extractMapField(results, "mta_sts", "record")
        }

        var nsRecords []string
        if basic, ok := results["basic_records"].(map[string]any); ok {
                if ns, ok := basic["ns"].([]any); ok {
                        for _, v := range ns {
                                if s, ok := v.(string); ok {
                                        nsRecords = append(nsRecords, s)
                                }
                        }
                }
        }

        var mxRecords []string
        if basic, ok := results["basic_records"].(map[string]any); ok {
                if mx, ok := basic["mx"].([]any); ok {
                        for _, v := range mx {
                                switch m := v.(type) {
                                case string:
                                        mxRecords = append(mxRecords, m)
                                case map[string]any:
                                        if host, ok := m["host"].(string); ok {
                                                mxRecords = append(mxRecords, host)
                                        }
                                }
                        }
                }
        }

        var aRecords []string
        if basic, ok := results["basic_records"].(map[string]any); ok {
                if a, ok := basic["a"].([]any); ok {
                        for _, v := range a {
                                if s, ok := v.(string); ok {
                                        aRecords = append(aRecords, s)
                                }
                        }
                }
        }

        badgeDetailed := fmt.Sprintf("%s/badge?domain=%s&style=detailed", base, domain)
        analyzeURL := fmt.Sprintf("%s/analyze?domain=%s", base, domain)
        snapshotURL := fmt.Sprintf("%s/snapshot/%s", base, domain)
        topologyURL := fmt.Sprintf("%s/topology?domain=%s", base, domain)
        waybackURL := fmt.Sprintf("%s/agent/wayback?domain=%s", base, domain)
        apiURL := fmt.Sprintf("%s/agent/api?q=%s", base, domain)

        postureColor := "#3fb950"
        if postureScore < 50 {
                postureColor = "#f85149"
        } else if postureScore < 75 {
                postureColor = "#d29922"
        }

        bimiLabel := "Not configured"
        if bimiPresent {
                bimiLabel = "Present"
        }
        caaLabel := "Not configured"
        if caaPresent {
                caaLabel = "Present"
        }

        var sb strings.Builder
        sb.WriteString(`<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns# DC: http://purl.org/dc/elements/1.1/">
<head>
  <meta charset="UTF-8">
  <title>DNS Security Intelligence Report — ` + ed + ` — DNS Tool</title>
  <meta name="description" content="Full DNS security intelligence report for ` + ed + ` — Posture: ` + fmt.Sprintf("%d", postureScore) + `/100. SPF, DKIM, DMARC, DNSSEC, MTA-STS, CAA, subdomain discovery, and certificate transparency analysis.">
  <meta name="robots" content="noindex, noarchive">
  <meta name="generator" content="DNS Tool ` + esc(h.Config.AppVersion) + `">
  <meta property="og:title" content="DNS Security Intelligence Report — ` + ed + `">
  <meta property="og:description" content="Posture ` + fmt.Sprintf("%d", postureScore) + `/100 (` + esc(postureGrade) + `) — Email auth, transport security, subdomain discovery.">
  <meta property="og:type" content="article">
  <meta property="og:image" content="` + esc(badgeDetailed) + `">
  <meta property="og:site_name" content="DNS Tool">
  <meta property="article:published_time" content="` + isoTimestamp + `">
  <meta name="DC.title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="DC.creator" content="DNS Tool by IT Help San Diego Inc.">
  <meta name="DC.date" content="` + isoDate + `">
  <meta name="DC.type" content="Dataset">
  <meta name="DC.identifier" content="` + esc(analyzeURL) + `">
  <meta name="DC.relation" content="https://doi.org/10.5281/zenodo.18854899">
  <meta name="citation_title" content="DNS Security Intelligence Report: ` + ed + `">
  <meta name="citation_author" content="IT Help San Diego Inc.">
  <meta name="citation_publication_date" content="` + isoDate + `">
  <meta name="citation_doi" content="10.5281/zenodo.18854899">
  <style>
    :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --dim: #8b949e; --link: #58a6ff; --accent: ` + postureColor + `; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
    .report { max-width: 900px; margin: 0 auto; }
    h1 { font-size: 1.6rem; margin-bottom: .25rem; }
    .subtitle { color: var(--dim); font-size: .9rem; margin-bottom: 2rem; }
    .subtitle a { color: var(--link); text-decoration: none; }
    h2 { font-size: 1.15rem; color: var(--link); margin: 2rem 0 .75rem; padding-bottom: .25rem; border-bottom: 1px solid var(--border); }
    .score-hero { display: flex; align-items: center; gap: 2rem; padding: 1.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 1.5rem; }
    .score-ring { width: 100px; height: 100px; border-radius: 50%; border: 4px solid var(--accent); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .score-ring .num { font-size: 2rem; font-weight: 700; color: var(--accent); }
    .score-details { flex: 1; }
    .score-details .grade { font-size: 1.2rem; font-weight: 600; }
    .score-details .risk { color: var(--dim); font-size: .9rem; margin-top: .25rem; }
    .badge-embed { text-align: center; margin: 1.5rem 0; }
    .badge-embed object { max-width: 100%; height: auto; }
    table { width: 100%; border-collapse: collapse; margin: .5rem 0 1rem; }
    th, td { text-align: left; padding: .5rem .75rem; border: 1px solid var(--border); }
    th { background: var(--surface); color: var(--dim); font-weight: 600; font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; }
    td { font-size: .9rem; }
    .status-pass { color: #3fb950; font-weight: 600; }
    .status-fail { color: #f85149; font-weight: 600; }
    .status-warn { color: #d29922; font-weight: 600; }
    .records-block { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: .5rem 0 1rem; font-family: "SF Mono", "Fira Code", monospace; font-size: .82rem; white-space: pre-wrap; word-break: break-all; color: var(--dim); overflow-x: auto; }
    .subdomain-list { column-count: 2; column-gap: 1.5rem; list-style: none; padding: 0; }
    .subdomain-list li { font-family: monospace; font-size: .85rem; padding: .2rem 0; border-bottom: 1px solid var(--border); }
    .links-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .75rem; margin: .75rem 0; }
    .links-grid a { display: block; padding: .75rem 1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--link); text-decoration: none; font-weight: 600; font-size: .9rem; }
    .links-grid a:hover { border-color: var(--link); }
    .links-grid .desc { color: var(--dim); font-size: .78rem; font-weight: 400; margin-top: .25rem; }
    .provenance { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; font-size: .85rem; margin-top: 1rem; }
    .provenance dt { color: var(--dim); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; margin-top: .5rem; }
    .provenance dd { margin: 0 0 .25rem; }
    .provenance a { color: var(--link); text-decoration: none; }
    @media (max-width: 600px) { .score-hero { flex-direction: column; text-align: center; } .subdomain-list { column-count: 1; } }
  </style>
</head>
<body>
<div class="report">

<h1>DNS Security Intelligence Report</h1>
<p class="subtitle">` + ed + ` · Scanned <time datetime="` + isoTimestamp + `">` + isoDate + `</time> · <a href="` + esc(base) + `">DNS Tool</a> by <a href="https://it-help.tech">IT Help San Diego Inc.</a></p>

<div class="score-hero">
  <div class="score-ring"><span class="num">` + fmt.Sprintf("%d", postureScore) + `</span></div>
  <div class="score-details">
    <div class="grade">` + esc(postureGrade) + `</div>
    <div class="risk">` + esc(postureLabel) + ``)
        if riskLevel != "" && riskLevel != "Unknown" {
                sb.WriteString(` · Risk: ` + esc(riskLevel))
        }
        sb.WriteString(`</div>
  </div>
</div>

<h2>Email Authentication</h2>
<table>
  <tr><th>Control</th><th>Status</th><th>Detail</th></tr>
  <tr><td>SPF</td><td class="` + statusClass(spfStatus) + `">` + esc(spfStatus) + `</td><td>Sender Policy Framework — authorizes mail senders</td></tr>
  <tr><td>DKIM</td><td class="` + statusClass(dkimStatus) + `">` + esc(dkimStatus) + `</td><td>DomainKeys Identified Mail — cryptographic message signing</td></tr>
  <tr><td>DMARC</td><td class="` + statusClass(dmarcStatus) + `">` + esc(dmarcStatus) + `</td><td>Policy: <strong>` + esc(dmarcPolicy) + `</strong></td></tr>
  <tr><td>BIMI</td><td class="` + boolStatusClass(bimiPresent) + `">` + esc(bimiLabel) + `</td><td>Brand Indicators for Message Identification</td></tr>
</table>`)

        if len(spfRecords) > 0 {
                sb.WriteString(`
<h3 style="font-size:.95rem;margin:.75rem 0 .25rem;color:var(--dim)">SPF Records</h3>
<div class="records-block">`)
                for _, r := range spfRecords {
                        sb.WriteString(esc(r) + "\n")
                }
                sb.WriteString(`</div>`)
        }

        if dmarcRaw != "" {
                sb.WriteString(`
<h3 style="font-size:.95rem;margin:.75rem 0 .25rem;color:var(--dim)">DMARC Record</h3>
<div class="records-block">` + esc(dmarcRaw) + `</div>`)
        }

        if len(dkimSelectors) > 0 {
                sb.WriteString(`
<h3 style="font-size:.95rem;margin:.75rem 0 .25rem;color:var(--dim)">DKIM Selectors Discovered</h3>
<div class="records-block">`)
                for _, s := range dkimSelectors {
                        sb.WriteString(esc(s) + "\n")
                }
                sb.WriteString(`</div>`)
        }

        sb.WriteString(`

<h2>Transport Security</h2>
<table>
  <tr><th>Control</th><th>Status</th><th>Detail</th></tr>
  <tr><td>DNSSEC</td><td class="` + statusClass(dnssecStatus) + `">` + esc(dnssecStatus) + `</td><td>DNS Security Extensions — cryptographic record signing</td></tr>
  <tr><td>MTA-STS</td><td class="` + statusClass(mtaSTSMode) + `">` + esc(mtaSTSMode) + `</td><td>Mail Transfer Agent Strict Transport Security</td></tr>
  <tr><td>CAA</td><td class="` + boolStatusClass(caaPresent) + `">` + esc(caaLabel) + `</td><td>Certificate Authority Authorization — controls certificate issuance</td></tr>
</table>`)

        if mtaSTSPolicy != "" {
                sb.WriteString(`
<h3 style="font-size:.95rem;margin:.75rem 0 .25rem;color:var(--dim)">MTA-STS Policy</h3>
<div class="records-block">` + esc(mtaSTSPolicy) + `</div>`)
        }

        sb.WriteString(`

<h2>Infrastructure</h2>
<table>
  <tr><th>Record Type</th><th>Values</th></tr>`)

        if len(aRecords) > 0 {
                sb.WriteString(`
  <tr><td>A Records</td><td>` + esc(strings.Join(aRecords, ", ")) + `</td></tr>`)
        }
        if len(mxRecords) > 0 {
                sb.WriteString(`
  <tr><td>MX Records</td><td>` + esc(strings.Join(mxRecords, ", ")) + `</td></tr>`)
        }
        if len(nsRecords) > 0 {
                sb.WriteString(`
  <tr><td>NS Records</td><td>` + esc(strings.Join(nsRecords, ", ")) + `</td></tr>`)
        }

        sb.WriteString(`
</table>

<h2>Subdomain Discovery</h2>
<p style="color:var(--dim);font-size:.9rem">` + fmt.Sprintf("%d", subCount) + ` subdomain(s) discovered via Certificate Transparency logs.</p>`)

        if len(subdomainList) > 0 {
                sb.WriteString(`
<ul class="subdomain-list">`)
                limit := len(subdomainList)
                if limit > 100 {
                        limit = 100
                }
                for i := 0; i < limit; i++ {
                        sb.WriteString(`<li>` + esc(subdomainList[i]) + `</li>`)
                }
                sb.WriteString(`</ul>`)
                if len(subdomainList) > 100 {
                        sb.WriteString(`<p style="color:var(--dim);font-size:.85rem;margin-top:.5rem">Showing 100 of ` + fmt.Sprintf("%d", len(subdomainList)) + ` subdomains. See the <a href="` + esc(analyzeURL) + `" style="color:var(--link)">full report</a> for all results.</p>`)
                }
        }

        sb.WriteString(`

<h2>Security Badge</h2>
<div class="badge-embed">
  <a href="` + esc(analyzeURL) + `"><object type="image/svg+xml" data="` + esc(badgeDetailed) + `" aria-label="DNS Tool detailed security badge for ` + ed + `">` + ed + ` security badge</object></a>
</div>

<h2>Related Resources</h2>
<div class="links-grid">
  <a href="` + esc(analyzeURL) + `">Full Interactive Report<div class="desc">Live analysis with charts, graphs, and deep-dive panels</div></a>
  <a href="` + esc(snapshotURL) + `">Observed Records Snapshot<div class="desc">Raw DNS records with SHA-3-512 integrity hash</div></a>
  <a href="` + esc(topologyURL) + `">Protocol Topology Map<div class="desc">Animated signal flow and RFC dependency graph</div></a>
  <a href="` + esc(apiURL) + `">Machine-Readable JSON<div class="desc">Structured API response for automation</div></a>
  <a href="` + esc(waybackURL) + `">Wayback Machine Archive<div class="desc">Third-party permanent record via Internet Archive</div></a>
  <a href="https://doi.org/10.5281/zenodo.18854899">Zenodo DOI<div class="desc">Concept DOI for citation and reproducibility</div></a>
</div>

<h2>Provenance</h2>
<dl class="provenance">
  <dt>Tool</dt><dd>DNS Tool by <a href="https://it-help.tech">IT Help San Diego Inc.</a></dd>
  <dt>Version</dt><dd>` + esc(h.Config.AppVersion) + `</dd>
  <dt>Methodology</dt><dd>RFC-grounded analysis with Bayesian confidence scoring</dd>
  <dt>Concept DOI</dt><dd><a href="https://doi.org/10.5281/zenodo.18854899">10.5281/zenodo.18854899</a></dd>
  <dt>License</dt><dd>BUSL-1.1</dd>
  <dt>Timestamp</dt><dd><time datetime="` + isoTimestamp + `">` + isoTimestamp + `</time></dd>
</dl>

</div>
</body>
</html>`)

        return sb.String()
}

func statusClass(s string) string {
        lower := strings.ToLower(s)
        switch {
        case lower == "success" || lower == "signed" || lower == "enforce" || lower == "present":
                return "status-pass"
        case lower == "missing" || lower == "not found" || lower == "unsigned" || lower == "none" || lower == "fail":
                return "status-fail"
        default:
                return "status-warn"
        }
}

func boolStatusClass(present bool) string {
        if present {
                return "status-pass"
        }
        return "status-fail"
}
