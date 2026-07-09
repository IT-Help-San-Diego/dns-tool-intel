// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/icae"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/sha3"
)

func (h *AnalysisHandler) APIDNSHistory(c *gin.Context) {
	domain := strings.TrimSpace(c.Query(mapKeyDomain))
	if domain == "" || !dnsclient.ValidateDomain(domain) {
		c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Invalid domain"})
		return
	}
	asciiDomain, err := dnsclient.DomainToASCII(domain)
	if err != nil {
		asciiDomain = domain
	}

	userAPIKey := strings.TrimSpace(c.GetHeader("X-SecurityTrails-Key"))

	if userAPIKey == "" {
		c.JSON(http.StatusOK, gin.H{mapKeyStatus: "no_key", mapKeyMessage: "SecurityTrails API key required"})
		return
	}

	result := analyzer.FetchDNSHistoryWithKey(c.Request.Context(), asciiDomain, userAPIKey, h.DNSHistoryCache)

	status, sOk := result[mapKeyStatus].(string)
	if !sOk || status == "rate_limited" || status == mapKeyError || status == "timeout" {
		c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
		return
	}

	available, aOk := result["available"].(bool)
	if !aOk || !available {
		c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) APISubdomains(c *gin.Context) {
	domain := strings.TrimPrefix(c.Param(mapKeyDomain), "/")
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Domain is required"})
		return
	}
	if !dnsclient.ValidateDomain(domain) {
		c.JSON(http.StatusBadRequest, gin.H{mapKeyStatus: mapKeyError, mapKeyMessage: "Invalid domain"})
		return
	}
	result := h.Analyzer.DiscoverSubdomains(c.Request.Context(), domain)
	c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) ExportSubdomainsCSV(c *gin.Context) {
	domain := strings.TrimSpace(strings.ToLower(c.Query(mapKeyDomain)))
	if domain == "" {
		c.Redirect(http.StatusFound, "/")
		return
	}
	if !dnsclient.ValidateDomain(domain) {
		c.Redirect(http.StatusFound, "/")
		return
	}

	cached, ok := h.Analyzer.GetCTCache(domain)
	if !ok || len(cached) == 0 {
		c.Redirect(http.StatusFound, "/analyze?domain="+domain)
		return
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	filename := fmt.Sprintf("%s_subdomains_%s.csv", strings.ReplaceAll(domain, ".", "_"), timestamp)

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header(headerContentDisposition, fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Status(http.StatusOK)

	w := c.Writer
	w.WriteString("Subdomain,Status,Source,CNAME Target,Provider,Certificates,First Seen,Issuers\n")

	for _, sd := range cached {
		name, _ := sd["name"].(string) //nolint:errcheck // type assertion with zero-value fallback
		sdStatus := "Expired"
		if isCur, ok := sd["is_current"].(bool); ok && isCur {
			sdStatus = "Current"
		}
		source, _ := sd["source"].(string)            //nolint:errcheck // type assertion with zero-value fallback
		cnameTarget, _ := sd["cname_target"].(string) //nolint:errcheck // type assertion with zero-value fallback
		provider, _ := sd["provider"].(string)        //nolint:errcheck // type assertion with zero-value fallback
		certCount, _ := sd["cert_count"].(string)     //nolint:errcheck // type assertion with zero-value fallback
		firstSeen, _ := sd["first_seen"].(string)     //nolint:errcheck // type assertion with zero-value fallback

		var issuerStr string
		if issuers, ok := sd["issuers"].([]string); ok && len(issuers) > 0 {
			issuerStr = strings.Join(issuers, "; ")
		}

		w.WriteString(csvEscape(name) + "," +
			csvEscape(sdStatus) + "," +
			csvEscape(source) + "," +
			csvEscape(cnameTarget) + "," +
			csvEscape(provider) + "," +
			csvEscape(certCount) + "," +
			csvEscape(firstSeen) + "," +
			csvEscape(issuerStr) + "\n")
	}
	w.Flush()
}

func csvEscape(s string) string {
	if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func unmarshalRawJSON(raw json.RawMessage, domain, label string) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var result interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		slog.Warn("buildAnalysisJSON: failed to unmarshal "+label, "domain", domain, mapKeyError, err)
	}
	return result
}

func extractCurrencyFromResults(fullResults interface{}) interface{} {
	frMap, ok := fullResults.(map[string]interface{})
	if !ok {
		return nil
	}
	cr, exists := frMap[mapKeyCurrencyReport]
	if !exists {
		return nil
	}
	return cr
}

func (h *AnalysisHandler) buildAnalysisJSON(ctx context.Context, analysis dbq.DomainAnalysis) ([]byte, string) {
	fullResults := unmarshalRawJSON(analysis.FullResults, analysis.Domain, "full results")
	ctSubdomains := unmarshalRawJSON(analysis.CtSubdomains, analysis.Domain, "ct subdomains")
	currencyReport := extractCurrencyFromResults(fullResults)

	provenance := map[string]interface{}{
		"tool_version":       h.Config.AppVersion,
		"hash_algorithm":     "SHA-3-512",
		"hash_standard":      "NIST FIPS 202 (Keccak)",
		"export_timestamp":   time.Now().UTC().Format(time.RFC3339),
		"analysis_timestamp": formatTimestampISO(analysis.CreatedAt),
		"engines": map[string]interface{}{
			"icae": map[string]string{
				"name":         "Intelligence Confidence Audit Engine",
				"purpose":      "Correctness verification via deterministic test cases",
				mapKeyStandard: "ICD 203 Analytic Standards",
			},
			"icuae": map[string]string{
				"name":         "Intelligence Currency Audit Engine",
				"purpose":      "Data timeliness and validity measurement",
				mapKeyStandard: "ICD 203, NIST SP 800-53 SI-7, ISO/IEC 25012, RFC 8767",
			},
		},
	}
	if currencyReport != nil {
		provenance[mapKeyCurrencyReport] = currencyReport
	}
	if q := h.rawQueries(); q != nil {
		if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
			provenance["icae_summary"] = map[string]interface{}{
				"maturity":        icaeMetrics.OverallMaturity,
				"pass_rate":       icaeMetrics.PassRate,
				"total_cases":     icaeMetrics.TotalAllCases,
				"total_passes":    icaeMetrics.TotalPasses,
				"total_runs":      icaeMetrics.TotalRuns,
				"days_running":    icaeMetrics.DaysRunning,
				"protocols_count": icaeMetrics.TotalProtocols,
			}
		}
	}

	citationManifest := buildCitationManifestFromResults(analysis.FullResults)

	payload := map[string]interface{}{
		"analysis_duration": analysis.AnalysisDuration,
		"analysis_success":  analysis.AnalysisSuccess,
		"ascii_domain":      analysis.AsciiDomain,
		"citation_manifest": citationManifest,
		"country_code":      analysis.CountryCode,
		"country_name":      analysis.CountryName,
		"created_at":        formatTimestampISO(analysis.CreatedAt),
		"ct_subdomains":     ctSubdomains,
		"dkim_status":       analysis.DkimStatus,
		"dmarc_policy":      analysis.DmarcPolicy,
		"dmarc_status":      analysis.DmarcStatus,
		mapKeyDomain:        analysis.Domain,
		"error_message":     analysis.ErrorMessage,
		"full_results":      fullResults,
		"id":                analysis.ID,
		"provenance":        provenance,
		"registrar_name":    analysis.RegistrarName,
		"registrar_source":  analysis.RegistrarSource,
		"spf_status":        analysis.SpfStatus,
		"updated_at":        formatTimestampISO(analysis.UpdatedAt),
	}

	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	orderedPayload := make([]orderedKV, len(keys))
	for i, k := range keys {
		orderedPayload[i] = orderedKV{Key: k, Value: payload[k]}
	}

	buf := marshalOrderedJSON(orderedPayload)
	buf = append(buf, '\n')

	hash := sha3.Sum512(buf)
	return buf, hex.EncodeToString(hash[:])
}

type orderedKV struct {
	Key   string
	Value interface{}
}

func marshalOrderedJSON(entries []orderedKV) []byte {
	buf := []byte("{")
	for i, kv := range entries {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyBytes, kErr := json.Marshal(kv.Key)
		if kErr != nil {
			slog.Debug("marshal key error", "key", kv.Key, "error", kErr)
			continue
		}
		valBytes, vErr := json.Marshal(kv.Value)
		if vErr != nil {
			slog.Debug("marshal value error", "key", kv.Key, "error", vErr)
			continue
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf
}

func (h *AnalysisHandler) loadAnalysisForAPI(c *gin.Context) (dbq.DomainAnalysis, bool) {
	idStr := c.Param("id")
	analysisID, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{mapKeyError: errMsgInvalidAnalysisID})
		return dbq.DomainAnalysis{}, false
	}

	ctx := c.Request.Context()
	analysis, err := h.store().GetAnalysisByID(ctx, int32(analysisID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{mapKeyError: strAnalysisNotFound})
		return dbq.DomainAnalysis{}, false
	}

	if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
		auth, authOk := c.Get(mapKeyAuthenticated)
		if authOk && auth == true {
			c.JSON(http.StatusForbidden, gin.H{
				mapKeyError:   "restricted",
				mapKeyMessage: "This report includes user-provided intelligence and is restricted to its owner. Custom selectors can reveal internal mail infrastructure and vendor relationships.",
			})
		} else {
			c.JSON(http.StatusNotFound, gin.H{mapKeyError: strAnalysisNotFound})
		}
		return dbq.DomainAnalysis{}, false
	}

	return analysis, true
}

func (h *AnalysisHandler) APIAnalysis(c *gin.Context) {
	// Strict whitelist on the download query parameter. Historically this
	// was a boolean flag (== "1"), but Qualys WAS QID 150743 flagged the
	// endpoint as a possible SSRF sink because it accepted arbitrary
	// values without validation. Reject anything other than empty or "1"
	// with HTTP 400 to make the contract explicit and silence the scan.
	// Validated BEFORE loadAnalysisForAPI / buildAnalysisJSON so attacker
	// payloads never trigger any DB or hash work.
	dl := c.Query("download")
	if dl != "" && dl != "1" {
		c.JSON(http.StatusBadRequest, gin.H{mapKeyError: "invalid download parameter"})
		return
	}

	analysis, ok := h.loadAnalysisForAPI(c)
	if !ok {
		return
	}

	jsonBytes, fileHash := h.buildAnalysisJSON(c.Request.Context(), analysis)
	filename := fmt.Sprintf("dns-intelligence-%s.json", analysis.AsciiDomain)

	if dl == "1" || c.Request.Header.Get("Accept") == "application/octet-stream" {
		c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="%s"`, filename))
	}
	c.Header("X-SHA3-512", fileHash)
	c.Data(http.StatusOK, "application/json; charset=utf-8", jsonBytes)
}

func (h *AnalysisHandler) APIAnalysisChecksum(c *gin.Context) {
	analysis, ok := h.loadAnalysisForAPI(c)
	if !ok {
		return
	}

	_, fileHash := h.buildAnalysisJSON(c.Request.Context(), analysis)
	filename := fmt.Sprintf("dns-intelligence-%s.json", analysis.AsciiDomain)

	format := c.Query("format")
	if format == "sha3" {
		sha3Filename := fmt.Sprintf("dns-intelligence-%s.json.sha3", analysis.AsciiDomain)
		c.Header(headerContentDisposition, fmt.Sprintf(`attachment; filename="%s"`, sha3Filename))
		var sb strings.Builder
		sb.WriteString("# DNS Tool — SHA-3-512 Integrity Checksum\n")
		sb.WriteString("#\n")
		sb.WriteString("# Cause I'm a hacker, baby, I'm gonna pwn you good,\n")
		sb.WriteString("# Diff your zone to the spec like you knew I would.\n")
		sb.WriteString("# Cite those RFCs, baby, so my argument stood,\n")
		sb.WriteString("# Standards over swagger — that's understood.\n")
		sb.WriteString("#\n")
		sb.WriteString("# — DNS Tool / If it's not in RFC 1034, it ain't understood.\n")
		sb.WriteString("#\n")
		sb.WriteString("# 'Hacker' per RFC 1392 (IETF Internet Users' Glossary, 1993):\n")
		sb.WriteString("# 'A person who delights in having an intimate understanding of the\n")
		sb.WriteString("#  internal workings of a system, computers and computer networks\n")
		sb.WriteString("#  in particular.' That's us. That's always been us.\n")
		sb.WriteString("#\n")
		sb.WriteString("# Algorithm: SHA-3-512 (Keccak, NIST FIPS 202)\n")
		sb.WriteString("# Verify:   openssl dgst -sha3-512 " + filename + "\n")
		sb.WriteString("#\n")
		sb.WriteString("# Provenance:\n")
		sb.WriteString(fmt.Sprintf("#   Analysis ID:   %d\n", analysis.ID))
		sb.WriteString(fmt.Sprintf("#   Report URL:    %s/analysis/%d/view\n", h.Config.BaseURL, analysis.ID))
		sb.WriteString(fmt.Sprintf("#   Tool Version:  %s\n", h.Config.AppVersion))
		sb.WriteString(fmt.Sprintf("#   Export Time:    %s\n", time.Now().UTC().Format(time.RFC3339)))
		sb.WriteString("#   Engines:        ICAE (Confidence) + ICuAE (Currency)\n")
		sb.WriteString("#   Standards:       ICD 203, NIST SP 800-53 SI-7, ISO/IEC 25012\n")
		sb.WriteString("#\n")
		sb.WriteString(fmt.Sprintf("%s  %s\n", fileHash, filename))
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(sb.String()))
		return
	}

	checksumResponse := gin.H{
		"algorithm":    "SHA-3-512",
		mapKeyStandard: "NIST FIPS 202 (Keccak)",
		"hash":         fileHash,
		"filename":     filename,
		"provenance": gin.H{
			"analysis_id":      analysis.ID,
			"report_url":       fmt.Sprintf("%s/analysis/%d/view", h.Config.BaseURL, analysis.ID),
			"tool_version":     h.Config.AppVersion,
			"export_timestamp": time.Now().UTC().Format(time.RFC3339),
			"engines":          []string{"ICAE (Confidence)", "ICuAE (Currency)"},
			"standards":        []string{"ICD 203", "NIST SP 800-53 SI-7", "ISO/IEC 25012", "RFC 8767"},
		},
		"verify_commands": map[string]string{
			"openssl": fmt.Sprintf("openssl dgst -sha3-512 %s", filename),
			"python":  fmt.Sprintf("python3 -c \"import hashlib; print(hashlib.sha3_512(open('%s','rb').read()).hexdigest())\"", filename),
			"sha3sum": fmt.Sprintf("sha3sum -a 512 %s", filename),
		},
	}
	c.JSON(http.StatusOK, checksumResponse)
}

func (h *AnalysisHandler) ViewCrossReference(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	idStr := c.Param("id")
	analysisID, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil {
		h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, mapKeyDanger, errMsgInvalidAnalysisID)
		return
	}

	ctx := c.Request.Context()
	analysis, err := h.store().GetAnalysisByID(ctx, int32(analysisID))
	if err != nil {
		h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyDanger, strAnalysisNotFound)
		return
	}

	if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
		h.renderRestrictedAccess(c, nonce, csrfToken)
		return
	}

	results := NormalizeResults(analysis.FullResults)
	if results == nil {
		h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, mapKeyDanger, errMsgFailedToParseResults)
		return
	}

	crossRef, _ := results["cross_reference"].(map[string]any)

	viewData := NewTemplateData(c, h.Config, "")
	viewData["Domain"] = analysis.Domain
	viewData["AsciiDomain"] = analysis.AsciiDomain
	viewData["AnalysisID"] = analysis.ID
	viewData["CrossRef"] = crossRef
	viewData["HasCrossRef"] = crossRef != nil && len(crossRef) > 0

	c.HTML(http.StatusOK, "analysis_crossref.html", viewData)
}

func (h *AnalysisHandler) APICrossReference(c *gin.Context) {
	analysis, ok := h.loadAnalysisForAPI(c)
	if !ok {
		return
	}

	results := NormalizeResults(analysis.FullResults)
	if results == nil {
		c.JSON(http.StatusInternalServerError, gin.H{mapKeyError: errMsgFailedToParseResults})
		return
	}

	crossRef, _ := results["cross_reference"].(map[string]any)
	if crossRef == nil {
		c.JSON(http.StatusNotFound, gin.H{mapKeyError: "Cross-reference data not available for this analysis. The domain may have been analyzed before this feature was introduced."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"analysis_id":     analysis.ID,
		"domain":          analysis.Domain,
		"cross_reference": crossRef,
	})
}
