// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/icae"
	"dnstool/go-server/internal/icuae"
	"dnstool/go-server/internal/unified"

	"github.com/gin-gonic/gin"
)

// resolveReportMode returns the report mode for the request, or "" when an
// explicit :mode param is not a known mode. Unknown modes must not render
// (the pre-2026-07-24 fallback to "E" made every junk suffix like
// /view/null a distinct 200 page, multiplying the crawlable URL space).
func resolveReportMode(c *gin.Context) string {
	if mode := c.Param("mode"); mode != "" {
		switch strings.ToUpper(mode) {
		case "E":
			return "E"
		case "C":
			return "C"
		case "CZ":
			return "CZ"
		case "Z":
			return "Z"
		case "EC":
			return "EC"
		case "B":
			return "B"
		default:
			return ""
		}
	}
	if c.Query(mapKeyCovert) == "1" {
		return "C"
	}
	return "E"
}

func reportModeTemplate(mode string) string {
	switch mode {
	case "C", "CZ":
		return "results_covert.html"
	case "B":
		return "results_executive.html"
	default:
		return "results.html"
	}
}

func isCovertMode(mode string) bool {
	return mode == "C" || mode == "CZ" || mode == "EC"
}

func (h *AnalysisHandler) ViewAnalysisStatic(c *gin.Context) {
	mode := resolveReportMode(c)
	if mode == "" {
		if id, err := strconv.ParseInt(c.Param("id"), 10, 32); err == nil {
			c.Redirect(http.StatusMovedPermanently, "/analysis/"+strconv.FormatInt(id, 10)+"/view")
			return
		}
		mode = "E"
	}
	h.viewAnalysisWithMode(c, mode)
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
	h.viewAnalysisWithMode(c, resolveReportMode(c))
}

func (h *AnalysisHandler) ViewAnalysisExecutive(c *gin.Context) {
	h.viewAnalysisWithMode(c, "B")
}

func (h *AnalysisHandler) viewAnalysisWithMode(c *gin.Context, mode string) {
	nonce, ok := c.Get("csp_nonce")
	if !ok {
		nonce = ""
	}
	csrfToken, ok := c.Get("csrf_token")
	if !ok {
		csrfToken = ""
	}
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

	if len(analysis.FullResults) == 0 || string(analysis.FullResults) == "null" {
		h.renderErrorPage(c, http.StatusGone, nonce, csrfToken, mapKeyWarning, "This report is no longer available. Please re-analyze the domain.")
		return
	}

	results := NormalizeResults(analysis.FullResults)
	if results == nil {
		h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, mapKeyDanger, errMsgFailedToParseResults)
		return
	}

	if dnsclient.IsTLDInput(analysis.AsciiDomain) {
		if mode == "E" {
			mode = "Z"
		} else if mode == "C" {
			mode = "CZ"
		}
	}

	waitSeconds, err2 := strconv.Atoi(c.Query("wait_seconds"))
	if err2 != nil {
		waitSeconds = 0
	}
	waitReason := c.Query("wait_reason")

	timestamp := analysisTimestamp(analysis)
	dur := analysisDuration(analysis)
	toolVersion := extractToolVersion(results)
	verifyCommands := analyzer.GenerateVerificationCommands(analysis.AsciiDomain, results)
	integrityHash := computeIntegrityHash(analysis, timestamp, toolVersion, h.Config.AppVersion, results)
	rfcCount := analyzer.CountVerifiedStandards(results)
	currentHash := derefString(analysis.PostureHash)
	drift := h.detectHistoricalDrift(ctx, currentHash, analysis.Domain, analysis.ID, results)
	isSub, rootDom := extractRootDomain(analysis.AsciiDomain)
	emailScope := h.resolveEmailScope(ctx, isSub, rootDom, analysis.AsciiDomain, results)

	viewData := NewTemplateData(c, h.Config, "")
	viewData["Domain"] = analysis.Domain
	viewData["AsciiDomain"] = analysis.AsciiDomain
	viewData["Results"] = results
	viewData["AnalysisID"] = analysis.ID
	viewData["AnalysisDuration"] = dur
	viewData["AnalysisTimestamp"] = timestamp
	viewData["FromHistory"] = true
	viewData["WaitSeconds"] = waitSeconds
	viewData["WaitReason"] = waitReason
	viewData["DomainExists"] = resultsDomainExists(results)
	viewData["ToolVersion"] = toolVersion
	viewData["VerificationCommands"] = verifyCommands
	viewData["IsSubdomain"] = isSub
	viewData["RootDomain"] = rootDom
	viewData["SecurityTrailsKey"] = ""
	viewData["IntegrityHash"] = integrityHash
	viewData["RFCCount"] = rfcCount
	viewData["SectionTuning"] = h.Config.SectionTuning
	viewData["PostureHash"] = currentHash
	viewData["DriftDetected"] = drift.Detected
	viewData["DriftPrevHash"] = drift.PrevHash
	viewData["DriftPrevTime"] = drift.PrevTime
	viewData["DriftPrevID"] = drift.PrevID
	viewData["DriftFields"] = drift.Fields
	viewData["IsPublicSuffix"] = isPublicSuffixDomain(analysis.AsciiDomain)
	viewData["IsTLD"] = dnsclient.IsTLDInput(analysis.AsciiDomain)
	viewData["SubdomainEmailScope"] = emailScope
	viewData["ReportMode"] = mode
	viewData["WaybackURL"] = derefString(analysis.WaybackUrl)
	h.enrichViewDataMetrics(ctx, viewData, results, analysis.Domain, analysis.ID)
	viewData["CovertMode"] = isCovertMode(mode)

	c.HTML(http.StatusOK, reportModeTemplate(mode), viewData)
}

func resolveCovertMode(c *gin.Context, asciiDomain string) string {
	covert := c.PostForm(mapKeyCovert) == "1" || c.Query(mapKeyCovert) == "1"
	isTLD := dnsclient.IsTLDInput(asciiDomain)
	if covert && isTLD {
		return "CZ"
	}
	if covert {
		return "C"
	}
	if isTLD {
		return "Z"
	}
	return "E"
}

func (h *AnalysisHandler) enrichViewDataMetrics(ctx context.Context, data gin.H, results map[string]any, domain string, analysisID int32) {
	if snap, ok := results["_icae_snapshot"].(map[string]any); ok {
		h.enrichFromSnapshot(ctx, data, results, snap, domain, analysisID)
		return
	}

	var maturityLevel string
	if q := h.rawQueries(); q != nil {
		if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
			data["ICAEMetrics"] = icaeMetrics
			maturityLevel = icaeMetrics.OverallMaturity
		}
	}
	var currencyScore float64
	if cr, ok := results[mapKeyCurrencyReport]; ok {
		if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
			data["CurrencyReport"] = report
			currencyScore = report.OverallScore
		}
	}

	calibrated, cOk := results["calibrated_confidence"].(map[string]float64)
	if cOk && calibrated != nil && maturityLevel != "" {
		uc := unified.ComputeUnifiedConfidence(unified.Input{
			CalibratedConfidence: calibrated,
			CurrencyScore:        currencyScore,
			MaturityLevel:        maturityLevel,
		})
		data["UnifiedConfidence"] = uc
	}

	if analysisID > 0 {
		if q := h.rawQueries(); q != nil {
			if sugConfig := buildSuggestedConfig(ctx, q, domain, analysisID); sugConfig != nil {
				data["SuggestedConfig"] = sugConfig
			}
		}
	}
}

func (h *AnalysisHandler) enrichFromSnapshot(ctx context.Context, data gin.H, results map[string]any, snap map[string]any, domain string, analysisID int32) {
	h.enrichICAEFromSnapshot(ctx, data, snap)
	enrichCurrencyReport(data, results)
	enrichUnifiedConfidence(data, snap)
	h.enrichSuggestedConfig(ctx, data, domain, analysisID)
}

func (h *AnalysisHandler) enrichICAEFromSnapshot(ctx context.Context, data gin.H, snap map[string]any) {
	q := h.rawQueries()
	if q == nil {
		return
	}
	icaeMetrics := icae.LoadReportMetrics(ctx, q)
	if icaeMetrics == nil {
		return
	}
	snappedMaturity, _ := snap["overall_maturity"].(string) //nolint:errcheck // zero-value fallback is intentional
	if snappedMaturity != "" {
		icaeMetrics.OverallMaturity = snappedMaturity
		icaeMetrics.OverallMaturityDisplay = snappedMaturity
	}
	data["ICAEMetrics"] = icaeMetrics
}

func enrichCurrencyReport(data gin.H, results map[string]any) {
	cr, ok := results[mapKeyCurrencyReport]
	if !ok {
		return
	}
	if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
		data["CurrencyReport"] = report
	}
}

func enrichUnifiedConfidence(data gin.H, snap map[string]any) {
	uc, ok := snap["unified_confidence"]
	if !ok {
		return
	}
	if ucMap, valid := uc.(map[string]any); valid {
		data["UnifiedConfidence"] = restoreUnifiedConfidence(ucMap)
	}
}

func (h *AnalysisHandler) enrichSuggestedConfig(ctx context.Context, data gin.H, domain string, analysisID int32) {
	if analysisID <= 0 {
		return
	}
	q := h.rawQueries()
	if q == nil {
		return
	}
	if sugConfig := buildSuggestedConfig(ctx, q, domain, analysisID); sugConfig != nil {
		data["SuggestedConfig"] = sugConfig
	}
}

func restoreUnifiedConfidence(m map[string]any) unified.UnifiedConfidence {
	uc := unified.UnifiedConfidence{}
	if v, ok := m["level"].(string); ok {
		uc.Level = v
	}
	if v, ok := m["score"].(float64); ok {
		uc.Score = v
	}
	if v, ok := m["accuracy_factor"].(float64); ok {
		uc.AccuracyFactor = v
	}
	if v, ok := m["currency_factor"].(float64); ok {
		uc.CurrencyFactor = v
	}
	if v, ok := m["maturity_ceiling"].(float64); ok {
		uc.MaturityCeiling = v
	}
	if v, ok := m["maturity_level"].(string); ok {
		uc.MaturityLevel = v
	}
	if v, ok := m["weakest_link"].(string); ok {
		uc.WeakestLink = v
	}
	if v, ok := m["weakest_detail"].(string); ok {
		uc.WeakestDetail = v
	}
	if v, ok := m["explanation"].(string); ok {
		uc.Explanation = v
	}
	if v, ok := m["protocol_count"].(float64); ok {
		uc.ProtocolCount = int(v)
	}
	return uc
}

func (h *AnalysisHandler) snapshotICAEMetrics(ctx context.Context, results map[string]any) {
	snapshot := map[string]any{}

	if q := h.rawQueries(); q != nil {
		if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
			snapshot["overall_maturity"] = icaeMetrics.OverallMaturity
		}
	}

	var currencyScore float64
	if cr, ok := results[mapKeyCurrencyReport]; ok {
		if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
			currencyScore = report.OverallScore
		}
	}

	calibrated, calOk := results["calibrated_confidence"].(map[string]float64)
	maturityLevel, matOk := snapshot["overall_maturity"].(string)
	if calOk && calibrated != nil && matOk && maturityLevel != "" {
		uc := unified.ComputeUnifiedConfidence(unified.Input{
			CalibratedConfidence: calibrated,
			CurrencyScore:        currencyScore,
			MaturityLevel:        maturityLevel,
		})
		snapshot["unified_confidence"] = map[string]any{
			"level":            uc.Level,
			"score":            uc.Score,
			"accuracy_factor":  uc.AccuracyFactor,
			"currency_factor":  uc.CurrencyFactor,
			"maturity_ceiling": uc.MaturityCeiling,
			"maturity_level":   uc.MaturityLevel,
			"weakest_link":     uc.WeakestLink,
			"weakest_detail":   uc.WeakestDetail,
			"explanation":      uc.Explanation,
			"protocol_count":   uc.ProtocolCount,
		}
	}

	results["_icae_snapshot"] = snapshot
}

func analysisTimestamp(analysis dbq.DomainAnalysis) string {
	ts := formatTimestamp(analysis.CreatedAt)
	if analysis.UpdatedAt.Valid {
		ts = formatTimestamp(analysis.UpdatedAt)
	}
	return ts
}

func analysisDuration(analysis dbq.DomainAnalysis) float64 {
	if analysis.AnalysisDuration != nil {
		return *analysis.AnalysisDuration
	}
	return 0.0
}

func computeIntegrityHash(analysis dbq.DomainAnalysis, timestamp, toolVersion, appVersion string, results map[string]any) string {
	hashVersion := toolVersion
	if hashVersion == "" {
		hashVersion = appVersion
	}
	return analyzer.ReportIntegrityHash(analysis.AsciiDomain, analysis.ID, timestamp, hashVersion, results)
}

func (h *AnalysisHandler) resolveEmailScope(ctx context.Context, isSub bool, rootDom, asciiDomain string, results map[string]any) *subdomainEmailScope {
	if !isSub || rootDom == "" {
		return nil
	}
	es := computeSubdomainEmailScope(ctx, h.Analyzer.DNS, asciiDomain, rootDom, results)
	return &es
}

type viewDataInput struct {
	domain, asciiDomain string
	results             map[string]any
	analysisID          int32
	analysisDuration    float64
	timestamp           string
	postureHash         string
	drift               driftInfo
	exposureChecks      bool
	ephemeral           bool
	devNull             bool
	isPrivate           bool
}

func (h *AnalysisHandler) buildAnalyzeViewData(c *gin.Context, v viewDataInput) gin.H {
	ctx := c.Request.Context()
	verifyCommands := analyzer.GenerateVerificationCommands(v.asciiDomain, v.results)
	integrityHash := analyzer.ReportIntegrityHash(v.asciiDomain, v.analysisID, v.timestamp, h.Config.AppVersion, v.results)
	rfcCount := analyzer.CountVerifiedStandards(v.results)

	isSub, rootDom := extractRootDomain(v.asciiDomain)
	emailScope := h.resolveEmailScope(ctx, isSub, rootDom, v.asciiDomain, v.results)

	analyzeData := NewTemplateData(c, h.Config, "")
	analyzeData["Domain"] = v.domain
	analyzeData["AsciiDomain"] = v.asciiDomain
	analyzeData["Results"] = v.results
	analyzeData["AnalysisID"] = v.analysisID
	analyzeData["AnalysisDuration"] = v.analysisDuration
	analyzeData["AnalysisTimestamp"] = v.timestamp
	analyzeData["FromHistory"] = false
	analyzeData["FromCache"] = false
	analyzeData["DomainExists"] = resultsDomainExists(v.results)
	analyzeData["ToolVersion"] = h.Config.AppVersion
	analyzeData["VerificationCommands"] = verifyCommands
	analyzeData["IsSubdomain"] = isSub
	analyzeData["RootDomain"] = rootDom
	analyzeData["SecurityTrailsKey"] = ""
	analyzeData["IntegrityHash"] = integrityHash
	analyzeData["RFCCount"] = rfcCount
	analyzeData["ExposureChecks"] = v.exposureChecks
	analyzeData["SectionTuning"] = h.Config.SectionTuning
	analyzeData["PostureHash"] = v.postureHash
	analyzeData["DriftDetected"] = v.drift.Detected
	analyzeData["DriftPrevHash"] = v.drift.PrevHash
	analyzeData["DriftPrevTime"] = v.drift.PrevTime
	analyzeData["DriftPrevID"] = v.drift.PrevID
	analyzeData["DriftFields"] = v.drift.Fields
	analyzeData["Ephemeral"] = v.ephemeral
	analyzeData["DevNull"] = v.devNull
	analyzeData["IsPrivateReport"] = v.isPrivate
	analyzeData["IsPublicSuffix"] = isPublicSuffixDomain(v.asciiDomain)
	analyzeData["IsTLD"] = dnsclient.IsTLDInput(v.asciiDomain)
	analyzeData["SubdomainEmailScope"] = emailScope
	analyzeData["WaybackURL"] = ""
	if q := h.rawQueries(); q != nil {
		if icaeMetrics := icae.LoadReportMetrics(ctx, q); icaeMetrics != nil {
			analyzeData["ICAEMetrics"] = icaeMetrics
		}
	}
	if cr, ok := v.results[mapKeyCurrencyReport]; ok {
		if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
			analyzeData["CurrencyReport"] = report
		}
	}
	return analyzeData
}

func (h *AnalysisHandler) indexFlashData(c *gin.Context, nonce, csrfToken any, category, message string) gin.H {
	data := NewTemplateData(c, h.Config, "home")
	data["BaseURL"] = h.Config.BaseURL
	data["FlashMessages"] = []FlashMessage{{Category: category, Message: message}}
	return data
}

func (h *AnalysisHandler) renderRestrictedAccess(c *gin.Context, nonce, csrfToken any) {
	auth, authExists := c.Get(mapKeyAuthenticated)
	if !authExists || auth != true {
		h.renderErrorPage(c, http.StatusNotFound, nonce, csrfToken, mapKeyDanger, strAnalysisNotFound)
		return
	}
	msg := "This report includes user-provided intelligence and is restricted to its owner. " +
		"Custom selectors can reveal internal mail infrastructure and vendor relationships — " +
		"responsible intelligence handling means sharing only with trusted parties. " +
		"If you should have access, request it from the report owner."
	c.HTML(http.StatusForbidden, templateIndex, h.indexFlashData(c, nonce, csrfToken, mapKeyWarning, msg))
}

func (h *AnalysisHandler) renderErrorPage(c *gin.Context, status int, nonce, csrfToken any, category, message string) {
	c.HTML(status, templateIndex, h.indexFlashData(c, nonce, csrfToken, category, message))
}

func extractToolVersion(results map[string]any) string {
	if tv, ok := results["_tool_version"].(string); ok {
		return tv
	}
	return ""
}

func (h *AnalysisHandler) renderIndexFlash(c *gin.Context, nonce, csrfToken any, category, message string) {
	c.HTML(http.StatusOK, templateIndex, h.indexFlashData(c, nonce, csrfToken, category, message))
}

func (h *AnalysisHandler) enrichResultsNoHistory(_ *gin.Context, _ string, results map[string]any) {
	h.enrichResultsAsync(results)
}

func (h *AnalysisHandler) enrichResultsAsync(results map[string]any) {
	if rem, ok := results["remediation"].(map[string]any); ok {
		results["remediation"] = analyzer.EnrichRemediationWithRFCMeta(rem)
	}

	results["rfc_metadata"] = analyzer.GetAllRFCMetadata()
}

func extractReportsAndDurations(analyses []dbq.DomainAnalysis) ([]icuae.CurrencyReport, []float64) {
	var reports []icuae.CurrencyReport
	var durations []float64
	for _, ha := range analyses {
		if len(ha.FullResults) == 0 {
			continue
		}
		var fr map[string]any
		if json.Unmarshal(ha.FullResults, &fr) != nil {
			continue
		}
		if cr, ok := fr[mapKeyCurrencyReport]; ok {
			if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
				reports = append(reports, report)
			}
		}
		if ha.AnalysisDuration != nil {
			durations = append(durations, *ha.AnalysisDuration*1000)
		}
	}
	return reports, durations
}

func buildSuggestedConfig(ctx context.Context, queries *dbq.Queries, domain string, currentID int32) *icuae.SuggestedConfig {
	historicalAnalyses, err := queries.ListAnalysesByDomain(ctx, dbq.ListAnalysesByDomainParams{
		Domain: domain,
		Limit:  20,
	})
	if err != nil || len(historicalAnalyses) < 3 {
		return nil
	}

	reports, durations := extractReportsAndDurations(historicalAnalyses)

	if len(reports) < 3 {
		return nil
	}

	stats := icuae.BuildRollingStats(reports, durations)
	config := icuae.GenerateSuggestedConfig(stats, icuae.DefaultProfile)
	config.BasedOn = len(reports)
	return &config
}
