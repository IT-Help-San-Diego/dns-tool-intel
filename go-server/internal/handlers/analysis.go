// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
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
        "sync"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/icae"
        "dnstool/go-server/internal/icuae"
        "dnstool/go-server/internal/scanner"
        "dnstool/go-server/internal/unified"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/sha3"
)

const (
        templateIndex            = "index.html"
        headerContentDisposition = "Content-Disposition"


        mapKeyAuthenticated = "authenticated"
        mapKeyCovert = "covert"
        mapKeyCritical = "critical"
        mapKeyCurrencyReport = "currency_report"
        mapKeyDanger = "danger"
        mapKeyDkimAnalysis = "dkim_analysis"
        mapKeyDmarcAnalysis = "dmarc_analysis"
        mapKeyDomain = "domain"
        mapKeyMessage = "message"
        mapKeySpfAnalysis = "spf_analysis"
        mapKeyStandard = "standard"
        mapKeyStatus = "status"
        mapKeyWarning = "warning"
        strAnalysisNotFound = "Analysis not found"
        strUtc = "2006-01-02 15:04:05 UTC"
)

type AnalysisHandler struct {
        DB              *db.Database
        Config          *config.Config
        Analyzer        *analyzer.Analyzer
        DNSHistoryCache *analyzer.DNSHistoryCache
        Calibration     *icae.CalibrationEngine
        DimCharts       *icuae.DimensionCharts
}

func NewAnalysisHandler(database *db.Database, cfg *config.Config, a *analyzer.Analyzer, historyCache *analyzer.DNSHistoryCache) *AnalysisHandler {
        return &AnalysisHandler{
                DB:              database,
                Config:          cfg,
                Analyzer:        a,
                DNSHistoryCache: historyCache,
                Calibration:     icae.NewCalibrationEngine(),
                DimCharts:       icuae.NewDimensionCharts(),
        }
}

func (h *AnalysisHandler) checkPrivateAccess(c *gin.Context, analysisID int32, private bool) bool {
        if !private {
                return true
        }
        auth, exists := c.Get(mapKeyAuthenticated)
        if !exists || auth != true {
                return false
        }
        uid, ok := c.Get(mapKeyUserId)
        if !ok {
                return false
        }
        userID, ok := uid.(int32)
        if !ok {
                return false
        }
        isOwner, err := h.DB.Queries.CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
                AnalysisID: analysisID,
                UserID:     userID,
        })
        return err == nil && isOwner
}

func resolveReportMode(c *gin.Context) string {
        if mode := c.Param("mode"); mode != "" {
                switch strings.ToUpper(mode) {
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
                        return "E"
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
        h.viewAnalysisWithMode(c, resolveReportMode(c))
}

func (h *AnalysisHandler) ViewAnalysis(c *gin.Context) {
        h.viewAnalysisWithMode(c, resolveReportMode(c))
}

func (h *AnalysisHandler) ViewAnalysisExecutive(c *gin.Context) {
        h.viewAnalysisWithMode(c, "B")
}

func (h *AnalysisHandler) viewAnalysisWithMode(c *gin.Context, mode string) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                h.renderErrorPage(c, http.StatusBadRequest, nonce, csrfToken, mapKeyDanger, "Invalid analysis ID")
                return
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
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
                h.renderErrorPage(c, http.StatusInternalServerError, nonce, csrfToken, mapKeyDanger, "Failed to parse results")
                return
        }

        if dnsclient.IsTLDInput(analysis.AsciiDomain) {
                if mode == "E" {
                        mode = "Z"
                } else if mode == "C" {
                        mode = "CZ"
                }
        }

        waitSeconds, _ := strconv.Atoi(c.Query("wait_seconds"))
        waitReason := c.Query("wait_reason")

        timestamp := analysisTimestamp(analysis)
        dur := analysisDuration(analysis)
        toolVersion := extractToolVersion(results)
        verifyCommands := analyzer.GenerateVerificationCommands(analysis.AsciiDomain, results)
        integrityHash := computeIntegrityHash(analysis, timestamp, toolVersion, h.Config.AppVersion, results)
        rfcCount := analyzer.CountVerifiedRFCs(results)
        currentHash := derefString(analysis.PostureHash)
        drift := h.detectHistoricalDrift(ctx, currentHash, analysis.Domain, analysis.ID, results)
        isSub, rootDom := extractRootDomain(analysis.AsciiDomain)
        emailScope := h.resolveEmailScope(ctx, isSub, rootDom, analysis.AsciiDomain, results)

        viewData := gin.H{
                strAppversion:           h.Config.AppVersion,
                strCspnonce:             nonce,
                strCsrftoken:            csrfToken,
                strActivepage:           "",
                "Domain":               analysis.Domain,
                "AsciiDomain":          analysis.AsciiDomain,
                "Results":              results,
                "AnalysisID":           analysis.ID,
                "AnalysisDuration":     dur,
                "AnalysisTimestamp":    timestamp,
                "FromHistory":          true,
                "WaitSeconds":          waitSeconds,
                "WaitReason":           waitReason,
                "DomainExists":         resultsDomainExists(results),
                "ToolVersion":          toolVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "BetaPages":            h.Config.BetaPages,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          currentHash,
                "DriftDetected":        drift.Detected,
                "DriftPrevHash":        drift.PrevHash,
                "DriftPrevTime":        drift.PrevTime,
                "DriftPrevID":          drift.PrevID,
                "DriftFields":          drift.Fields,
                "IsPublicSuffix":       isPublicSuffixDomain(analysis.AsciiDomain),
                "IsTLD":                dnsclient.IsTLDInput(analysis.AsciiDomain),
                "SubdomainEmailScope":  emailScope,
                "ReportMode":           mode,
        }
        h.enrichViewDataMetrics(ctx, viewData, results, analysis.Domain, analysis.ID)
        viewData["CovertMode"] = isCovertMode(mode)

        mergeAuthData(c, h.Config, viewData)
        c.HTML(http.StatusOK, reportModeTemplate(mode), viewData)
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        domain := strings.TrimSpace(c.PostForm(mapKeyDomain))
        if domain == "" {
                domain = strings.TrimSpace(c.Query(mapKeyDomain))
        }

        if domain == "" {
                h.renderIndexFlash(c, nonce, csrfToken, mapKeyDanger, "Please enter a domain name.")
                return
        }

        if !dnsclient.ValidateDomain(domain) {
                h.renderIndexFlash(c, nonce, csrfToken, mapKeyDanger, fmt.Sprintf("Invalid domain name: %s", domain))
                return
        }

        asciiDomain, err := dnsclient.DomainToASCII(domain)
        if err != nil {
                asciiDomain = domain
        }

        customSelectors := extractCustomSelectors(c)
        hasNovelSelectors := len(customSelectors) > 0 && !analyzer.AllSelectorsKnown(customSelectors)
        exposureChecks := c.PostForm("exposure_checks") == "1"
        devNull := c.PostForm("devnull") == "1"

        isAuthenticated, userID := extractAuthInfo(c)

        ephemeral := devNull || (hasNovelSelectors && !isAuthenticated)

        startTime := time.Now()
        ctx := c.Request.Context()

        opts := analyzer.AnalysisOptions{
                ExposureChecks: exposureChecks,
        }
        results := h.Analyzer.AnalyzeDomain(ctx, asciiDomain, customSelectors, opts)
        analysisDuration := time.Since(startTime).Seconds()

        h.applyConfidenceEngines(results)

        if success, ok := results["analysis_success"].(bool); ok && !success {
                if errMsg, ok := results[mapKeyError].(string); ok {
                        h.renderIndexFlash(c, nonce, csrfToken, mapKeyWarning, errMsg)
                        return
                }
        }

        h.enrichResultsNoHistory(c, asciiDomain, results)

        domainExists := resultsDomainExists(results)

        clientIP := c.ClientIP()
        countryCode, countryName := lookupCountry(clientIP)

        scanClass := scanner.Classify(asciiDomain, clientIP)

        postureHash := analyzer.CanonicalPostureHash(results)

        drift := h.detectDrift(ctx, devNull, domainExists, asciiDomain, postureHash, results)

        isPrivate := hasNovelSelectors && isAuthenticated
        analysisID, timestamp := h.persistOrLogEphemeral(c.Request.Context(), persistParams{
                domain:            domain,
                asciiDomain:       asciiDomain,
                results:           results,
                analysisDuration:  analysisDuration,
                countryCode:       countryCode,
                countryName:       countryName,
                isPrivate:         isPrivate,
                hasNovelSelectors: hasNovelSelectors,
                scanClass:         scanClass,
                ephemeral:         ephemeral,
                domainExists:      domainExists,
                devNull:           devNull,
        })

        h.handlePostAnalysisSideEffects(ctx, c, sideEffectsParams{
                asciiDomain:     asciiDomain,
                analysisID:      analysisID,
                isAuthenticated: isAuthenticated,
                userID:          userID,
                ephemeral:       ephemeral,
                domainExists:    domainExists,
                drift:           drift,
                postureHash:     postureHash,
        })

        h.recordCurrencyIfEligible(ephemeral, domainExists, asciiDomain, results)

        analyzeData := h.buildAnalyzeViewData(c, nonce, csrfToken, viewDataInput{
                domain:           domain,
                asciiDomain:      asciiDomain,
                results:          results,
                analysisID:       analysisID,
                analysisDuration: analysisDuration,
                timestamp:        timestamp,
                postureHash:      postureHash,
                drift:            drift,
                exposureChecks:   exposureChecks,
                ephemeral:        ephemeral,
                devNull:          devNull,
                isPrivate:        isPrivate,
        })

        applyDevNullHeaders(c, devNull)
        mode := resolveCovertMode(c, asciiDomain)
        analyzeData["CovertMode"] = isCovertMode(mode)
        analyzeData["ReportMode"] = mode

        mergeAuthData(c, h.Config, analyzeData)
        c.HTML(http.StatusOK, reportModeTemplate(mode), analyzeData)
}

func (h *AnalysisHandler) recordCurrencyIfEligible(ephemeral, domainExists bool, asciiDomain string, results map[string]any) {
        if ephemeral || !domainExists {
                return
        }
        cr, ok := results[mapKeyCurrencyReport]
        if !ok {
                return
        }
        if report, valid := cr.(icuae.CurrencyReport); valid {
                go icuae.RecordScanResult(context.Background(), h.DB.Queries, asciiDomain, report, h.Config.AppVersion)
        }
}

func applyDevNullHeaders(c *gin.Context, devNull bool) {
        if devNull {
                c.Header("X-Hacker", "MUST means MUST -- not kinda, maybe, should. // DNS Tool")
                c.Header("X-Persistence", "/dev/null")
        }
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
        var maturityLevel string
        if icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries); icaeMetrics != nil {
                data["ICAEMetrics"] = icaeMetrics
                maturityLevel = icaeMetrics.OverallMaturity
        }
        var currencyScore float64
        if cr, ok := results[mapKeyCurrencyReport]; ok {
                if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                        data["CurrencyReport"] = report
                        currencyScore = report.OverallScore
                }
        }

        calibrated, _ := results["calibrated_confidence"].(map[string]float64)
        if calibrated != nil && maturityLevel != "" {
                uc := unified.ComputeUnifiedConfidence(unified.Input{
                        CalibratedConfidence: calibrated,
                        CurrencyScore:        currencyScore,
                        MaturityLevel:        maturityLevel,
                })
                data["UnifiedConfidence"] = uc
        }

        if analysisID > 0 {
                if sugConfig := buildSuggestedConfig(ctx, h.DB.Queries, domain, analysisID); sugConfig != nil {
                        data["SuggestedConfig"] = sugConfig
                }
        }
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

func derefString(p *string) string {
        if p != nil {
                return *p
        }
        return ""
}

func (h *AnalysisHandler) detectHistoricalDrift(ctx context.Context, currentHash, domain string, analysisID int32, results map[string]any) driftInfo {
        if currentHash == "" {
                return driftInfo{}
        }
        prevRow, prevErr := h.DB.Queries.GetPreviousAnalysisForDriftBefore(ctx, dbq.GetPreviousAnalysisForDriftBeforeParams{
                Domain: domain,
                ID:     analysisID,
        })
        if prevErr != nil {
                return driftInfo{}
        }
        return computeDriftFromPrev(currentHash, prevAnalysisSnapshot{
                Hash:           prevRow.PostureHash,
                ID:             prevRow.ID,
                CreatedAtValid: prevRow.CreatedAt.Valid,
                CreatedAt:      prevRow.CreatedAt.Time,
                FullResults:    prevRow.FullResults,
        }, results)
}

func (h *AnalysisHandler) resolveEmailScope(ctx context.Context, isSub bool, rootDom, asciiDomain string, results map[string]any) *subdomainEmailScope {
        if !isSub || rootDom == "" {
                return nil
        }
        es := computeSubdomainEmailScope(ctx, h.Analyzer.DNS, asciiDomain, rootDom, results)
        return &es
}

func extractAuthInfo(c *gin.Context) (bool, int32) {
        isAuthenticated := false
        var userID int32
        if auth, exists := c.Get(mapKeyAuthenticated); exists && auth == true {
                isAuthenticated = true
                if uid, ok := c.Get(mapKeyUserId); ok {
                        userID, _ = uid.(int32)
                }
        }
        return isAuthenticated, userID
}

func (h *AnalysisHandler) detectDrift(ctx context.Context, devNull, domainExists bool, asciiDomain, postureHash string, results map[string]any) driftInfo {
        drift := driftInfo{}
        if !devNull && domainExists {
                prevRow, prevErr := h.DB.Queries.GetPreviousAnalysisForDrift(ctx, asciiDomain)
                if prevErr == nil {
                        drift = computeDriftFromPrev(postureHash, prevAnalysisSnapshot{
                                        Hash:           prevRow.PostureHash,
                                        ID:             prevRow.ID,
                                        CreatedAtValid: prevRow.CreatedAt.Valid,
                                        CreatedAt:      prevRow.CreatedAt.Time,
                                        FullResults:    prevRow.FullResults,
                                }, results)
                        if drift.Detected {
                                slog.Info("Posture drift detected", mapKeyDomain, asciiDomain, "prev_hash", drift.PrevHash[:8], "new_hash", postureHash[:8], "changed_fields", len(drift.Fields))
                        }
                }
        }
        return drift
}

type persistParams struct {
        domain, asciiDomain       string
        results                   map[string]any
        analysisDuration          float64
        countryCode, countryName  string
        isPrivate                 bool
        hasNovelSelectors         bool
        scanClass                 scanner.Classification
        ephemeral                 bool
        domainExists              bool
        devNull                   bool
}

func (h *AnalysisHandler) persistOrLogEphemeral(ctx context.Context, p persistParams) (int32, string) {
        isSuccess, _ := extractAnalysisError(p.results)
        if p.ephemeral || p.devNull || (!p.domainExists && isSuccess) {
                logEphemeralReason(p.asciiDomain, p.devNull, p.domainExists)
                return 0, time.Now().UTC().Format(strUtc)
        }
        return h.saveAnalysis(ctx, saveAnalysisInput{
                domain:           p.domain,
                asciiDomain:      p.asciiDomain,
                results:          p.results,
                duration:         p.analysisDuration,
                countryCode:      p.countryCode,
                countryName:      p.countryName,
                private:          p.isPrivate,
                hasUserSelectors: p.hasNovelSelectors,
                scanClass:        p.scanClass,
        })
}

func logEphemeralReason(asciiDomain string, devNull, domainExists bool) {
        if devNull {
                slog.Info("/dev/null scan — full analysis, zero persistence", mapKeyDomain, asciiDomain)
        } else if !domainExists {
                slog.Info("Non-existent/undelegated domain — not persisted", mapKeyDomain, asciiDomain)
        } else {
                slog.Info("Ephemeral analysis (custom DKIM selectors, unauthenticated) — not persisted", mapKeyDomain, asciiDomain)
        }
}

type sideEffectsParams struct {
        asciiDomain     string
        analysisID      int32
        isAuthenticated bool
        userID          int32
        ephemeral       bool
        domainExists    bool
        drift           driftInfo
        postureHash     string
}

func (h *AnalysisHandler) handlePostAnalysisSideEffects(ctx context.Context, c *gin.Context, p sideEffectsParams) {
        if p.analysisID > 0 {
                h.recordUserAnalysisAsync(p)
                if p.drift.Detected {
                        go h.persistDriftEvent(p.asciiDomain, p.analysisID, p.drift, p.postureHash)
                }
        }

        if !p.ephemeral && p.domainExists {
                icae.EvaluateAndRecord(c.Request.Context(), h.DB.Queries, h.Config.AppVersion)
                recordAnalyticsCollector(c, p.asciiDomain)
        }
}

func (h *AnalysisHandler) recordUserAnalysisAsync(p sideEffectsParams) {
        if !p.isAuthenticated || p.userID <= 0 {
                return
        }
        go func() {
                err := h.DB.Queries.InsertUserAnalysis(context.Background(), dbq.InsertUserAnalysisParams{
                        UserID:     p.userID,
                        AnalysisID: p.analysisID,
                })
                if err != nil {
                        slog.Error("Failed to record user analysis association", mapKeyUserId, p.userID, "analysis_id", p.analysisID, mapKeyError, err)
                }
        }()
}

func recordAnalyticsCollector(c *gin.Context, domain string) {
        ac, exists := c.Get("analytics_collector")
        if !exists {
                return
        }
        if collector, ok := ac.(interface{ RecordAnalysis(string) }); ok {
                collector.RecordAnalysis(domain)
        }
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

func (h *AnalysisHandler) buildAnalyzeViewData(c *gin.Context, nonce, csrfToken any, v viewDataInput) gin.H {
        ctx := c.Request.Context()
        verifyCommands := analyzer.GenerateVerificationCommands(v.asciiDomain, v.results)
        integrityHash := analyzer.ReportIntegrityHash(v.asciiDomain, v.analysisID, v.timestamp, h.Config.AppVersion, v.results)
        rfcCount := analyzer.CountVerifiedRFCs(v.results)

        isSub, rootDom := extractRootDomain(v.asciiDomain)
        emailScope := h.resolveEmailScope(ctx, isSub, rootDom, v.asciiDomain, v.results)

        analyzeData := gin.H{
                strAppversion:           h.Config.AppVersion,
                strCspnonce:             nonce,
                strCsrftoken:            csrfToken,
                strActivepage:           "",
                "Domain":               v.domain,
                "AsciiDomain":          v.asciiDomain,
                "Results":              v.results,
                "AnalysisID":           v.analysisID,
                "AnalysisDuration":     v.analysisDuration,
                "AnalysisTimestamp":     v.timestamp,
                "FromHistory":          false,
                "FromCache":            false,
                "DomainExists":         resultsDomainExists(v.results),
                "ToolVersion":          h.Config.AppVersion,
                "VerificationCommands": verifyCommands,
                "IsSubdomain":          isSub,
                "RootDomain":           rootDom,
                "SecurityTrailsKey":    "",
                "IntegrityHash":        integrityHash,
                "RFCCount":             rfcCount,
                "ExposureChecks":       v.exposureChecks,
                "MaintenanceNote":      h.Config.MaintenanceNote,
                "BetaPages":            h.Config.BetaPages,
                "SectionTuning":        h.Config.SectionTuning,
                "PostureHash":          v.postureHash,
                "DriftDetected":        v.drift.Detected,
                "DriftPrevHash":        v.drift.PrevHash,
                "DriftPrevTime":        v.drift.PrevTime,
                "DriftPrevID":          v.drift.PrevID,
                "DriftFields":          v.drift.Fields,
                "Ephemeral":            v.ephemeral,
                "DevNull":              v.devNull,
                "IsPrivateReport":      v.isPrivate,
                "IsPublicSuffix":       isPublicSuffixDomain(v.asciiDomain),
                "IsTLD":                dnsclient.IsTLDInput(v.asciiDomain),
                "SubdomainEmailScope":  emailScope,
        }
        if icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries); icaeMetrics != nil {
                analyzeData["ICAEMetrics"] = icaeMetrics
        }
        if cr, ok := v.results[mapKeyCurrencyReport]; ok {
                if report, hydrated := icuae.HydrateCurrencyReport(cr); hydrated {
                        analyzeData["CurrencyReport"] = report
                }
        }
        return analyzeData
}

type driftInfo struct {
        Detected bool
        PrevHash string
        PrevTime string
        PrevID   int32
        Fields   []analyzer.PostureDiffField
}

type prevAnalysisSnapshot struct {
        Hash           *string
        ID             int32
        CreatedAtValid bool
        CreatedAt      time.Time
        FullResults    json.RawMessage
}

func computeDriftFromPrev(currentHash string, prev prevAnalysisSnapshot, currentResults map[string]any) driftInfo {
        if prev.Hash == nil || *prev.Hash == "" || *prev.Hash == currentHash {
                return driftInfo{}
        }
        di := driftInfo{
                Detected: true,
                PrevHash: *prev.Hash,
                PrevID:   prev.ID,
        }
        if prev.CreatedAtValid {
                di.PrevTime = prev.CreatedAt.Format("2 Jan 2006 15:04 UTC")
        }
        if prev.FullResults != nil {
                var prevResults map[string]any
                if json.Unmarshal(prev.FullResults, &prevResults) == nil {
                        di.Fields = analyzer.ComputePostureDiff(prevResults, currentResults)
                }
        }
        return di
}

func (h *AnalysisHandler) persistDriftEvent(domain string, analysisID int32, drift driftInfo, currentHash string) {
        diffJSON, err := json.Marshal(drift.Fields)
        if err != nil {
                slog.Error("Failed to marshal drift diff", mapKeyDomain, domain, mapKeyError, err)
                return
        }

        severity := "info"
        for _, f := range drift.Fields {
                if f.Severity == mapKeyCritical {
                        severity = mapKeyCritical
                        break
                }
                if f.Severity == mapKeyWarning && severity != mapKeyCritical {
                        severity = mapKeyWarning
                }
        }

        _, insertErr := h.DB.Queries.InsertDriftEvent(context.Background(), dbq.InsertDriftEventParams{
                Domain:         domain,
                AnalysisID:     analysisID,
                PrevAnalysisID: drift.PrevID,
                CurrentHash:    currentHash,
                PreviousHash:   drift.PrevHash,
                DiffSummary:    diffJSON,
                Severity:       severity,
        })
        if insertErr != nil {
                slog.Error("Failed to persist drift event", mapKeyDomain, domain, mapKeyError, insertErr)
                return
        }
        slog.Info("Drift event persisted", mapKeyDomain, domain, "severity", severity, "changed_fields", len(drift.Fields))
}

func (h *AnalysisHandler) indexFlashData(c *gin.Context, nonce, csrfToken any, category, message string) gin.H {
        data := gin.H{
                strAppversion:    h.Config.AppVersion,
                strCspnonce:      nonce,
                strCsrftoken:     csrfToken,
                strActivepage:    "home",
                "FlashMessages": []FlashMessage{{Category: category, Message: message}},
        }
        mergeAuthData(c, h.Config, data)
        return data
}

func (h *AnalysisHandler) renderRestrictedAccess(c *gin.Context, nonce, csrfToken any) {
        auth, _ := c.Get(mapKeyAuthenticated)
        if auth != true {
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

func extractCustomSelectors(c *gin.Context) []string {
        var customSelectors []string
        for _, sel := range []string{c.PostForm("dkim_selector1"), c.PostForm("dkim_selector2")} {
                sel = strings.TrimSpace(sel)
                if sel != "" {
                        customSelectors = append(customSelectors, sel)
                }
        }
        return customSelectors
}

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

        status, _ := result[mapKeyStatus].(string)
        if status == "rate_limited" || status == mapKeyError || status == "timeout" {
                c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
                return
        }

        available, _ := result["available"].(bool)
        if !available {
                c.JSON(http.StatusOK, gin.H{mapKeyStatus: "unavailable"})
                return
        }

        c.JSON(http.StatusOK, result)
}

func (h *AnalysisHandler) enrichResultsNoHistory(_ *gin.Context, _ string, results map[string]any) {
        if rem, ok := results["remediation"].(map[string]any); ok {
                results["remediation"] = analyzer.EnrichRemediationWithRFCMeta(rem)
        }

        results["rfc_metadata"] = analyzer.GetAllRFCMetadata()
}

func resultsDomainExists(results map[string]any) bool {
        if v, ok := results["domain_exists"]; ok {
                if b, ok := v.(bool); ok {
                        return b
                }
        }
        return true
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
                name, _ := sd["name"].(string)
                status := "Expired"
                if isCur, ok := sd["is_current"].(bool); ok && isCur {
                        status = "Current"
                }
                source, _ := sd["source"].(string)
                cnameTarget, _ := sd["cname_target"].(string)
                provider, _ := sd["provider"].(string)
                certCount, _ := sd["cert_count"].(string)
                firstSeen, _ := sd["first_seen"].(string)

                var issuerStr string
                if issuers, ok := sd["issuers"].([]string); ok && len(issuers) > 0 {
                        issuerStr = strings.Join(issuers, "; ")
                }

                w.WriteString(csvEscape(name) + "," +
                        csvEscape(status) + "," +
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
        if strings.ContainsAny(s, ",\"\n\r") {
                return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
        }
        return s
}

func (h *AnalysisHandler) buildAnalysisJSON(ctx context.Context, analysis dbq.DomainAnalysis) ([]byte, string) {
        var fullResults interface{}
        if len(analysis.FullResults) > 0 {
                json.Unmarshal(analysis.FullResults, &fullResults)
        }
        var ctSubdomains interface{}
        if len(analysis.CtSubdomains) > 0 {
                json.Unmarshal(analysis.CtSubdomains, &ctSubdomains)
        }

        var currencyReport interface{}
        if frMap, ok := fullResults.(map[string]interface{}); ok {
                if cr, exists := frMap[mapKeyCurrencyReport]; exists {
                        currencyReport = cr
                }
        }

        provenance := map[string]interface{}{
                "tool_version":       h.Config.AppVersion,
                "hash_algorithm":     "SHA-3-512",
                "hash_standard":      "NIST FIPS 202 (Keccak)",
                "export_timestamp":   time.Now().UTC().Format(time.RFC3339),
                "analysis_timestamp": formatTimestampISO(analysis.CreatedAt),
                "engines": map[string]interface{}{
                        "icae": map[string]string{
                                "name":     "Intelligence Confidence Audit Engine",
                                "purpose":  "Correctness verification via deterministic test cases",
                                mapKeyStandard: "ICD 203 Analytic Standards",
                        },
                        "icuae": map[string]string{
                                "name":     "Intelligence Currency Audit Engine",
                                "purpose":  "Data timeliness and validity measurement",
                                mapKeyStandard: "ICD 203, NIST SP 800-53 SI-18, ISO/IEC 25012, RFC 8767",
                        },
                },
        }
        if currencyReport != nil {
                provenance[mapKeyCurrencyReport] = currencyReport
        }
        if icaeMetrics := icae.LoadReportMetrics(ctx, h.DB.Queries); icaeMetrics != nil {
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

        payload := map[string]interface{}{
                "analysis_duration": analysis.AnalysisDuration,
                "analysis_success":  analysis.AnalysisSuccess,
                "ascii_domain":      analysis.AsciiDomain,
                "country_code":      analysis.CountryCode,
                "country_name":      analysis.CountryName,
                "created_at":        formatTimestampISO(analysis.CreatedAt),
                "ct_subdomains":     ctSubdomains,
                "dkim_status":       analysis.DkimStatus,
                "dmarc_policy":      analysis.DmarcPolicy,
                "dmarc_status":      analysis.DmarcStatus,
                mapKeyDomain:            analysis.Domain,
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

        orderedPayload := make([]struct {
                Key   string
                Value interface{}
        }, len(keys))
        for i, k := range keys {
                orderedPayload[i].Key = k
                orderedPayload[i].Value = payload[k]
        }

        buf := []byte("{")
        for i, kv := range orderedPayload {
                if i > 0 {
                        buf = append(buf, ',')
                }
                keyBytes, _ := json.Marshal(kv.Key)
                valBytes, _ := json.Marshal(kv.Value)
                buf = append(buf, keyBytes...)
                buf = append(buf, ':')
                buf = append(buf, valBytes...)
        }
        buf = append(buf, '}')
        buf = append(buf, '\n')

        hash := sha3.Sum512(buf)
        return buf, hex.EncodeToString(hash[:])
}

func (h *AnalysisHandler) loadAnalysisForAPI(c *gin.Context) (dbq.DomainAnalysis, bool) {
        idStr := c.Param("id")
        analysisID, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{mapKeyError: "Invalid analysis ID"})
                return dbq.DomainAnalysis{}, false
        }

        ctx := c.Request.Context()
        analysis, err := h.DB.Queries.GetAnalysisByID(ctx, int32(analysisID))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{mapKeyError: strAnalysisNotFound})
                return dbq.DomainAnalysis{}, false
        }

        if !h.checkPrivateAccess(c, analysis.ID, analysis.Private) {
                auth, _ := c.Get(mapKeyAuthenticated)
                if auth == true {
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
        analysis, ok := h.loadAnalysisForAPI(c)
        if !ok {
                return
        }

        jsonBytes, fileHash := h.buildAnalysisJSON(c.Request.Context(), analysis)
        filename := fmt.Sprintf("dns-intelligence-%s.json", analysis.AsciiDomain)

        if c.Query("download") == "1" || c.Request.Header.Get("Accept") == "application/octet-stream" {
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
                sb.WriteString("#   Standards:       ICD 203, NIST SP 800-53 SI-18, ISO/IEC 25012\n")
                sb.WriteString("#\n")
                sb.WriteString(fmt.Sprintf("%s  %s\n", fileHash, filename))
                c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(sb.String()))
                return
        }

        checksumResponse := gin.H{
                "algorithm": "SHA-3-512",
                mapKeyStandard:  "NIST FIPS 202 (Keccak)",
                "hash":      fileHash,
                "filename":  filename,
                "provenance": gin.H{
                        "analysis_id":      analysis.ID,
                        "report_url":       fmt.Sprintf("%s/analysis/%d/view", h.Config.BaseURL, analysis.ID),
                        "tool_version":     h.Config.AppVersion,
                        "export_timestamp": time.Now().UTC().Format(time.RFC3339),
                        "engines":          []string{"ICAE (Confidence)", "ICuAE (Currency)"},
                        "standards":        []string{"ICD 203", "NIST SP 800-53 SI-18", "ISO/IEC 25012", "RFC 8767"},
                },
                "verify_commands": map[string]string{
                        "openssl": fmt.Sprintf("openssl dgst -sha3-512 %s", filename),
                        "python":  fmt.Sprintf("python3 -c \"import hashlib; print(hashlib.sha3_512(open('%s','rb').read()).hexdigest())\"", filename),
                        "sha3sum": fmt.Sprintf("sha3sum -a 512 %s", filename),
                },
        }
        c.JSON(http.StatusOK, checksumResponse)
}

type saveAnalysisInput struct {
        domain           string
        asciiDomain      string
        results          map[string]any
        duration         float64
        countryCode      string
        countryName      string
        private          bool
        hasUserSelectors bool
        scanClass        scanner.Classification
}

func (h *AnalysisHandler) saveAnalysis(ctx context.Context, p saveAnalysisInput) (int32, string) {
        p.results["_tool_version"] = h.Config.AppVersion
        fullResultsJSON, _ := json.Marshal(p.results)

        basicRecordsJSON := getJSONFromResults(p.results, "basic_records", "")
        authRecordsJSON := getJSONFromResults(p.results, "authoritative_records", "")

        spfStatus := getStringFromResults(p.results, mapKeySpfAnalysis, mapKeyStatus)
        dmarcStatus := getStringFromResults(p.results, mapKeyDmarcAnalysis, mapKeyStatus)
        dmarcPolicy := getStringFromResults(p.results, mapKeyDmarcAnalysis, "policy")
        dkimStatus := getStringFromResults(p.results, mapKeyDkimAnalysis, mapKeyStatus)
        registrarName := getStringFromResults(p.results, "registrar_info", "registrar")
        registrarSource := getStringFromResults(p.results, "registrar_info", "source")

        spfRecordsJSON := getJSONFromResults(p.results, mapKeySpfAnalysis, "records")
        dmarcRecordsJSON := getJSONFromResults(p.results, mapKeyDmarcAnalysis, "records")
        dkimSelectorsJSON := getJSONFromResults(p.results, mapKeyDkimAnalysis, "selectors")
        ctSubdomainsJSON := getJSONFromResults(p.results, "ct_subdomains", "")

        postureHash := analyzer.CanonicalPostureHash(p.results)

        success, errorMessage := extractAnalysisError(p.results)
        cc, cn := optionalStrings(p.countryCode, p.countryName)
        scanSource, scanIP := extractScanFields(p.scanClass)

        params := dbq.InsertAnalysisParams{
                Domain:               p.domain,
                AsciiDomain:          p.asciiDomain,
                BasicRecords:         basicRecordsJSON,
                AuthoritativeRecords: authRecordsJSON,
                SpfStatus:            spfStatus,
                SpfRecords:           spfRecordsJSON,
                DmarcStatus:          dmarcStatus,
                DmarcPolicy:          dmarcPolicy,
                DmarcRecords:         dmarcRecordsJSON,
                DkimStatus:           dkimStatus,
                DkimSelectors:        dkimSelectorsJSON,
                RegistrarName:        registrarName,
                RegistrarSource:      registrarSource,
                CtSubdomains:         ctSubdomainsJSON,
                FullResults:          fullResultsJSON,
                CountryCode:          cc,
                CountryName:          cn,
                AnalysisSuccess:      &success,
                ErrorMessage:         errorMessage,
                AnalysisDuration:     &p.duration,
                PostureHash:          &postureHash,
                Private:              p.private,
                HasUserSelectors:     p.hasUserSelectors,
                ScanFlag:             p.scanClass.IsScan,
                ScanSource:           scanSource,
                ScanIp:               scanIP,
        }

        row, err := h.DB.Queries.InsertAnalysis(ctx, params)
        if err != nil {
                slog.Error("Failed to save analysis", mapKeyDomain, p.domain, mapKeyError, err)
                return 0, time.Now().UTC().Format(strUtc)
        }

        timestamp := "just now"
        if row.CreatedAt.Valid {
                timestamp = row.CreatedAt.Time.Format(strUtc)
        }
        return row.ID, timestamp
}

func extractAnalysisError(results map[string]any) (bool, *string) {
        if errStr, ok := results[mapKeyError].(string); ok && errStr != "" {
                return false, &errStr
        }
        return true, nil
}

func optionalStrings(a, b string) (*string, *string) {
        var ap, bp *string
        if a != "" {
                ap = &a
        }
        if b != "" {
                bp = &b
        }
        return ap, bp
}

func extractScanFields(sc scanner.Classification) (*string, *string) {
        var scanSource, scanIP *string
        if sc.IsScan {
                scanSource = &sc.Source
        }
        if sc.IP != "" {
                scanIP = &sc.IP
        }
        return scanSource, scanIP
}

var countryCache sync.Map

type countryEntry struct {
        code, name string
        fetched    time.Time
}

func lookupCountry(ip string) (string, string) {
        if ip == "" || ip == "127.0.0.1" || ip == "::1" {
                return "", ""
        }

        if cached, ok := countryCache.Load(ip); ok {
                entry := cached.(countryEntry)
                if time.Since(entry.fetched) < 24*time.Hour {
                        return entry.code, entry.name
                }
        }

        client := &http.Client{Timeout: 2 * time.Second}
        resp, err := client.Get(fmt.Sprintf("https://ip-api.com/json/%s?fields=status,countryCode,country", ip))
        if err != nil {
                return "", ""
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                return "", ""
        }

        var result struct {
                Status      string `json:"status"`
                CountryCode string `json:"countryCode"`
                Country     string `json:"country"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
                return "", ""
        }

        countryCache.Store(ip, countryEntry{code: result.CountryCode, name: result.Country, fetched: time.Now()})
        return result.CountryCode, result.Country
}

func getStringFromResults(results map[string]any, section, key string) *string {
        if key == "" {
                if v, ok := results[section]; ok {
                        if s, ok := v.(string); ok {
                                return &s
                        }
                }
                return nil
        }
        sectionData, ok := results[section].(map[string]any)
        if !ok {
                return nil
        }
        v, ok := sectionData[key]
        if !ok {
                return nil
        }
        s, ok := v.(string)
        if !ok {
                return nil
        }
        return &s
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

func getJSONFromResults(results map[string]any, section, key string) json.RawMessage {
        var data any
        if key == "" {
                data = results[section]
        } else {
                sectionData, ok := results[section].(map[string]any)
                if !ok {
                        return nil
                }
                data = sectionData[key]
        }
        if data == nil {
                return nil
        }
        b, err := json.Marshal(data)
        if err != nil {
                return nil
        }
        return b
}

var protocolResultKeys = map[string]string{
        "SPF":     mapKeySpfAnalysis,
        "DKIM":    mapKeyDkimAnalysis,
        "DMARC":   mapKeyDmarcAnalysis,
        "DANE":    "dane_analysis",
        "DNSSEC":  "dnssec_analysis",
        "BIMI":    "bimi_analysis",
        "MTA_STS": "mta_sts_analysis",
        "TLS_RPT": "tlsrpt_analysis",
        "CAA":     "caa_analysis",
}

var icuaeToDimChart = map[string]string{
        icuae.DimensionSourceCredibility: "SourceCredibility",
        icuae.DimensionCurrentness:       "TemporalValidity",
        icuae.DimensionCompleteness:      "ChainCompleteness",
        icuae.DimensionTTLCompliance:     "TTLCompliance",
        icuae.DimensionTTLRelevance:      "ResolverConsensus",
}

func (h *AnalysisHandler) applyConfidenceEngines(results map[string]any) {
        cr, ok := results[mapKeyCurrencyReport].(icuae.CurrencyReport)
        if !ok {
                return
        }

        calibrated := h.computeCalibratedConfidence(results, cr)
        results["calibrated_confidence"] = calibrated

        ewmaSnapshot := h.recordDimensionCharts(cr)
        results["ewma_drift"] = ewmaSnapshot

        slog.Info("Confidence engines applied",
                "protocols_calibrated", len(calibrated),
                "ewma_dimensions", len(ewmaSnapshot),
        )
}

func (h *AnalysisHandler) computeCalibratedConfidence(results map[string]any, cr icuae.CurrencyReport) map[string]float64 {
        totalAgree, totalResolvers := aggregateResolverAgreement(results)

        calibrated := make(map[string]float64, len(protocolResultKeys))
        for protocol, resultKey := range protocolResultKeys {
                rawConfidence := protocolRawConfidence(results, resultKey)
                cc := h.Calibration.CalibratedConfidence(protocol, rawConfidence, totalAgree, totalResolvers)
                calibrated[protocol] = cc
        }
        return calibrated
}

func protocolRawConfidence(results map[string]any, resultKey string) float64 {
        section, ok := results[resultKey].(map[string]any)
        if !ok {
                return 0.0
        }
        status, _ := section[mapKeyStatus].(string)
        switch status {
        case "secure", "pass", "valid", "good":
                return 1.0
        case mapKeyWarning, "info", "partial":
                return 0.7
        case "fail", mapKeyDanger, mapKeyCritical:
                return 0.3
        case mapKeyError, "n/a", "":
                return 0.0
        default:
                return 0.5
        }
}

func aggregateResolverAgreement(results map[string]any) (int, int) {
        consensus, ok := results["resolver_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        perRecord, ok := consensus["per_record_consensus"].(map[string]any)
        if !ok {
                return 0, 0
        }
        totalAgree := 0
        totalResolvers := 0
        for _, data := range perRecord {
                rd, ok := data.(map[string]any)
                if !ok {
                        continue
                }
                rc, _ := rd["resolver_count"].(int)
                isConsensus, _ := rd["consensus"].(bool)
                agreeCount := rc
                if !isConsensus {
                        agreeCount = rc - 1
                        if agreeCount < 0 {
                                agreeCount = 0
                        }
                }
                totalAgree += agreeCount
                totalResolvers += rc
        }
        return totalAgree, totalResolvers
}

func (h *AnalysisHandler) recordDimensionCharts(cr icuae.CurrencyReport) map[string]icuae.ChartSnapshot {
        scores := make(map[string]float64, len(cr.Dimensions))
        for _, dim := range cr.Dimensions {
                if chartKey, ok := icuaeToDimChart[dim.Dimension]; ok {
                        scores[chartKey] = dim.Score
                }
        }
        h.DimCharts.RecordDimensionScores(scores)
        return h.DimCharts.Summary()
}
