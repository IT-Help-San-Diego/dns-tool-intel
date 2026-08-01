// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/botverify"
	"dnstool/go-server/internal/dnsclient"
	"dnstool/go-server/internal/handlers/badgepkg"
	"dnstool/go-server/internal/logging"
	"dnstool/go-server/internal/scanner"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

func extractDomainInput(c *gin.Context) string {
	domain := strings.TrimSpace(c.PostForm(mapKeyDomain))
	if domain == "" {
		domain = strings.TrimSpace(c.Query(mapKeyDomain))
	}
	return domain
}

func isAnalysisFailure(results map[string]any) (bool, string) {
	success, ok := results["analysis_success"].(bool)
	if !ok || success {
		return false, ""
	}
	errMsg, ok := results[mapKeyError].(string)
	if !ok {
		return false, ""
	}
	return true, errMsg
}

func getContextValue(c *gin.Context, key string) any {
	v, ok := c.Get(key)
	if !ok {
		return ""
	}
	return v
}

func isAgentCacheEligible(c *gin.Context, customSelectors []string, exposureChecks bool) bool {
	return c.Request.Method == http.MethodGet && c.Query("src") == "agent" && len(customSelectors) == 0 && !exposureChecks
}

// isReadOnlyCacheEligible decides whether a request can be served from a stored
// analysis row without triggering a fresh scan.
//
// HTTP-spec discipline (RFC 9110 §9.2.1): GET/HEAD must be safe and idempotent.
// Crawlers, link-prefetch, social link previews, and shared-link clicks all use
// GET — none of them should create domain_analyses rows or trigger network work.
// Only POST is permitted to create new rows.
//
// Custom selectors and exposure checks alter the result, so a generic cached row
// cannot be used.
func isReadOnlyCacheEligible(customSelectors []string, exposureChecks bool) bool {
	return len(customSelectors) == 0 && !exposureChecks
}

type analyzeInput struct {
	domain, asciiDomain          string
	customSelectors              []string
	exposureChecks, devNull      bool
	isAuthenticated              bool
	userID                       int32
	hasNovelSelectors, ephemeral bool
	// inputAsGiven / inputDiscarded record that the scanned domain was
	// EXTRACTED from what the user typed — a pasted URL, most often. Carried so
	// the report can say what was scanned and what was dropped: an instrument
	// that silently substitutes its input claims to have measured what the user
	// asked for when it measured something else.
	inputAsGiven, inputDiscarded string
	// userAgent and clientIP are captured at request time so the async scan
	// goroutine (which runs after the *gin.Context is gone) can still call
	// botverify.Classify and tag the persisted row with provenance.
	userAgent, clientIP string
}

func extractAnalyzeInput(c *gin.Context) (analyzeInput, bool) {
	domain := extractDomainInput(c)
	if domain == "" {
		return analyzeInput{}, false
	}
	// Accept what people actually paste. A URL is the commonest way anyone
	// enters a domain, and rejecting it read as the tool being broken rather
	// than strict. The disclosure below is not optional.
	asGiven := domain
	var discardedDesc string
	if normalized, changed, discarded := dnsclient.NormalizeDomainInput(domain); changed && normalized != "" {
		domain = normalized
		discardedDesc = discarded
	} else {
		asGiven = ""
	}
	if !dnsclient.ValidateDomain(domain) && !analyzer.IsWeb3Input(domain) {
		return analyzeInput{}, false
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
	return analyzeInput{
		domain: domain, asciiDomain: asciiDomain,
		inputAsGiven: asGiven, inputDiscarded: discardedDesc,
		customSelectors: customSelectors, exposureChecks: exposureChecks,
		devNull: devNull, isAuthenticated: isAuthenticated, userID: userID,
		hasNovelSelectors: hasNovelSelectors, ephemeral: ephemeral,
		userAgent: c.Request.UserAgent(), clientIP: c.ClientIP(),
	}, true
}

// cacheLookupOutcome distinguishes the three terminal states of a cache
// lookup: served (HTML written), miss (no row → caller should render the
// "not yet analyzed" interstitial), or transient (DB blip → caller should
// render an "unavailable" message instead of falsely claiming the domain
// has not been analyzed).
type cacheLookupOutcome int

const (
	cacheServed cacheLookupOutcome = iota
	cacheMiss
	cacheTransient
)

func (h *AnalysisHandler) tryServeFromCache(c *gin.Context, inp analyzeInput, nonce, csrfToken any) cacheLookupOutcome {
	if !isReadOnlyCacheEligible(inp.customSelectors, inp.exposureChecks) {
		return cacheMiss
	}
	if outcome := h.serveCachedAnalysis(c, inp.domain, inp.asciiDomain, nonce, csrfToken); outcome != cacheMiss {
		return outcome
	}
	if inp.domain != inp.asciiDomain {
		return h.serveCachedAnalysis(c, inp.asciiDomain, inp.asciiDomain, nonce, csrfToken)
	}
	return cacheMiss
}

func annotateInputNormalization(results map[string]any, inp analyzeInput) {
	if inp.inputAsGiven == "" {
		return
	}
	results["_input_normalization"] = map[string]any{
		"as_given":  inp.inputAsGiven,
		"scanned":   inp.domain,
		"discarded": inp.inputDiscarded,
		"note": "The scanned name was extracted from the input as entered. " +
			"Findings describe the extracted name only.",
	}
}

func (h *AnalysisHandler) Analyze(c *gin.Context) {
	nonce := getContextValue(c, "csp_nonce")
	csrfToken := getContextValue(c, "csrf_token")

	inp, valid := extractAnalyzeInput(c)
	if !valid {
		domain := extractDomainInput(c)
		msg := "Please enter a domain name."
		if domain != "" {
			msg = fmt.Sprintf("Invalid domain name: %s", domain)
		}
		h.renderIndexFlash(c, nonce, csrfToken, mapKeyDanger, msg)
		return
	}

	// HTTP-spec discipline (RFC 9110 §9.2.1): GET/HEAD must be safe and
	// idempotent. They never trigger a fresh scan or create domain_analyses
	// rows. Crawlers, link-prefetch, social link previews, and shared-link
	// clicks all use GET — so we serve the latest stored analysis (with a
	// page-level CACHED banner + [Re-scan] button) or, if no analysis exists,
	// render an interstitial that lets the user POST a fresh scan.
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
		switch h.tryServeFromCache(c, inp, nonce, csrfToken) {
		case cacheServed:
			return
		case cacheTransient:
			// DB blip — do NOT render "not yet analyzed" (that would be
			// a lie that may cause crawlers to re-queue the URL or users
			// to assume their POST silently failed). Return a transparent
			// unavailable message; never cache.
			h.renderCacheLookupUnavailable(c, nonce, csrfToken, inp.domain)
			return
		case cacheMiss:
		}
		h.renderNotYetAnalyzed(c, nonce, csrfToken, inp.domain)
		return
	}

	wantsJSON := strings.Contains(c.GetHeader("Accept"), "application/json") && c.Request.Method == "POST"
	if wantsJSON {
		h.analyzeAsync(c, inp.domain, inp.asciiDomain, inp.customSelectors, inp.exposureChecks, inp.devNull, inp.isAuthenticated, inp.userID, inp.hasNovelSelectors, inp.ephemeral)
		return
	}

	startTime := time.Now()
	ctx, cancelScan := scanContext(c.Request.Context())
	defer cancelScan()

	results := h.Analyzer.AnalyzeDomain(ctx, inp.asciiDomain, inp.customSelectors, analyzer.AnalysisOptions{
		ExposureChecks: inp.exposureChecks,
	})
	analysisDuration := time.Since(startTime).Seconds()

	h.applyConfidenceEngines(results)

	if failed, errMsg := isAnalysisFailure(results); failed {
		go h.recordDailyStats(false, analysisDuration)
		h.renderIndexFlash(c, nonce, csrfToken, mapKeyWarning, errMsg)
		return
	}

	h.enrichResultsNoHistory(c, inp.asciiDomain, results)

	domainExists := resultsDomainExists(results)
	clientIP := c.ClientIP()
	countryCode, countryName := lookupCountry(clientIP)
	scanClass := scanner.Classify(inp.asciiDomain, clientIP)
	botClass := botverify.Classify(c.Request.UserAgent(), clientIP).String()
	postureHash := analyzer.CanonicalPostureHash(results)
	drift := h.detectDrift(ctx, inp.devNull, domainExists, inp.asciiDomain, postureHash, results)

	h.snapshotICAEMetrics(ctx, results)

	if c.Query("src") == "agent" || strings.Contains(c.Request.UserAgent(), "DEVONagent") {
		results["_request_source"] = "agent"
	}

	isPrivate := inp.hasNovelSelectors && inp.isAuthenticated
	annotateInputNormalization(results, inp)
	analysisID, timestamp := h.persistOrLogEphemeral(ctx, persistParams{
		domain:            inp.domain,
		asciiDomain:       inp.asciiDomain,
		results:           results,
		analysisDuration:  analysisDuration,
		countryCode:       countryCode,
		countryName:       countryName,
		isPrivate:         isPrivate,
		hasNovelSelectors: inp.hasNovelSelectors,
		scanClass:         scanClass,
		botClass:          botClass,
		ephemeral:         inp.ephemeral,
		domainExists:      domainExists,
		devNull:           inp.devNull,
	})

	h.storeTelemetry(ctx, analysisID, results, inp.ephemeral)

	analysisSuccess, _ := extractAnalysisError(results) //nolint:errcheck // error message not needed here
	h.handlePostAnalysisSideEffects(ctx, c, sideEffectsParams{
		asciiDomain:      inp.asciiDomain,
		analysisID:       analysisID,
		isAuthenticated:  inp.isAuthenticated,
		userID:           inp.userID,
		ephemeral:        inp.ephemeral,
		domainExists:     domainExists,
		drift:            drift,
		postureHash:      postureHash,
		analysisSuccess:  analysisSuccess,
		analysisDuration: analysisDuration,
		isPrivate:        isPrivate,
		isScanFlagged:    scanClass.IsScan,
		results:          results,
	})

	h.recordCurrencyIfEligible(inp.ephemeral, domainExists, inp.asciiDomain, results)

	analyzeData := h.buildAnalyzeViewData(c, viewDataInput{
		domain:           inp.domain,
		asciiDomain:      inp.asciiDomain,
		results:          results,
		analysisID:       analysisID,
		analysisDuration: analysisDuration,
		timestamp:        timestamp,
		postureHash:      postureHash,
		drift:            drift,
		exposureChecks:   inp.exposureChecks,
		ephemeral:        inp.ephemeral,
		devNull:          inp.devNull,
		isPrivate:        isPrivate,
	})

	applyDevNullHeaders(c, inp.devNull)
	mode := resolveCovertMode(c, inp.asciiDomain)
	analyzeData["CovertMode"] = isCovertMode(mode)
	analyzeData["ReportMode"] = mode

	c.HTML(http.StatusOK, reportModeTemplate(mode), analyzeData)
}

// cachedAnalysisMaxAge bounds how old a stored analysis can be before GET
// requests stop serving it. The previous 1-hour cap was too aggressive for
// share-link / bookmark traffic — we now serve up to 30 days, with the
// page-level CACHED banner displaying the original timestamp and a [Re-scan]
// button so users can always trigger a fresh analysis on demand. POST /analyze
// is unaffected and always runs a fresh scan.
const cachedAnalysisMaxAge = 30 * 24 * time.Hour

func (h *AnalysisHandler) serveCachedAnalysis(c *gin.Context, domain, asciiDomain string, _, _ any) cacheLookupOutcome {
	s := h.store()
	if s == nil {
		// No store configured at all is treated as a transient infrastructure
		// problem (likely test wiring or a misconfig) — never lie that the
		// domain has not been analyzed.
		return cacheTransient
	}
	analysis, err := s.GetRecentAnalysisByDomain(c.Request.Context(), domain)
	if err != nil {
		// pgx.ErrNoRows is the only error that genuinely means "this domain
		// has never been analyzed". Anything else (timeout, connection
		// refused, replica failover, malformed row) is a transient
		// infrastructure problem the caller must surface honestly instead
		// of caching as a negative.
		if errors.Is(err, pgx.ErrNoRows) {
			return cacheMiss
		}
		slog.Warn("serveCachedAnalysis: db lookup failed",
			"domain", domain, "error", err)
		return cacheTransient
	}
	// From here, we have a row but it's not eligible to be served as a cached
	// result. These are all "miss-equivalent" outcomes — the domain has been
	// touched before but we have nothing publishable to show, so we route the
	// user to the interstitial → POST path. None of these are transient
	// errors, so it's safe to render the no-store interstitial.
	if analysis.Private {
		return cacheMiss
	}
	if analysis.AnalysisSuccess != nil && !*analysis.AnalysisSuccess {
		return cacheMiss
	}
	if analysis.ScanFlag {
		return cacheMiss
	}
	if !analysis.CreatedAt.Valid || time.Since(analysis.CreatedAt.Time) > cachedAnalysisMaxAge {
		return cacheMiss
	}
	results := badgepkg.UnmarshalResults(analysis.FullResults, "serveCachedAnalysis")
	if results == nil {
		return cacheMiss
	}

	h.enrichResultsAsync(results)

	var analysisID int32 = analysis.ID
	var analysisDuration float64
	if analysis.AnalysisDuration != nil {
		analysisDuration = *analysis.AnalysisDuration
	}
	var timestamp string
	if analysis.CreatedAt.Valid {
		timestamp = analysis.CreatedAt.Time.UTC().Format(time.RFC3339)
	}
	var postureHash string
	if analysis.PostureHash != nil {
		postureHash = *analysis.PostureHash
	}

	analyzeData := h.buildAnalyzeViewData(c, viewDataInput{
		domain:           domain,
		asciiDomain:      asciiDomain,
		results:          results,
		analysisID:       analysisID,
		analysisDuration: analysisDuration,
		timestamp:        timestamp,
		postureHash:      postureHash,
		drift:            driftInfo{},
	})
	analyzeData["FromCache"] = true
	analyzeData["FromCacheAt"] = timestamp
	analyzeData["FromCacheDomain"] = domain

	mode := resolveCovertMode(c, asciiDomain)
	analyzeData["CovertMode"] = isCovertMode(mode)
	analyzeData["ReportMode"] = mode

	// Cache discipline: this HTML carries a per-session CSRF token (the
	// [Re-scan] form) and may include personalized nav/auth state from
	// NewTemplateData. `no-store` is the strongest defensible header for
	// CSRF/session-personalized pages — it prevents both shared/edge caches
	// and browser disk storage from retaining the response, which is the
	// RFC 9111 §5.2.2.5 contract for sensitive content. Crawler-burst
	// protection is already provided by the GET=read discipline itself:
	// even N parallel GETs only cost one SELECT each — no scan, no DB write.
	c.Header("Cache-Control", "no-store")
	c.HTML(http.StatusOK, reportModeTemplate(mode), analyzeData)
	return cacheServed
}

// renderNotYetAnalyzed serves the "[domain] hasn't been analyzed yet" interstitial.
// Used when a GET /analyze?domain=foo arrives for a domain we have no stored
// analysis for. Shows the homepage with the domain prefilled so the user just
// clicks Analyze to POST a fresh scan.
func (h *AnalysisHandler) renderNotYetAnalyzed(c *gin.Context, nonce, csrfToken any, domain string) {
	msg := fmt.Sprintf("%s has not been analyzed yet — click Analyze to run a fresh scan.", domain)
	data := h.indexFlashData(c, nonce, csrfToken, "info", msg)
	data["PrefillDomain"] = domain
	// Negative responses must NOT be shared/edge-cached. A transient DB error,
	// a stale row, or a race with a POST that has just landed could otherwise
	// be cached as "not analyzed" and served to thousands of users after the
	// domain genuinely is analyzed. The interstitial also embeds a CSRF token,
	// which must remain per-session. `no-store` is the safest contract here.
	c.Header("Cache-Control", "no-store")
	c.HTML(http.StatusOK, templateIndex, data)
}

// renderCacheLookupUnavailable is the honest response when a GET arrives but
// our cache lookup hit a transient infrastructure failure (DB timeout, replica
// failover, etc.). We must NOT render the "not yet analyzed" interstitial in
// this case — that would be a factual misrepresentation, and a crawler that
// sees it could (a) re-queue the URL for re-crawl thinking it's pending and
// (b) skew our published "domains never analyzed" intelligence. Returns 503
// with a no-store cache header so the response is never reused.
func (h *AnalysisHandler) renderCacheLookupUnavailable(c *gin.Context, nonce, csrfToken any, domain string) {
	msg := fmt.Sprintf("Lookup for %s is temporarily unavailable — please retry in a moment.", domain)
	data := h.indexFlashData(c, nonce, csrfToken, "warning", msg)
	data["PrefillDomain"] = domain
	c.Header("Cache-Control", "no-store")
	c.Header("Retry-After", "5")
	c.HTML(http.StatusServiceUnavailable, templateIndex, data)
}

func shouldServeAsyncWait(c *gin.Context, customSelectors []string, exposureChecks bool) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	if c.Query("sync") == "1" {
		return false
	}
	if c.GetHeader("X-Requested-With") == "fetch" {
		return false
	}
	if isAgentCacheEligible(c, customSelectors, exposureChecks) {
		return false
	}
	return true
}

func (h *AnalysisHandler) startDirectAsyncAnalysis(c *gin.Context, inp analyzeInput) string {
	token, sp := h.ProgressStore.NewToken()
	clientIP := c.ClientIP()
	countryCode, countryName := lookupCountry(clientIP)
	traceID := token

	go h.runAsyncScan(token, traceID, sp, inp, clientIP, countryCode, countryName)

	return token
}

func (h *AnalysisHandler) renderWaitingPage(c *gin.Context, token, domain, asciiDomain string) {
	c.Header("Cache-Control", "no-store, private, max-age=0")
	c.Header("X-Robots-Tag", "noindex, nofollow")
	data := NewTemplateData(c, h.Config, "scan")
	data["Domain"] = domain
	data["AsciiDomain"] = asciiDomain
	data["ScanToken"] = token
	data["BaseURL"] = h.Config.BaseURL
	c.HTML(http.StatusOK, "scan_wait.html", data)
}

// scanTimeout bounds a scan and its persistence. 90s predates this helper —
// it was the async path's bound (and agentpkg's, hand-rolled in both places)
// and comfortably covers the slowest observed full scan (~35s pre-#231,
// ~12s since); the constant exists so the sync and async paths cannot drift
// apart again.
const scanTimeout = 90 * time.Second

// scanContext is the context every scan and its save must run on: parent
// VALUES kept (slog trace attribution), parent CANCELLATION dropped, its own
// deadline. A scan is not a page render — once measurement starts, a client
// navigating away must not cancel it or discard its results. Measured
// 2026-07-31 (dev log, google.com): the sync path rode c.Request.Context(),
// so a second form submit's rate-limit redirect killed the first request's
// connection, every DNS query died "context canceled", and 7.46s of
// completed analysis failed to save at severity CRITICAL.
func scanContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), scanTimeout)
}

func (h *AnalysisHandler) runAsyncScan(token, traceID string, sp *scanProgress, inp analyzeInput, clientIP, countryCode, countryName string) {
	ctx, cancel := scanContext(context.Background())
	defer cancel()

	slog.LogAttrs(ctx, slog.LevelInfo, "scan started",
		logging.ScanStarted(inp.asciiDomain, traceID, 0)...)

	scanStart := time.Now()

	results := h.Analyzer.AnalyzeDomain(ctx, inp.asciiDomain, inp.customSelectors, analyzer.AnalysisOptions{
		ExposureChecks:  inp.exposureChecks,
		OnPhaseProgress: sp.MakeInstrumentedProgressCallback(inp.asciiDomain, traceID),
	})
	analysisDuration := time.Since(sp.startTime).Seconds()
	scanElapsedMs := time.Since(scanStart).Milliseconds()

	h.applyConfidenceEngines(results)
	h.enrichResultsAsync(results)

	if failed, _ := isAnalysisFailure(results); failed {
		go h.recordDailyStats(false, analysisDuration)
		slog.LogAttrs(ctx, slog.LevelError, "scan failed",
			logging.ScanFailed(inp.asciiDomain, traceID, "analysis returned failure")...)
		sp.MarkFailed("analysis failed")
		return
	}

	domainExists := resultsDomainExists(results)
	scanClass := scanner.Classify(inp.asciiDomain, clientIP)
	botClass := botverify.Classify(inp.userAgent, clientIP).String()
	postureHash := analyzer.CanonicalPostureHash(results)
	drift := h.detectDrift(ctx, inp.devNull, domainExists, inp.asciiDomain, postureHash, results)

	h.snapshotICAEMetrics(ctx, results)

	telRaw := results["_scan_telemetry"]
	delete(results, "_scan_telemetry")

	isPrivate := inp.hasNovelSelectors && inp.isAuthenticated
	annotateInputNormalization(results, inp)
	analysisID, _ := h.persistOrLogEphemeral(ctx, persistParams{
		domain:            inp.domain,
		asciiDomain:       inp.asciiDomain,
		results:           results,
		analysisDuration:  analysisDuration,
		countryCode:       countryCode,
		countryName:       countryName,
		isPrivate:         isPrivate,
		hasNovelSelectors: inp.hasNovelSelectors,
		scanClass:         scanClass,
		botClass:          botClass,
		ephemeral:         inp.ephemeral,
		domainExists:      domainExists,
		devNull:           inp.devNull,
	})

	h.storeTelemetryFromRaw(ctx, analysisID, telRaw, inp.ephemeral)

	analysisSuccess, _ := extractAnalysisError(results)
	h.handlePostAnalysisSideEffectsAsync(ctx, sideEffectsParams{
		asciiDomain:      inp.asciiDomain,
		analysisID:       analysisID,
		isAuthenticated:  inp.isAuthenticated,
		userID:           inp.userID,
		ephemeral:        inp.ephemeral,
		domainExists:     domainExists,
		drift:            drift,
		postureHash:      postureHash,
		analysisSuccess:  analysisSuccess,
		analysisDuration: analysisDuration,
		isPrivate:        isPrivate,
		isScanFlagged:    scanClass.IsScan,
		results:          results,
	})

	h.recordCurrencyIfEligible(inp.ephemeral, domainExists, inp.asciiDomain, results)

	slog.LogAttrs(ctx, slog.LevelInfo, "scan completed",
		logging.ScanCompleted(inp.asciiDomain, traceID, int(analysisID), scanElapsedMs)...)

	if analysisID > 0 {
		redirectURL := fmt.Sprintf("/analysis/%d", analysisID)
		sp.MarkComplete(analysisID, redirectURL)
	} else {
		sp.MarkComplete(0, "")
	}
}

func (h *AnalysisHandler) analyzeAsync(c *gin.Context, domain, asciiDomain string, customSelectors []string, exposureChecks, devNull, isAuthenticated bool, userID int32, hasNovelSelectors, ephemeral bool) {
	token, sp := h.ProgressStore.NewToken()

	clientIP := c.ClientIP()
	countryCode, countryName := lookupCountry(clientIP)

	traceID := token

	c.JSON(http.StatusAccepted, gin.H{
		"token":       token,
		"domain":      asciiDomain,
		"analysis_id": nil,
	})

	inp := buildAsyncInput(c.Request.UserAgent(), clientIP, domain, asciiDomain, customSelectors,
		exposureChecks, devNull, isAuthenticated, userID, hasNovelSelectors, ephemeral)
	// buildAsyncInput reconstructs analyzeInput from exploded parameters, so
	// any field not in that parameter list is silently dropped — which is how
	// the normalization disclosure went missing on the ONLY path the topology
	// console uses. Re-derive it here from the same request rather than
	// widening the parameter list further.
	if asGiven, changed, discarded := dnsclient.NormalizeDomainInput(extractDomainInput(c)); changed {
		inp.inputAsGiven = extractDomainInput(c)
		inp.inputDiscarded = discarded
		_ = asGiven
	}
	go h.runAsyncScan(token, traceID, sp, inp, clientIP, countryCode, countryName)
}

// buildAsyncInput captures request-time data (notably userAgent) into an
// analyzeInput before the *gin.Context is recycled. The goroutine started by
// analyzeAsync needs userAgent to call botverify.Classify; if userAgent is
// empty the classifier returns "investigate", which previously caused all
// browser-initiated async scans to be tagged as investigate (v26.48.04 bug).
// Takes primitives (not *gin.Context) so callers cannot accidentally invoke
// it after the context has been recycled.
func buildAsyncInput(userAgent, clientIP, domain, asciiDomain string, customSelectors []string,
	exposureChecks, devNull, isAuthenticated bool, userID int32,
	hasNovelSelectors, ephemeral bool) analyzeInput {
	return analyzeInput{
		domain:            domain,
		asciiDomain:       asciiDomain,
		customSelectors:   customSelectors,
		exposureChecks:    exposureChecks,
		devNull:           devNull,
		isAuthenticated:   isAuthenticated,
		userID:            userID,
		hasNovelSelectors: hasNovelSelectors,
		ephemeral:         ephemeral,
		userAgent:         userAgent,
		clientIP:          clientIP,
	}
}

func applyDevNullHeaders(c *gin.Context, devNull bool) {
	if devNull {
		c.Header("X-Hacker", "MUST means MUST -- not kinda, maybe, should. // DNS Tool")
		c.Header("X-Persistence", "/dev/null")
	}
}

func extractAuthInfo(c *gin.Context) (bool, int32) {
	isAuthenticated := false
	var userID int32
	if auth, exists := c.Get(mapKeyAuthenticated); exists && auth == true {
		isAuthenticated = true
		if uid, ok := c.Get(mapKeyUserId); ok {
			if id, idOk := uid.(int32); idOk {
				userID = id
			}
		}
	}
	return isAuthenticated, userID
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

func resultsDomainExists(results map[string]any) bool {
	if v, ok := results["domain_exists"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return true
}
