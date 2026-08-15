// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "context"
        "encoding/hex"
        "encoding/json"
        "log/slog"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"
        "dnstool/go-server/internal/middleware"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/sha3"
)

type EDEAmendment struct {
        Ground        string `json:"ground"`
        Date          string `json:"date"`
        FieldChanged  string `json:"field_changed"`
        OriginalValue string `json:"original_value"`
        CorrectedTo   string `json:"corrected_to"`
        Evidence      string `json:"evidence"`
        Rationale     string `json:"rationale"`
        Justification string `json:"justification"`
}

type IntegrityEvent struct {
        ID                  string         `json:"id"`
        Date                string         `json:"date"`
        Commit              string         `json:"commit"`
        Category            string         `json:"category"`
        Severity            string         `json:"severity"`
        Title               string         `json:"title"`
        Status              string         `json:"status"`
        Attribution         string         `json:"attribution"`
        ProtocolsAffected   []string       `json:"protocols_affected"`
        ConfidenceImpact    string         `json:"confidence_impact"`
        Resolution          string         `json:"resolution"`
        BayesianNote        string         `json:"bayesian_note"`
        CorrectionAction    string         `json:"correction_action"`
        PreventionRule      string         `json:"prevention_rule"`
        AuthoritativeSource string         `json:"authoritative_source"`
        Amendments          []EDEAmendment `json:"amendments,omitempty"`
        EventHash           string         `json:"-"`
}

type IntegritySummary struct {
        TotalEvents              int      `json:"total_events"`
        Open                     int      `json:"open"`
        Closed                   int      `json:"closed"`
        LastEventDate            string   `json:"last_event_date"`
        ConfidenceRecalibrations int      `json:"confidence_recalibrations"`
        ProtocolsAffected        []string `json:"protocols_affected"`
}

type TamperResistancePolicy struct {
        Enabled       bool   `json:"enabled"`
        Effective     string `json:"effective"`
        Standard      string `json:"standard"`
        AmendmentRule string `json:"amendment_rule"`
}

type IntegrityData struct {
        Summary               IntegritySummary       `json:"summary"`
        Events                []IntegrityEvent       `json:"events"`
        Taxonomy              map[string]string      `json:"taxonomy"`
        TamperResistancePolicy TamperResistancePolicy `json:"tamper_resistance_policy"`
        SHA3Hash              string                 `json:"-"`
}

var (
        integrityCache     IntegrityData
        integrityCacheMu   sync.RWMutex
        integrityCacheTime time.Time
)

var (
        dnssecUnmeasuredCache        int64
        dnssecUnmeasuredCacheMu      sync.RWMutex
        dnssecUnmeasuredCacheTime    time.Time
        dnssecIndeterminateCache     int64
        dnssecIndeterminateCacheMu   sync.RWMutex
        dnssecIndeterminateCacheTime time.Time
)

// cachedDNSSECUnmeasured returns the DNSSEC-unmeasured instrument-health count
// cached for 5 minutes. It is a corpus-level signal over ~18k rows that does not
// need per-request freshness, and the underlying query reaches into the
// full_results JSON payload (indexed by migration 022). Caching removes the
// per-request exposure so /stats is fast even if the index plan disappoints.
func (h *StatsHandler) cachedDNSSECUnmeasured(ctx context.Context) int64 {
        dnssecUnmeasuredCacheMu.RLock()
        if !dnssecUnmeasuredCacheTime.IsZero() && time.Since(dnssecUnmeasuredCacheTime) < 5*time.Minute {
                v := dnssecUnmeasuredCache
                dnssecUnmeasuredCacheMu.RUnlock()
                return v
        }
        dnssecUnmeasuredCacheMu.RUnlock()

        dnssecUnmeasuredCacheMu.Lock()
        defer dnssecUnmeasuredCacheMu.Unlock()
        if !dnssecUnmeasuredCacheTime.IsZero() && time.Since(dnssecUnmeasuredCacheTime) < 5*time.Minute {
                return dnssecUnmeasuredCache
        }

        count, err := h.DB.Queries.CountDNSSECUnmeasured(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count DNSSEC-unmeasured scans", mapKeyError, err)
                return dnssecUnmeasuredCache // stale value on error, never fabricate 0
        }
        dnssecUnmeasuredCache = count
        dnssecUnmeasuredCacheTime = time.Now()
        return count
}

// cachedDNSSECIndeterminate returns the DNSSEC-indeterminate corpus count,
// cached for 5 minutes. Distinct from cachedDNSSECUnmeasured (instrument-health,
// "our scans are timing out"): this is "we measured and the protocol couldn't
// attribute" (RFC 4033 §5) — a corpus property, expected and stable, not an
// alarm. Indexed by migration 023.
func (h *StatsHandler) cachedDNSSECIndeterminate(ctx context.Context) int64 {
        dnssecIndeterminateCacheMu.RLock()
        if !dnssecIndeterminateCacheTime.IsZero() && time.Since(dnssecIndeterminateCacheTime) < 5*time.Minute {
                v := dnssecIndeterminateCache
                dnssecIndeterminateCacheMu.RUnlock()
                return v
        }
        dnssecIndeterminateCacheMu.RUnlock()

        dnssecIndeterminateCacheMu.Lock()
        defer dnssecIndeterminateCacheMu.Unlock()
        if !dnssecIndeterminateCacheTime.IsZero() && time.Since(dnssecIndeterminateCacheTime) < 5*time.Minute {
                return dnssecIndeterminateCache
        }

        count, err := h.DB.Queries.CountDNSSECIndeterminate(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count DNSSEC-indeterminate scans", mapKeyError, err)
                return dnssecIndeterminateCache // stale value on error, never fabricate 0
        }
        dnssecIndeterminateCache = count
        dnssecIndeterminateCacheTime = time.Now()
        return count
}

func loadIntegrityData() IntegrityData {
        integrityCacheMu.RLock()
        if !integrityCacheTime.IsZero() && time.Since(integrityCacheTime) < 5*time.Minute {
                cached := integrityCache
                integrityCacheMu.RUnlock()
                return cached
        }
        integrityCacheMu.RUnlock()

        integrityCacheMu.Lock()
        defer integrityCacheMu.Unlock()

        if !integrityCacheTime.IsZero() && time.Since(integrityCacheTime) < 5*time.Minute {
                return integrityCache
        }

        // Resolved through the same candidate list as asset serving — a bare
        // "static/…" path here silently emptied /stats whenever the live tree
        // was go-server/static (candidate 2) or the cwd was wrong.
        data, err := os.ReadFile(filepath.Join(ResolveStaticDir(), "data", "integrity_stats.json"))
        if err != nil {
                slog.Warn("Stats: failed to read integrity_stats.json", mapKeyError, err)
                return IntegrityData{}
        }
        hash := sha3.Sum512(data)
        hashHex := hex.EncodeToString(hash[:])

        var f IntegrityData
        if err := json.Unmarshal(data, &f); err != nil {
                slog.Warn("Stats: failed to parse integrity_stats.json", mapKeyError, err)
                return IntegrityData{}
        }
        f.SHA3Hash = hashHex
        for i := range f.Events {
                redactDignityAmendments(&f.Events[i])
                hashEvent(&f.Events[i])
        }
        for i, j := 0, len(f.Events)-1; i < j; i, j = i+1, j-1 {
                f.Events[i], f.Events[j] = f.Events[j], f.Events[i]
        }
        integrityCache = f
        integrityCacheTime = time.Now()
        return f
}

func redactDignityAmendments(event *IntegrityEvent) {
        for j := range event.Amendments {
                if event.Amendments[j].Ground == "DIGNITY_OF_EXPRESSION" &&
                        event.Amendments[j].OriginalValue != "[REDACTED — DIGNITY_OF_EXPRESSION]" {
                        event.Amendments[j].OriginalValue = "[REDACTED — DIGNITY_OF_EXPRESSION]"
                }
        }
}

func hashEvent(event *IntegrityEvent) {
        eventJSON, err := json.Marshal(event)
        if err == nil {
                eh := sha3.Sum512(eventJSON)
                event.EventHash = hex.EncodeToString(eh[:])
        }
}

type StatsHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewStatsHandler(database *db.Database, cfg *config.Config) *StatsHandler {
        return &StatsHandler{DB: database, Config: cfg}
}

func (h *StatsHandler) Stats(c *gin.Context) {
        ctx := c.Request.Context()

        recentStats, err := h.DB.Queries.ListRecentStats(ctx, 30)
        if err != nil {
                errData := NewTemplateData(c, h.Config, "stats")
                errData["FlashMessages"] = []FlashMessage{{Category: "danger", Message: "Failed to fetch stats"}}
                c.HTML(http.StatusInternalServerError, "stats.html", errData)
                return
        }

        statsSummary, err := h.DB.Queries.SumAnalysisStats(ctx)
        if err != nil {
                slog.Warn("Stats: failed to sum analysis stats", mapKeyError, err)
        }
        totalAnalyses := statsSummary.Total
        successfulAnalyses := statsSummary.Successful
        failedAnalyses := statsSummary.Failed
        uniqueDomains, err := h.DB.Queries.CountUniqueDomainsTotal(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count unique domains", mapKeyError, err)
        }

        popularDomains, err := h.DB.Queries.ListPopularDomains(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list popular domains", mapKeyError, err)
        }
        // Additive provenance leaderboards. Each is shown as its own column on the
        // stats page so users can see plugin, human, verified-bot, and investigate
        // traffic independently — none is hidden behind the others, and the four
        // buckets are mutually exclusive (plugin traffic takes precedence and is
        // excluded from the human/bot/investigate buckets so it is never
        // double-counted). See internal/botverify/verify.go for how scan_source
        // values are assigned and db/queries/domain_analyses.sql for the bucket SQL.
        popularHuman, err := h.DB.Queries.ListPopularDomainsHuman(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list human-popular domains", mapKeyError, err)
        }
        popularPlugin, err := h.DB.Queries.ListPopularDomainsPlugin(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list plugin-popular domains", mapKeyError, err)
        }
        popularVerifiedBot, err := h.DB.Queries.ListPopularDomainsVerifiedBot(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list verified-bot-popular domains", mapKeyError, err)
        }
        popularInvestigate, err := h.DB.Queries.ListPopularDomainsInvestigate(ctx, 10)
        if err != nil {
                slog.Warn("Stats: failed to list investigate-popular domains", mapKeyError, err)
        }
        countryStats, err := h.DB.Queries.ListCountryDistribution(ctx, 20)
        if err != nil {
                slog.Warn("Stats: failed to list country distribution", mapKeyError, err)
        }

        maxRecentStats := 7
        if len(recentStats) < maxRecentStats {
                maxRecentStats = len(recentStats)
        }
        slicedStats := recentStats[:maxRecentStats]

        statItems := make([]DailyStat, 0, len(slicedStats))
        for _, s := range slicedStats {
                statItems = append(statItems, buildDailyStat(s))
        }

        popItems := make([]PopularDomain, 0, len(popularDomains))
        for _, d := range popularDomains {
                popItems = append(popItems, PopularDomain{Domain: d.Domain, Count: d.Count})
        }
        popItemsHuman := make([]PopularDomain, 0, len(popularHuman))
        for _, d := range popularHuman {
                popItemsHuman = append(popItemsHuman, PopularDomain{Domain: d.Domain, Count: d.Count})
        }
        popItemsPlugin := make([]PopularDomain, 0, len(popularPlugin))
        for _, d := range popularPlugin {
                popItemsPlugin = append(popItemsPlugin, PopularDomain{Domain: d.Domain, Count: d.Count})
        }
        popItemsVerifiedBot := make([]PopularDomain, 0, len(popularVerifiedBot))
        for _, d := range popularVerifiedBot {
                popItemsVerifiedBot = append(popItemsVerifiedBot, PopularDomain{Domain: d.Domain, Count: d.Count})
        }
        popItemsInvestigate := make([]PopularDomain, 0, len(popularInvestigate))
        for _, d := range popularInvestigate {
                popItemsInvestigate = append(popItemsInvestigate, PopularDomain{Domain: d.Domain, Count: d.Count})
        }

        countryItems := make([]CountryStat, 0, len(countryStats))
        for _, cs := range countryStats {
                countryItems = append(countryItems, buildCountryStat(cs))
        }

        remediatedDomains, err := h.DB.Queries.CountRemediatedDomains(ctx)
        if err != nil {
                slog.Warn("Stats: failed to count remediated domains", mapKeyError, err)
        }

        // Corpus-level instrument-health counter: how many scans could not
        // MEASURE DNSSEC (DNSKEY/DS lookup failed, or no validator cast a
        // usable AD-flag vote). A climbing count is OUR resolver probes
        // failing, not a domain finding — see CountDNSSECUnmeasured.
        dnssecUnmeasured := h.cachedDNSSECUnmeasured(ctx)
        dnssecIndeterminate := h.cachedDNSSECIndeterminate(ctx)

        // True unique visitors via HyperLogLog++ union across every persisted
        // daily sketch. SUM(unique_visitors) is mathematically wrong (it
        // double-counts every returning visitor because the per-day pseudoID
        // salt rotates daily); HLL with a stable salt is mergeable across
        // days and yields a true distinct count with bounded relative error
        // (~0.81% at p=14). See go-server/db/migrations/014_site_analytics_hll.sql
        // for full citations (Flajolet 2007; Heule 2013).
        trueUnique := middleware.ComputeTrueUniqueVisitors(ctx, h.DB.Pool, time.Time{}, time.Time{})
        var uniqueVisitors int64
        if trueUnique.OK {
                uniqueVisitors = int64(trueUnique.Estimate)
        }

        integrityData := loadIntegrityData()

        data := NewTemplateData(c, h.Config, "stats")
        data["TotalAnalyses"] = totalAnalyses
        data["SuccessfulAnalyses"] = successfulAnalyses
        data["FailedAnalyses"] = failedAnalyses
        data["UniqueDomains"] = uniqueDomains
        data["UniqueVisitors"] = uniqueVisitors
        data["UniqueVisitorsAvailable"] = trueUnique.OK
        data["UniqueVisitorsDays"] = trueUnique.DaysCovered
        data["UniqueVisitorsErrPct"] = trueUnique.StdErrorPct
        data["CountryStats"] = countryItems
        data["PopularDomains"] = popItems
        data["PopularDomainsHuman"] = popItemsHuman
        data["PopularDomainsPlugin"] = popItemsPlugin
        data["PopularDomainsVerifiedBot"] = popItemsVerifiedBot
        data["PopularDomainsInvestigate"] = popItemsInvestigate
        data["RecentStats"] = statItems
        data["RemediatedDomains"] = remediatedDomains
        data["DNSSECUnmeasured"] = dnssecUnmeasured
        data["DNSSECIndeterminate"] = dnssecIndeterminate
        data["IntegrityData"] = integrityData
        c.HTML(http.StatusOK, "stats.html", data)
}

func buildDailyStat(s dbq.AnalysisStat) DailyStat {
        dateStr := ""
        if s.Date.Valid {
                dateStr = s.Date.Time.Format("01/02")
        }
        var total, successful, failed, unique int32
        if s.TotalAnalyses != nil {
                total = *s.TotalAnalyses
        }
        if s.SuccessfulAnalyses != nil {
                successful = *s.SuccessfulAnalyses
        }
        if s.FailedAnalyses != nil {
                failed = *s.FailedAnalyses
        }
        if s.UniqueDomains != nil {
                unique = *s.UniqueDomains
        }
        var avg float64
        hasAvg := false
        if s.AvgAnalysisTime != nil {
                avg = *s.AvgAnalysisTime
                hasAvg = true
        }
        return DailyStat{
                Date:               dateStr,
                TotalAnalyses:      total,
                SuccessfulAnalyses: successful,
                FailedAnalyses:     failed,
                UniqueDomains:      unique,
                AvgAnalysisTime:    avg,
                HasAvgTime:         hasAvg,
        }
}

func buildCountryStat(cs dbq.ListCountryDistributionRow) CountryStat {
        code, name := "", ""
        if cs.CountryCode != nil {
                code = *cs.CountryCode
        }
        if cs.CountryName != nil {
                name = *cs.CountryName
        }
        flag := ""
        if len(code) == 2 {
                upper := strings.ToUpper(code)
                r1 := rune(0x1F1E6 + int(upper[0]) - int('A'))
                r2 := rune(0x1F1E6 + int(upper[1]) - int('A'))
                flag = string([]rune{r1, r2})
        }
        return CountryStat{Code: code, Name: name, Count: cs.Count, Flag: flag}
}

func (h *StatsHandler) StatisticsRedirect(c *gin.Context) {
        c.Redirect(http.StatusMovedPermanently, "/stats")
}
