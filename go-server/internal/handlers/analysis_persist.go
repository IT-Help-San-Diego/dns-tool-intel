// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/scanner"
)

type persistParams struct {
	domain, asciiDomain      string
	results                  map[string]any
	analysisDuration         float64
	countryCode, countryName string
	isPrivate                bool
	hasNovelSelectors        bool
	scanClass                scanner.Classification
	// botClass is the verified-bot classification ("human", "verified_bot:<name>",
	// or "investigate"). When non-empty AND scanClass.IsScan is false, this
	// becomes the persisted scan_source value so the leaderboard can split
	// human vs verified-bot vs investigate traffic. scanner.Classification still
	// wins when it identifies a security-tool scan (Qualys/CISA/etc).
	botClass  string
	ephemeral bool
	// domainExists is DEPRECATED — callers now read domain_status directly
	// from results. Kept as a struct field for compile-time compatibility
	// until all call sites are updated.
	domainExists bool
	devNull      bool
}

func (h *AnalysisHandler) persistOrLogEphemeral(ctx context.Context, p persistParams) (int32, string) {
	isSuccess, _ := extractAnalysisError(p.results) //nolint:errcheck // error message not needed here
	domainStatus, _ := p.results["domain_status"].(string)
	if persist, _ := shouldPersistResult(p.ephemeral, p.devNull, domainStatus, isSuccess); !persist {
		logEphemeralReason(p.asciiDomain, p.devNull, domainStatus)
		return 0, time.Now().UTC().Format(strUtc)
	}
	if h.store() == nil {
		slog.Warn("No store configured, skipping persist", mapKeyDomain, p.asciiDomain)
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
		botClass:         p.botClass,
	})
}

func logEphemeralReason(asciiDomain string, devNull bool, domainStatus string) {
	if devNull {
		slog.Info("/dev/null scan — full analysis, zero persistence", mapKeyDomain, asciiDomain)
	} else if domainStatus == "undelegated" {
		slog.Info("Undelegated domain — not persisted", mapKeyDomain, asciiDomain)
	} else {
		slog.Info("Ephemeral analysis (custom DKIM selectors, unauthenticated) — not persisted", mapKeyDomain, asciiDomain)
	}
}

func shouldPersistResult(ephemeral, devNull bool, domainStatus string, analysisSuccess bool) (persist bool, reason string) {
	if devNull {
		return false, "devnull"
	}
	if ephemeral {
		return false, "ephemeral"
	}
	// Drop only a positively-confirmed absence. "undelegated" is an authoritative
	// NXDOMAIN — the domain is genuinely non-existent. "indeterminate" (all
	// nameservers unreachable / SERVFAIL) is a finding — a domain whose DNS is
	// down is not an absence — and is kept.
	if domainStatus == "undelegated" && analysisSuccess {
		return false, "nonexistent_domain"
	}
	return true, ""
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
	// botClass: "human" | "verified_bot:<name>" | "investigate" | "" (unknown).
	// Used as the persisted scan_source when scanner.Classification did not flag
	// a security-tool scan, so the leaderboard can split human vs bot traffic.
	botClass string
}

func (h *AnalysisHandler) saveAnalysis(ctx context.Context, p saveAnalysisInput) (int32, string) {
	p.results["_tool_version"] = h.Config.AppVersion
	fullResultsJSON, marshalErr := json.Marshal(p.results)
	if marshalErr != nil {
		slog.Error("Failed to marshal results", mapKeyDomain, p.domain, mapKeyError, marshalErr)
		return 0, time.Now().UTC().Format(strUtc)
	}

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
	scanSource, scanIP := extractScanFields(p.scanClass, p.botClass)

	params := dbq.InsertAnalysisParams{
		Domain:               p.domain,
		AsciiDomain:          p.asciiDomain,
		AppVersion:           h.Config.AppVersion,
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

	row, err := h.store().InsertAnalysis(ctx, params)
	if err != nil {
		slog.Error("Failed to save analysis", mapKeyDomain, p.domain, mapKeyError, err)
		return 0, time.Now().UTC().Format(strUtc)
	}

	if success {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.store().UpsertDomainIndex(bgCtx, dbq.UpsertDomainIndexParams{
				Domain:    p.domain,
				HasDane:   analysisHasProtocol(p.results, "dane_analysis"),
				HasDnssec: analysisHasProtocol(p.results, "dnssec_analysis"),
				HasMtaSts: analysisHasProtocol(p.results, "mta_sts_analysis"),
			}); err != nil {
				slog.Warn("domain index upsert failed", "domain", p.domain, "error", err)
			}
		}()
	}

	timestamp := "just now"
	if row.CreatedAt.Valid {
		timestamp = row.CreatedAt.Time.Format(strUtc)
	}
	return row.ID, timestamp
}

func (h *AnalysisHandler) SaveForAgent(ctx context.Context, domain, asciiDomain string, results map[string]any) int32 {
	id, _ := h.saveAnalysis(ctx, saveAnalysisInput{
		domain:      domain,
		asciiDomain: asciiDomain,
		results:     results,
	})
	return id
}

func analysisHasProtocol(results map[string]any, key string) bool {
	section, ok := results[key].(map[string]any)
	if !ok {
		return false
	}
	status, _ := section["status"].(string)
	return status == "success" || status == "warning"
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

// extractScanFields chooses the scan_source and scan_ip values to persist for
// a domain analysis row.
//
//   - When the security-tool scanner classifier flagged the request (Qualys,
//     CISA, etc.), its Source string wins. This preserves existing behaviour
//     for security-tool detection and the existing scanner-alerts dashboard.
//   - Otherwise, the verified-bot classification (botClass) is used —
//     "human", "verified_bot:<name>", or "investigate" — so the leaderboard
//     can split traffic by provenance.
//   - When neither applies (e.g. callers that pass an empty botClass), no
//     scan_source is set, preserving legacy NULL semantics.
//
// scan_ip is taken from the scanner classification when present.
func extractScanFields(sc scanner.Classification, botClass string) (*string, *string) {
	var scanSource, scanIP *string
	switch {
	case sc.IsScan:
		s := sc.Source
		scanSource = &s
	case botClass != "":
		b := botClass
		scanSource = &b
	}
	if sc.IP != "" {
		ip := sc.IP
		scanIP = &ip
	}
	return scanSource, scanIP
}

var countryCache sync.Map

type countryEntry struct {
	code, name string
	fetched    time.Time
}

var countryCacheEvictOnce sync.Once

func startCountryCacheEviction() {
	countryCacheEvictOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				countryCache.Range(func(key, value any) bool {
					if entry, ok := value.(countryEntry); ok {
						if now.Sub(entry.fetched) > 24*time.Hour {
							countryCache.Delete(key)
						}
					}
					return true
				})
			}
		}()
	})
}

func lookupCountry(ip string) (string, string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" { // S1313: loopback check — intentional
		return "", ""
	}

	startCountryCacheEviction()

	if cached, ok := countryCache.Load(ip); ok {
		entry, valid := cached.(countryEntry)
		if valid && time.Since(entry.fetched) < 24*time.Hour {
			return entry.code, entry.name
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ip-api.com/json/%s?fields=status,countryCode,country", ip))
	if err != nil {
		return "", ""
	}
	defer safeClose(resp.Body, "openphish response body")

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
