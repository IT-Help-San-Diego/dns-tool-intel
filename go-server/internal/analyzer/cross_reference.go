// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "sort"
        "strings"
        "sync"
        "time"
)

const (
        mapKeyCrossRef = "cross_reference"

        crossRefSchemaVersion = "1.0"
        crossRefMaxBodyBytes  = 64 * 1024

        providerGoogle     = "google"
        providerCloudflare = "cloudflare"

        googleDoHEndpoint     = "https://dns.google/resolve"
        cloudflareDoHEndpoint = "https://cloudflare-dns.com/dns-query"

        googleDigToolbox = "https://toolbox.googleapps.com/apps/dig/#"
)

var crossRefRecordTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"}

type CrossRefProvider struct {
        Name      string            `json:"name"`
        Endpoint  string            `json:"endpoint"`
        Status    string            `json:"status"`
        LatencyMs int               `json:"latency_ms"`
        Records   map[string][]string `json:"records"`
        Failed    map[string]bool   `json:"failed,omitempty"`
        QueryURLs map[string]string `json:"query_urls"`
}

type CrossRefComparison struct {
        RecordType   string   `json:"record_type"`
        OurRecords   []string `json:"our_records"`
        TheirRecords []string `json:"their_records"`
        Match        string   `json:"match"`
}

type CrossRefResult struct {
        SchemaVersion string                        `json:"schema_version"`
        GeneratedAt   string                        `json:"generated_at"`
        Domain        string                        `json:"domain"`
        RecordTypes   []string                      `json:"record_types"`
        Providers     map[string]*CrossRefProvider   `json:"providers"`
        Comparisons   map[string][]CrossRefComparison `json:"comparisons"`
        Summary       CrossRefSummary               `json:"summary"`
        ManualVerify  map[string]string             `json:"manual_verify"`
}

type CrossRefSummary struct {
        TotalChecks    int    `json:"total_checks"`
        Matched        int    `json:"matched"`
        Absent         int    `json:"absent"`
        Partial        int    `json:"partial"`
        Mismatched     int    `json:"mismatched"`
        Unavailable    int    `json:"unavailable"`
        Verdict        string `json:"verdict"`
}

type dohAnswer struct {
        Name string `json:"name"`
        Type int    `json:"type"`
        TTL  int    `json:"TTL"`
        Data string `json:"data"`
}

type dohResponse struct {
        Status   int         `json:"Status"`
        TC       bool        `json:"TC"`
        RD       bool        `json:"RD"`
        RA       bool        `json:"RA"`
        AD       bool        `json:"AD"`
        CD       bool        `json:"CD"`
        Answer   []dohAnswer `json:"Answer"`
        Question []struct {
                Name string `json:"name"`
                Type int    `json:"type"`
        } `json:"Question"`
}

var dnsTypeMap = map[string]int{
        "A":     1,
        "AAAA":  28,
        "MX":    15,
        "NS":    2,
        "TXT":   16,
        "CNAME": 5,
}

var crossRefHTTPClient = &http.Client{
        Timeout: 3 * time.Second,
        Transport: &http.Transport{
                MaxIdleConns:        4,
                MaxIdleConnsPerHost: 2,
                IdleConnTimeout:     5 * time.Second,
                DisableKeepAlives:   true,
        },
}

func (a *Analyzer) CrossReferenceRecords(ctx context.Context, domain string, basicRecords map[string]any) map[string]any {
        budget := 6 * time.Second
        xrefCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
        defer cancel()

        now := time.Now().UTC()
        result := &CrossRefResult{
                SchemaVersion: crossRefSchemaVersion,
                GeneratedAt:   now.Format(time.RFC3339),
                Domain:        domain,
                RecordTypes:   crossRefRecordTypes,
                Providers:     make(map[string]*CrossRefProvider),
                Comparisons:   make(map[string][]CrossRefComparison),
                ManualVerify:  buildManualVerifyLinks(domain),
        }

        var wg sync.WaitGroup
        var mu sync.Mutex

        providers := []struct {
                name     string
                endpoint string
                queryFn  func(ctx context.Context, domain, rtype string) ([]string, string, error)
        }{
                {providerGoogle, googleDoHEndpoint, queryGoogleDoH},
                {providerCloudflare, cloudflareDoHEndpoint, queryCloudflareDoH},
        }

        for _, p := range providers {
                wg.Add(1)
                go func(name, endpoint string, queryFn func(ctx context.Context, domain, rtype string) ([]string, string, error)) {
                        defer wg.Done()

                        provider := &CrossRefProvider{
                                Name:      name,
                                Endpoint:  endpoint,
                                Records:   make(map[string][]string),
                                Failed:    make(map[string]bool),
                                QueryURLs: make(map[string]string),
                        }

                        start := time.Now()
                        allOK := true

                        for _, rt := range crossRefRecordTypes {
                                records, queryURL, err := queryFn(xrefCtx, domain, rt)
                                provider.QueryURLs[rt] = queryURL
                                if err != nil {
                                        slog.Warn("CrossRef DoH query failed", "provider", name, "type", rt, "domain", domain, "error", err)
                                        allOK = false
                                        provider.Records[rt] = []string{}
                                        provider.Failed[rt] = true
                                        continue
                                }
                                sort.Strings(records)
                                provider.Records[rt] = records
                        }

                        provider.LatencyMs = int(time.Since(start).Milliseconds())
                        if allOK {
                                provider.Status = "ok"
                        } else {
                                provider.Status = "partial"
                        }

                        mu.Lock()
                        result.Providers[name] = provider
                        mu.Unlock()
                }(p.name, p.endpoint, p.queryFn)
        }

        wg.Wait()

        buildComparisons(result, basicRecords)
        computeSummary(result)

        return crossRefToMap(result)
}

func queryGoogleDoH(ctx context.Context, domain, rtype string) ([]string, string, error) {
        typeNum, ok := dnsTypeMap[rtype]
        if !ok {
                return nil, "", fmt.Errorf("unsupported record type: %s", rtype)
        }

        url := fmt.Sprintf("%s?name=%s&type=%s", googleDoHEndpoint, domain, rtype)
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
                return nil, url, err
        }
        req.Header.Set("Accept", "application/dns-json")

        resp, err := crossRefHTTPClient.Do(req)
        if err != nil {
                return nil, url, err
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, crossRefMaxBodyBytes))
        if err != nil {
                return nil, url, err
        }

        var doh dohResponse
        if err := json.Unmarshal(body, &doh); err != nil {
                return nil, url, err
        }

        return extractAnswers(doh, typeNum, rtype), url, nil
}

func queryCloudflareDoH(ctx context.Context, domain, rtype string) ([]string, string, error) {
        typeNum, ok := dnsTypeMap[rtype]
        if !ok {
                return nil, "", fmt.Errorf("unsupported record type: %s", rtype)
        }

        url := fmt.Sprintf("%s?name=%s&type=%s", cloudflareDoHEndpoint, domain, rtype)
        req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err != nil {
                return nil, url, err
        }
        req.Header.Set("Accept", "application/dns-json")

        resp, err := crossRefHTTPClient.Do(req)
        if err != nil {
                return nil, url, err
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, crossRefMaxBodyBytes))
        if err != nil {
                return nil, url, err
        }

        var doh dohResponse
        if err := json.Unmarshal(body, &doh); err != nil {
                return nil, url, err
        }

        return extractAnswers(doh, typeNum, rtype), url, nil
}

func extractAnswers(doh dohResponse, typeNum int, rtype string) []string {
        var records []string
        for _, ans := range doh.Answer {
                if ans.Type != typeNum {
                        continue
                }
                data := normalizeRecordData(ans.Data, rtype)
                records = append(records, data)
        }
        if records == nil {
                records = []string{}
        }
        return records
}

func normalizeRecordData(data, rtype string) string {
        data = strings.TrimSuffix(data, ".")

        if rtype == "TXT" {
                data = strings.TrimPrefix(data, "\"")
                data = strings.TrimSuffix(data, "\"")
        }

        if rtype == "MX" {
                parts := strings.SplitN(data, " ", 2)
                if len(parts) == 2 {
                        host := strings.TrimSuffix(parts[1], ".")
                        data = parts[0] + " " + host
                }
        }

        return data
}

func buildComparisons(result *CrossRefResult, basicRecords map[string]any) {
        for provName, prov := range result.Providers {
                var comparisons []CrossRefComparison
                for _, rt := range crossRefRecordTypes {
                        ourRaw, _ := basicRecords[rt]
                        ourRecords := anyToStringSlice(ourRaw)
                        sort.Strings(ourRecords)

                        theirRecords := prov.Records[rt]

                        match := compareRecordSets(ourRecords, theirRecords, rt, prov.Failed[rt])

                        comparisons = append(comparisons, CrossRefComparison{
                                RecordType:   rt,
                                OurRecords:   ourRecords,
                                TheirRecords: theirRecords,
                                Match:        match,
                        })
                }
                result.Comparisons[provName] = comparisons
        }
}

func compareRecordSets(ours, theirs []string, rtype string, theirFailed bool) string {
        // A failed provider lookup is not a measurement of absence — it is
        // "could not verify" (unavailable), never corroboration of an absent
        // record. Absence is corroborated only when BOTH sides queried
        // successfully and found nothing.
        if theirFailed {
                return "unavailable"
        }

        oursNorm := normalizeSet(ours, rtype)
        theirsNorm := normalizeSet(theirs, rtype)

        if len(oursNorm) == 0 && len(theirsNorm) == 0 {
                return "absent"
        }

        if setsEqual(oursNorm, theirsNorm) {
                return "match"
        }

        if setsOverlap(oursNorm, theirsNorm) {
                return "partial"
        }

        return "mismatch"
}

func normalizeSet(records []string, rtype string) []string {
        var out []string
        for _, r := range records {
                n := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r, ".")))
                if n != "" {
                        out = append(out, n)
                }
        }
        sort.Strings(out)
        return out
}

func setsEqual(a, b []string) bool {
        if len(a) != len(b) {
                return false
        }
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

func setsOverlap(a, b []string) bool {
        set := make(map[string]bool, len(a))
        for _, v := range a {
                set[v] = true
        }
        for _, v := range b {
                if set[v] {
                        return true
                }
        }
        return false
}

func anyToStringSlice(v any) []string {
        if v == nil {
                return []string{}
        }
        switch val := v.(type) {
        case []string:
                return val
        case []any:
                out := make([]string, 0, len(val))
                for _, item := range val {
                        if s, ok := item.(string); ok {
                                out = append(out, s)
                        }
                }
                return out
        }
        return []string{}
}

func computeSummary(result *CrossRefResult) {
        total := 0
        matched := 0
        absent := 0
        partial := 0
        mismatched := 0
        unavailable := 0

        for _, comps := range result.Comparisons {
                for _, c := range comps {
                        total++
                        switch c.Match {
                        case "match":
                                matched++
                        case "partial":
                                partial++
                        case "absent":
                                absent++
                        case "mismatch":
                                mismatched++
                        case "unavailable":
                                unavailable++
                        }
                }
        }

        verdict := "corroborated"
        if mismatched > 0 || partial > 0 {
                verdict = "discrepancy_detected"
        }
        if unavailable == total && total > 0 {
                verdict = "verification_unavailable"
        }

        result.Summary = CrossRefSummary{
                TotalChecks: total,
                Matched:     matched,
                Absent:      absent,
                Partial:     partial,
                Mismatched:  mismatched,
                Unavailable: unavailable,
                Verdict:     verdict,
        }
}

func buildManualVerifyLinks(domain string) map[string]string {
        return map[string]string{
                "google_dig_a":    googleDigToolbox + "A/" + domain,
                "google_dig_mx":   googleDigToolbox + "MX/" + domain,
                "google_dig_ns":   googleDigToolbox + "NS/" + domain,
                "google_dig_txt":  googleDigToolbox + "TXT/" + domain,
                "google_doh":      fmt.Sprintf("%s?name=%s&type=A", googleDoHEndpoint, domain),
                "cloudflare_doh":  fmt.Sprintf("%s?name=%s&type=A", cloudflareDoHEndpoint, domain),
        }
}

func buildUnavailableResult(domain, reason string) map[string]any {
        r := &CrossRefResult{
                SchemaVersion: crossRefSchemaVersion,
                GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
                Domain:        domain,
                RecordTypes:   crossRefRecordTypes,
                Providers:     make(map[string]*CrossRefProvider),
                Comparisons:   make(map[string][]CrossRefComparison),
                ManualVerify:  buildManualVerifyLinks(domain),
                Summary: CrossRefSummary{
                        Verdict: "verification_unavailable",
                },
        }
        for _, name := range []string{providerGoogle, providerCloudflare} {
                r.Providers[name] = &CrossRefProvider{
                        Name:     name,
                        Status:   "skipped",
                }
        }
        _ = reason
        return crossRefToMap(r)
}

func crossRefToMap(r *CrossRefResult) map[string]any {
        b, _ := json.Marshal(r)
        var m map[string]any
        json.Unmarshal(b, &m)
        return m
}

// RebucketCrossRefSummary recomputes the five-way summary from the persisted
// comparisons, so rows written before the present/absent/partial split (which
// folded corroborated-absences and soft mismatches into "matched") render the
// same honest numbers as a fresh scan. It is idempotent: a new-shape summary
// recomputes to itself, and a new-shape "match" is always present-and-equal so
// the both-empty disambiguation only rewrites the old conflated "match".
//
// Caveat (unrecoverable for old rows): the pre-split code stored an empty
// record slice for BOTH a successful empty answer and a per-type failed DoH
// lookup under an "ok"/"partial" provider, so absent-vs-failed cannot be
// distinguished for that slice — both-empty is rebucketed as "absent".
func RebucketCrossRefSummary(crossRef map[string]any) {
        comparisonsRaw, _ := crossRef["comparisons"].(map[string]any)
        if len(comparisonsRaw) == 0 {
                return
        }

        total, matched, absent, partial, mismatched, unavailable := 0, 0, 0, 0, 0, 0
        rebucketedLegacy := false
        for _, provVal := range comparisonsRaw {
                comps, _ := provVal.([]any)
                for _, compVal := range comps {
                        comp, _ := compVal.(map[string]any)
                        if comp == nil {
                                continue
                        }
                        total++
                        match, _ := comp["match"].(string)
                        ours := anyToStringSlice(comp["our_records"])
                        theirs := anyToStringSlice(comp["their_records"])
                        switch match {
                        case "absent":
                                absent++
                        case "unavailable":
                                unavailable++
                        case "partial":
                                partial++
                        case "mismatch":
                                mismatched++
                        case "match":
                                if len(ours) == 0 && len(theirs) == 0 {
                                        // Rewrite the ROW label, not just the
                                        // counter, so the per-row table agrees
                                        // with the summary ("absent", not
                                        // "match"). A new-shape row never has
                                        // "match" with both-empty (that case is
                                        // emitted as "absent" at scan time), so
                                        // hitting this branch marks the row as
                                        // pre-split.
                                        comp["match"] = "absent"
                                        absent++
                                        rebucketedLegacy = true
                                } else {
                                        matched++
                                }
                        }
                }
        }

        verdict := "corroborated"
        if mismatched > 0 || partial > 0 {
                verdict = "discrepancy_detected"
        }
        if unavailable == total && total > 0 {
                verdict = "verification_unavailable"
        }

        crossRef["summary"] = map[string]any{
                "total_checks": total,
                "matched":      matched,
                "absent":       absent,
                "partial":      partial,
                "mismatched":   mismatched,
                "unavailable":  unavailable,
                "verdict":      verdict,
        }
        if rebucketedLegacy {
                crossRef["rebucketed_legacy"] = true
        }
}
