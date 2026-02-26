// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "testing"

        "dnstool/go-server/internal/icuae"
)

func TestBuildRecordCurrencies(t *testing.T) {
        ttlMap := map[string]uint32{
                "A":    300,
                "AAAA": 600,
                "MX":   3600,
        }

        records := buildRecordCurrencies(ttlMap)

        if len(records) != 3 {
                t.Fatalf("expected 3 records, got %d", len(records))
        }

        found := map[string]bool{}
        for _, r := range records {
                found[r.RecordType] = true
                if r.ObservedTTL != ttlMap[r.RecordType] {
                        t.Errorf("record %s: expected TTL %d, got %d", r.RecordType, ttlMap[r.RecordType], r.ObservedTTL)
                }
                if r.TypicalTTL != icuae.TypicalTTLFor(r.RecordType) {
                        t.Errorf("record %s: expected typical TTL %d, got %d", r.RecordType, icuae.TypicalTTLFor(r.RecordType), r.TypicalTTL)
                }
        }

        for rt := range ttlMap {
                if !found[rt] {
                        t.Errorf("missing record type %s", rt)
                }
        }
}

func TestBuildRecordCurrencies_Empty(t *testing.T) {
        records := buildRecordCurrencies(map[string]uint32{})
        if len(records) != 0 {
                t.Errorf("expected 0 records, got %d", len(records))
        }
}

func TestBuildObservedTypes(t *testing.T) {
        resolver := map[string]uint32{"A": 300, "MX": 3600}
        auth := map[string]uint32{"A": 300, "AAAA": 600}

        observed := buildObservedTypes(resolver, auth)

        if len(observed) != 3 {
                t.Fatalf("expected 3 observed types, got %d", len(observed))
        }
        for _, rt := range []string{"A", "MX", "AAAA"} {
                if !observed[rt] {
                        t.Errorf("expected %s to be observed", rt)
                }
        }
}

func TestBuildObservedTypes_BothEmpty(t *testing.T) {
        observed := buildObservedTypes(map[string]uint32{}, map[string]uint32{})
        if len(observed) != 0 {
                t.Errorf("expected 0 observed types, got %d", len(observed))
        }
}

func TestBuildObservedTypes_Overlap(t *testing.T) {
        resolver := map[string]uint32{"A": 300}
        auth := map[string]uint32{"A": 300}

        observed := buildObservedTypes(resolver, auth)
        if len(observed) != 1 {
                t.Errorf("expected 1 observed type (deduplicated), got %d", len(observed))
        }
}

func TestExtractResolverAgreements_Valid(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 3,
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      true,
                                "resolver_count": 3,
                        },
                        "MX": map[string]any{
                                "consensus":      false,
                                "resolver_count": 3,
                        },
                },
        }

        agreements, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 3 {
                t.Errorf("expected resolver count 3, got %d", resolverCount)
        }
        if len(agreements) != 2 {
                t.Fatalf("expected 2 agreements, got %d", len(agreements))
        }

        for _, a := range agreements {
                switch a.RecordType {
                case "A":
                        if !a.Unanimous {
                                t.Error("expected A to be unanimous")
                        }
                        if a.AgreeCount != 3 {
                                t.Errorf("A: expected agree count 3, got %d", a.AgreeCount)
                        }
                case "MX":
                        if a.Unanimous {
                                t.Error("expected MX not unanimous")
                        }
                        if a.AgreeCount != 2 {
                                t.Errorf("MX: expected agree count 2, got %d", a.AgreeCount)
                        }
                }
        }
}

func TestExtractResolverAgreements_NoPerRecord(t *testing.T) {
        consensus := map[string]any{
                "resolvers_queried": 4,
        }

        agreements, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 4 {
                t.Errorf("expected resolver count 4, got %d", resolverCount)
        }
        if agreements != nil {
                t.Errorf("expected nil agreements, got %v", agreements)
        }
}

func TestExtractResolverAgreements_DefaultResolverCount(t *testing.T) {
        consensus := map[string]any{
                "per_record_consensus": map[string]any{},
        }

        _, resolverCount := extractResolverAgreements(consensus)

        if resolverCount != 5 {
                t.Errorf("expected default resolver count 5, got %d", resolverCount)
        }
}

func TestExtractResolverAgreements_ZeroResolverCount(t *testing.T) {
        consensus := map[string]any{
                "per_record_consensus": map[string]any{
                        "A": map[string]any{
                                "consensus":      false,
                                "resolver_count": 0,
                        },
                },
        }

        agreements, _ := extractResolverAgreements(consensus)

        for _, a := range agreements {
                if a.RecordType == "A" && a.AgreeCount != 0 {
                        t.Errorf("expected agree count 0 when resolver_count=0 and no consensus, got %d", a.AgreeCount)
                }
        }
}

func TestEnrichCurrencyInput(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "ns": map[string]any{
                        "dns_providers": []string{"Cloudflare", "Route53"},
                },
                "basic_records": map[string]any{
                        "NS":  []string{"ns1.example.com", "ns2.example.com"},
                        "SOA": []string{"ns1.example.com admin.example.com 2024010101 3600 900 604800 86400"},
                },
        }

        enrichCurrencyInput(input, results)

        if len(input.DNSProviders) != 2 {
                t.Errorf("expected 2 DNS providers, got %d", len(input.DNSProviders))
        }
        if len(input.NSRecords) != 2 {
                t.Errorf("expected 2 NS records, got %d", len(input.NSRecords))
        }
        if input.SOARaw == "" {
                t.Error("expected SOARaw to be populated")
        }
}

func TestEnrichCurrencyInput_MissingData(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{}

        enrichCurrencyInput(input, results)

        if len(input.DNSProviders) != 0 {
                t.Errorf("expected 0 DNS providers, got %d", len(input.DNSProviders))
        }
        if len(input.NSRecords) != 0 {
                t.Errorf("expected 0 NS records, got %d", len(input.NSRecords))
        }
        if input.SOARaw != "" {
                t.Error("expected empty SOARaw")
        }
}

func TestEnrichCurrencyInput_EmptySOA(t *testing.T) {
        input := &icuae.CurrencyReportInput{}
        results := map[string]any{
                "basic_records": map[string]any{
                        "SOA": []string{},
                },
        }

        enrichCurrencyInput(input, results)

        if input.SOARaw != "" {
                t.Error("expected empty SOARaw for empty SOA slice")
        }
}

func TestEnrichBasicRecords(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status":        "success",
                        "valid_records": []string{"v=DMARC1; p=reject"},
                },
                "mta_sts": map[string]any{
                        "record": "_mta-sts.example.com v=STSv1; id=20240101",
                },
                "tlsrpt": map[string]any{
                        "record": "v=TLSRPTv1; rua=mailto:tls@example.com",
                },
        }

        enrichBasicRecords(basic, resultsMap)

        if dmarc, ok := basic["DMARC"].([]string); !ok || len(dmarc) != 1 {
                t.Error("expected DMARC record in basic")
        }
        if mtaSts, ok := basic["MTA-STS"].([]string); !ok || len(mtaSts) != 1 {
                t.Error("expected MTA-STS record in basic")
        }
        if tlsrpt, ok := basic["TLS-RPT"].([]string); !ok || len(tlsrpt) != 1 {
                t.Error("expected TLS-RPT record in basic")
        }
}

func TestEnrichBasicRecords_EmptyResults(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{}

        enrichBasicRecords(basic, resultsMap)

        if _, ok := basic["DMARC"]; ok {
                t.Error("expected no DMARC in basic")
        }
        if _, ok := basic["MTA-STS"]; ok {
                t.Error("expected no MTA-STS in basic")
        }
        if _, ok := basic["TLS-RPT"]; ok {
                t.Error("expected no TLS-RPT in basic")
        }
}

func TestEnrichBasicRecords_ErrorStatus(t *testing.T) {
        basic := map[string]any{}
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "error",
                },
        }

        enrichBasicRecords(basic, resultsMap)

        if _, ok := basic["DMARC"]; ok {
                t.Error("expected no DMARC in basic when status is error")
        }
}

func TestEnrichMisplacedDMARC_Detected(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "warning",
                        "issues": []string{},
                },
        }

        enrichMisplacedDMARC(basic, resultsMap)

        dmarcResult := resultsMap["dmarc"].(map[string]any)
        if dmarcResult["misplaced_dmarc"] == nil {
                t.Error("expected misplaced_dmarc to be set")
        }
}

func TestEnrichMisplacedDMARC_NotDetected(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=spf1 include:_spf.google.com ~all"},
        }
        resultsMap := map[string]any{
                "dmarc": map[string]any{
                        "status": "success",
                },
        }

        enrichMisplacedDMARC(basic, resultsMap)

        dmarcResult := resultsMap["dmarc"].(map[string]any)
        if dmarcResult["misplaced_dmarc"] != nil {
                t.Error("expected misplaced_dmarc not to be set")
        }
}

func TestEnrichMisplacedDMARC_NoDmarcInResults(t *testing.T) {
        basic := map[string]any{
                "TXT": []string{"v=DMARC1; p=reject"},
        }
        resultsMap := map[string]any{}

        enrichMisplacedDMARC(basic, resultsMap)
}

func TestBuildPropagationStatus_Synchronized(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"1.2.3.4"},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "synchronized" {
                t.Errorf("expected synchronized, got %v", entry["status"])
        }
        if entry["synced"] != true {
                t.Error("expected synced=true")
        }
}

func TestBuildPropagationStatus_Propagating(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"5.6.7.8"},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "propagating" {
                t.Errorf("expected propagating, got %v", entry["status"])
        }
        if entry["mismatch"] != true {
                t.Error("expected mismatch=true")
        }
}

func TestBuildPropagationStatus_Unknown(t *testing.T) {
        basic := map[string]any{
                "A": []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{},
        }

        propagation := buildPropagationStatus(basic, auth)

        entry, ok := propagation["A"].(map[string]any)
        if !ok {
                t.Fatal("expected A entry in propagation")
        }
        if entry["status"] != "unknown" {
                t.Errorf("expected unknown, got %v", entry["status"])
        }
}

func TestBuildPropagationStatus_SkipsTTLKeys(t *testing.T) {
        basic := map[string]any{
                "_ttl":          map[string]uint32{"A": 300},
                "_query_status": "ok",
                "A":             []string{"1.2.3.4"},
        }
        auth := map[string]any{
                "A": []string{"1.2.3.4"},
        }

        propagation := buildPropagationStatus(basic, auth)

        if _, ok := propagation["_ttl"]; ok {
                t.Error("expected _ttl to be skipped")
        }
        if _, ok := propagation["_query_status"]; ok {
                t.Error("expected _query_status to be skipped")
        }
        if _, ok := propagation["A"]; !ok {
                t.Error("expected A entry")
        }
}

func TestPopulateTTLReports_NilMaps(t *testing.T) {
        results := map[string]any{}

        populateTTLReports(results)

        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix to be populated")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report to be populated")
        }
}

func TestPopulateTTLReports_WithData(t *testing.T) {
        results := map[string]any{
                "resolver_ttl": map[string]uint32{"A": 300, "MX": 3600},
                "auth_ttl":     map[string]uint32{"A": 300},
        }

        populateTTLReports(results)

        if results["freshness_matrix"] == nil {
                t.Error("expected freshness_matrix to be populated")
        }
        if results["currency_report"] == nil {
                t.Error("expected currency_report to be populated")
        }
}

func TestBuildICuAEReport_Basic(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{}

        report := buildICuAEReport(resolverTTL, authTTL, results)

        if report.OverallGrade == "" {
                t.Error("expected non-empty overall grade")
        }
}

func TestBuildICuAEReport_WithConsensus(t *testing.T) {
        resolverTTL := map[string]uint32{"A": 300}
        authTTL := map[string]uint32{"A": 300}
        results := map[string]any{
                "resolver_consensus": map[string]any{
                        "resolvers_queried": 3,
                        "per_record_consensus": map[string]any{
                                "A": map[string]any{
                                        "consensus":      true,
                                        "resolver_count": 3,
                                },
                        },
                },
        }

        report := buildICuAEReport(resolverTTL, authTTL, results)

        if report.OverallGrade == "" {
                t.Error("expected non-empty overall grade")
        }
}
