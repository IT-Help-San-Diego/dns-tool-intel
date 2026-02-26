// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package zoneparse

import (
        "sort"
        "strings"
)

type ZoneHealth struct {
        TypeDistribution []TypeCount `json:"type_distribution"`
        UniqueHostnames  int         `json:"unique_hostnames"`
        TotalRecords     int         `json:"total_records"`

        HasSOA    bool `json:"has_soa"`
        HasNS     bool `json:"has_ns"`
        HasMX     bool `json:"has_mx"`
        HasA      bool `json:"has_a"`
        HasAAAA   bool `json:"has_aaaa"`
        HasSPF    bool `json:"has_spf"`
        HasDMARC  bool `json:"has_dmarc"`
        HasDKIM   bool `json:"has_dkim"`
        HasCAA    bool `json:"has_caa"`
        HasTLSA   bool `json:"has_tlsa"`
        HasDNSSEC bool `json:"has_dnssec"`

        CompletenessScore   int    `json:"completeness_score"`
        CompletenessVerdict string `json:"completeness_verdict"`

        NSTargets  []string `json:"ns_targets"`
        NSCount    int      `json:"ns_count"`
        HasIPv6Glue bool   `json:"has_ipv6_glue"`

        MinTTL    uint32    `json:"min_ttl"`
        MaxTTL    uint32    `json:"max_ttl"`
        MedianTTL uint32    `json:"median_ttl"`
        TTLByType []TypeTTL `json:"ttl_by_type"`

        DNSKEYCount int `json:"dnskey_count"`
        RRSIGCount  int `json:"rrsig_count"`
        DSCount     int `json:"ds_count"`
        NSECCount      int `json:"nsec_count"`
        NSEC3Count     int `json:"nsec3_count"`
        NSEC3ParamCount int `json:"nsec3param_count"`

        RecordsByType map[string][]ParsedRecord `json:"-"`
}

type TypeCount struct {
        Type    string  `json:"type"`
        Count   int     `json:"count"`
        Percent float64 `json:"percent"`
}

type TypeTTL struct {
        Type    string `json:"type"`
        MinTTL  uint32 `json:"min_ttl"`
        MaxTTL  uint32 `json:"max_ttl"`
        Count   int    `json:"count"`
        Uniform bool   `json:"uniform"`
}

func AnalyzeHealth(records []ParsedRecord) *ZoneHealth {
        h := &ZoneHealth{
                TypeDistribution: []TypeCount{},
                NSTargets:        []string{},
                TTLByType:        []TypeTTL{},
                RecordsByType:    make(map[string][]ParsedRecord),
        }

        if len(records) == 0 {
                return h
        }

        h.TotalRecords = len(records)

        typeCounts := make(map[string]int)
        hostnames := make(map[string]struct{})
        nsTargets := make(map[string]struct{})
        var allTTLs []uint32
        typeTTLs := make(map[string][]uint32)

        for _, r := range records {
                typeCounts[r.Type]++
                hostnames[r.Name] = struct{}{}
                allTTLs = append(allTTLs, r.TTL)
                typeTTLs[r.Type] = append(typeTTLs[r.Type], r.TTL)
                h.RecordsByType[r.Type] = append(h.RecordsByType[r.Type], r)

                switch r.Type {
                case "SOA":
                        h.HasSOA = true
                case "NS":
                        h.HasNS = true
                        nsTargets[strings.TrimSuffix(strings.ToLower(r.RData), ".")] = struct{}{}
                case "MX":
                        h.HasMX = true
                case "A":
                        h.HasA = true
                case "AAAA":
                        h.HasAAAA = true
                case "CAA":
                        h.HasCAA = true
                case "TLSA":
                        h.HasTLSA = true
                case "DNSKEY":
                        h.HasDNSSEC = true
                        h.DNSKEYCount++
                case "RRSIG":
                        h.HasDNSSEC = true
                        h.RRSIGCount++
                case "DS":
                        h.HasDNSSEC = true
                        h.DSCount++
                case "NSEC":
                        h.HasDNSSEC = true
                        h.NSECCount++
                case "NSEC3":
                        h.HasDNSSEC = true
                        h.NSEC3Count++
                case "NSEC3PARAM":
                        h.HasDNSSEC = true
                        h.NSEC3ParamCount++
                case "TXT":
                        rdata := strings.ToLower(r.RData)
                        if strings.Contains(rdata, "v=spf1") {
                                h.HasSPF = true
                        }
                        if strings.HasPrefix(r.Name, "_dmarc.") {
                                h.HasDMARC = true
                        }
                        if strings.Contains(r.Name, "._domainkey.") {
                                h.HasDKIM = true
                        }
                }
        }

        h.UniqueHostnames = len(hostnames)

        for ns := range nsTargets {
                h.NSTargets = append(h.NSTargets, ns)
        }
        sort.Strings(h.NSTargets)
        h.NSCount = len(h.NSTargets)

        for _, r := range records {
                if r.Type == "AAAA" {
                        name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
                        for ns := range nsTargets {
                                if name == ns {
                                        h.HasIPv6Glue = true
                                        break
                                }
                        }
                        if h.HasIPv6Glue {
                                break
                        }
                }
        }

        for rtype, count := range typeCounts {
                pct := float64(count) / float64(h.TotalRecords) * 100
                h.TypeDistribution = append(h.TypeDistribution, TypeCount{
                        Type:    rtype,
                        Count:   count,
                        Percent: pct,
                })
        }
        sort.Slice(h.TypeDistribution, func(i, j int) bool {
                return h.TypeDistribution[i].Count > h.TypeDistribution[j].Count
        })

        sort.Slice(allTTLs, func(i, j int) bool { return allTTLs[i] < allTTLs[j] })
        h.MinTTL = allTTLs[0]
        h.MaxTTL = allTTLs[len(allTTLs)-1]
        h.MedianTTL = allTTLs[len(allTTLs)/2]

        typeOrder := make([]string, 0, len(typeTTLs))
        for t := range typeTTLs {
                typeOrder = append(typeOrder, t)
        }
        sort.Strings(typeOrder)

        for _, rtype := range typeOrder {
                ttls := typeTTLs[rtype]
                sort.Slice(ttls, func(i, j int) bool { return ttls[i] < ttls[j] })
                uniform := ttls[0] == ttls[len(ttls)-1]
                h.TTLByType = append(h.TTLByType, TypeTTL{
                        Type:    rtype,
                        MinTTL:  ttls[0],
                        MaxTTL:  ttls[len(ttls)-1],
                        Count:   len(ttls),
                        Uniform: uniform,
                })
        }

        h.CompletenessScore, h.CompletenessVerdict = computeCompleteness(h)

        return h
}

func computeCompleteness(h *ZoneHealth) (int, string) {
        score := 0
        total := 0

        checks := []struct {
                present bool
                weight  int
        }{
                {h.HasSOA, 15},
                {h.HasNS, 15},
                {h.HasA || h.HasAAAA, 10},
                {h.HasMX, 10},
                {h.HasSPF, 10},
                {h.HasDMARC, 10},
                {h.HasDKIM, 5},
                {h.HasCAA, 10},
                {h.HasAAAA, 5},
                {h.HasDNSSEC, 10},
        }

        for _, c := range checks {
                total += c.weight
                if c.present {
                        score += c.weight
                }
        }

        pct := score * 100 / total
        verdict := "Minimal"
        switch {
        case pct >= 90:
                verdict = "Comprehensive"
        case pct >= 70:
                verdict = "Good"
        case pct >= 50:
                verdict = "Moderate"
        case pct >= 30:
                verdict = "Basic"
        }

        return pct, verdict
}
