// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "strings"
        "testing"
)

func TestExtractPrefix24(t *testing.T) {
        tests := []struct {
                name     string
                ip       string
                expected string
        }{
                {"valid IPv4", "192.168.1.100", "192.168.1.0/24"},
                {"another valid", "10.0.0.1", "10.0.0.0/24"},
                {"public IP", "93.184.216.34", "93.184.216.0/24"},
                {"invalid short", "192.168.1", ""},
                {"empty", "", ""},
                {"IPv6 address", "2001:db8::1", ""},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := extractPrefix24(tt.ip)
                        if got != tt.expected {
                                t.Errorf("extractPrefix24(%q) = %q, want %q", tt.ip, got, tt.expected)
                        }
                })
        }
}

func TestComputeDiversityScore(t *testing.T) {
        tests := []struct {
                name           string
                uniqueASNs     int
                uniqueOps      int
                uniquePrefixes int
                totalNS        int
                wantScore      string
        }{
                {"no nameservers", 0, 0, 0, 0, "unknown"},
                {"excellent diversity", 3, 2, 3, 4, "excellent"},
                {"good diversity", 2, 1, 2, 3, "good"},
                {"fair diversity", 2, 1, 1, 2, "fair"},
                {"poor diversity", 1, 1, 1, 4, "poor"},
                {"excellent high count", 4, 3, 5, 6, "excellent"},
                {"fair single ASN two prefixes", 1, 1, 2, 2, "fair"},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        score, _ := computeDiversityScore(tt.uniqueASNs, tt.uniqueOps, tt.uniquePrefixes, tt.totalNS)
                        if score != tt.wantScore {
                                t.Errorf("computeDiversityScore(%d,%d,%d,%d) score = %q, want %q",
                                        tt.uniqueASNs, tt.uniqueOps, tt.uniquePrefixes, tt.totalNS, score, tt.wantScore)
                        }
                })
        }
}

func TestCheckSerialConsensus(t *testing.T) {
        tests := []struct {
                name    string
                entries []NSFleetEntry
                want    bool
        }{
                {
                        "empty",
                        []NSFleetEntry{},
                        true,
                },
                {
                        "single entry",
                        []NSFleetEntry{{SOASerial: 2024010101, SOASerialOK: true}},
                        true,
                },
                {
                        "all match",
                        []NSFleetEntry{
                                {SOASerial: 2024010101, SOASerialOK: true},
                                {SOASerial: 2024010101, SOASerialOK: true},
                                {SOASerial: 2024010101, SOASerialOK: true},
                        },
                        true,
                },
                {
                        "mismatch",
                        []NSFleetEntry{
                                {SOASerial: 2024010101, SOASerialOK: true},
                                {SOASerial: 2024010102, SOASerialOK: true},
                        },
                        false,
                },
                {
                        "skip entries without serial",
                        []NSFleetEntry{
                                {SOASerial: 2024010101, SOASerialOK: true},
                                {SOASerial: 0, SOASerialOK: false},
                                {SOASerial: 2024010101, SOASerialOK: true},
                        },
                        true,
                },
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := checkSerialConsensus(tt.entries)
                        if got != tt.want {
                                t.Errorf("checkSerialConsensus() = %v, want %v", got, tt.want)
                        }
                })
        }
}

func TestScoreFleetDiversity(t *testing.T) {
        entries := []NSFleetEntry{
                {ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.1"}},
                {ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.2"}},
                {ASN: "15169", ASName: "Google LLC", IPv4: []string{"216.239.32.10"}},
        }

        d := scoreFleetDiversity(entries)
        if d.UniqueASNs != 2 {
                t.Errorf("UniqueASNs = %d, want 2", d.UniqueASNs)
        }
        if d.UniqueOperators != 2 {
                t.Errorf("UniqueOperators = %d, want 2", d.UniqueOperators)
        }
        if d.UniquePrefix24s != 2 {
                t.Errorf("UniquePrefix24s = %d, want 2", d.UniquePrefix24s)
        }
}

func TestScoreFleetDiversity_SingleProvider(t *testing.T) {
        entries := []NSFleetEntry{
                {ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.1"}},
                {ASN: "13335", ASName: "Cloudflare, Inc.", IPv4: []string{"104.18.1.2"}},
        }

        d := scoreFleetDiversity(entries)
        if d.UniqueASNs != 1 {
                t.Errorf("UniqueASNs = %d, want 1", d.UniqueASNs)
        }
        if d.Score != "poor" {
                t.Errorf("Score = %q, want 'poor'", d.Score)
        }
}

func TestCollectFleetIssues_LameDelegation(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, AAFlag: true, IsLame: false, SOASerial: 100, SOASerialOK: true},
                {Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, AAFlag: false, IsLame: true, SOASerial: 100, SOASerialOK: true},
        }
        diversity := scoreFleetDiversity(entries)
        issues := collectFleetIssues(entries, diversity, true)

        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "lame delegation") {
                        found = true
                }
        }
        if !found {
                t.Error("expected lame delegation issue for ns2.example.com")
        }
}

func TestCollectFleetIssues_NoIPs(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.gone.example.com", IPv4: []string{}, IPv6: []string{}},
        }
        diversity := scoreFleetDiversity(entries)
        issues := collectFleetIssues(entries, diversity, true)

        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "no IP addresses") {
                        found = true
                }
        }
        if !found {
                t.Error("expected 'no IP addresses' issue")
        }
}

func TestCollectFleetIssues_UDPUnreachable(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: false, TCPReach: true, AAFlag: false, SOASerial: 0, SOASerialOK: false},
        }
        diversity := scoreFleetDiversity(entries)
        issues := collectFleetIssues(entries, diversity, true)

        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "UDP unreachable") {
                        found = true
                }
        }
        if !found {
                t.Error("expected UDP unreachable issue")
        }
}

func TestCollectFleetIssues_SerialMismatch(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true},
                {Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, AAFlag: true, SOASerial: 99, SOASerialOK: true},
        }
        diversity := scoreFleetDiversity(entries)
        serialOK := checkSerialConsensus(entries)
        issues := collectFleetIssues(entries, diversity, serialOK)

        found := false
        for _, issue := range issues {
                if strings.Contains(issue, "SOA serial") {
                        found = true
                }
        }
        if !found {
                t.Error("expected SOA serial mismatch issue")
        }
}

func TestCollectFleetIssues_NetworkRestricted(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "a.gtld-servers.net", IPv4: []string{"192.5.6.30"}, UDPReach: false, TCPReach: false},
                {Hostname: "b.gtld-servers.net", IPv4: []string{"192.33.14.30"}, UDPReach: false, TCPReach: false},
                {Hostname: "c.gtld-servers.net", IPv4: []string{"192.26.92.30"}, UDPReach: false, TCPReach: false},
        }
        diversity := scoreFleetDiversity(entries)
        issues := collectFleetIssues(entries, diversity, true)

        networkRestricted := false
        for _, issue := range issues {
                if strings.Contains(issue, "scanning environment") {
                        networkRestricted = true
                }
                if strings.Contains(issue, "UDP unreachable") || strings.Contains(issue, "TCP unreachable") {
                        t.Error("should not list individual unreachable issues when network is restricted")
                }
        }
        if !networkRestricted {
                t.Error("expected network restriction notice when all nameservers fail both UDP and TCP")
        }
}

func TestCollectFleetIssues_PartialUnreachable(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true},
                {Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: false, TCPReach: false},
        }
        diversity := scoreFleetDiversity(entries)
        issues := collectFleetIssues(entries, diversity, true)

        hasUDP := false
        hasNetworkRestricted := false
        for _, issue := range issues {
                if strings.Contains(issue, "UDP unreachable") {
                        hasUDP = true
                }
                if strings.Contains(issue, "scanning environment") {
                        hasNetworkRestricted = true
                }
        }
        if !hasUDP {
                t.Error("expected individual unreachable issues when only some nameservers fail")
        }
        if hasNetworkRestricted {
                t.Error("should not show network restriction notice when some nameservers are reachable")
        }
}

func TestNSFleetToMap(t *testing.T) {
        result := NSFleetResult{
                Status:          "success",
                Message:         "Analyzed 2 nameserver(s)",
                SerialConsensus: true,
                Issues:          []string{},
                Nameservers: []NSFleetEntry{
                        {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, IPv6: []string{}, ASN: "13335", UDPReach: true, TCPReach: true, AAFlag: true},
                },
                Diversity: FleetDiversity{
                        UniqueASNs:      1,
                        UniqueOperators: 1,
                        UniquePrefix24s: 1,
                        Score:           "poor",
                        ScoreDetail:     "test",
                },
        }

        m := nsFleetToMap(result)
        if m["status"] != "success" {
                t.Errorf("status = %v, want 'success'", m["status"])
        }
        ns, ok := m["nameservers"].([]map[string]any)
        if !ok || len(ns) != 1 {
                t.Error("expected 1 nameserver entry in map")
        }
        div, ok := m["diversity"].(map[string]any)
        if !ok {
                t.Error("expected diversity map")
        }
        if div["score"] != "poor" {
                t.Errorf("diversity score = %v, want 'poor'", div["score"])
        }
}

func TestCollectFleetIssues_Clean(t *testing.T) {
        entries := []NSFleetEntry{
                {Hostname: "ns1.example.com", IPv4: []string{"1.2.3.4"}, UDPReach: true, TCPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true, ASN: "13335"},
                {Hostname: "ns2.example.com", IPv4: []string{"5.6.7.8"}, UDPReach: true, TCPReach: true, AAFlag: true, SOASerial: 100, SOASerialOK: true, ASN: "15169"},
        }
        diversity := FleetDiversity{UniqueASNs: 2, UniqueOperators: 2, UniquePrefix24s: 2, Score: "good"}
        issues := collectFleetIssues(entries, diversity, true)

        if len(issues) != 0 {
                t.Errorf("expected 0 issues for clean fleet, got %d: %v", len(issues), issues)
        }
}

