// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package zoneparse

import (
        "testing"
)

func TestAnalyzeHealthEmpty(t *testing.T) {
        h := AnalyzeHealth(nil)
        if h.TotalRecords != 0 {
                t.Errorf("expected 0 records, got %d", h.TotalRecords)
        }
        if h.CompletenessScore != 0 {
                t.Errorf("expected 0 completeness, got %d", h.CompletenessScore)
        }
}

func TestAnalyzeHealthBasicZone(t *testing.T) {
        records := []ParsedRecord{
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.example.com."},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.example.com."},
                {Name: "example.com.", TTL: 300, Class: "IN", Type: "A", RData: "93.184.216.34"},
                {Name: "example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2606:2800:220:1:248:1893:25c8:1946"},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.example.com."},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.example.com ~all"},
                {Name: "_dmarc.example.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "CAA", RData: "0 issue \"letsencrypt.org\""},
        }

        h := AnalyzeHealth(records)

        if h.TotalRecords != 9 {
                t.Errorf("expected 9 records, got %d", h.TotalRecords)
        }
        if !h.HasSOA {
                t.Error("expected HasSOA")
        }
        if !h.HasNS {
                t.Error("expected HasNS")
        }
        if !h.HasA {
                t.Error("expected HasA")
        }
        if !h.HasAAAA {
                t.Error("expected HasAAAA")
        }
        if !h.HasMX {
                t.Error("expected HasMX")
        }
        if !h.HasSPF {
                t.Error("expected HasSPF")
        }
        if !h.HasDMARC {
                t.Error("expected HasDMARC")
        }
        if !h.HasCAA {
                t.Error("expected HasCAA")
        }
        if h.NSCount != 2 {
                t.Errorf("expected 2 NS targets, got %d", h.NSCount)
        }
        if h.MinTTL != 300 {
                t.Errorf("expected min TTL 300, got %d", h.MinTTL)
        }
        if h.MaxTTL != 3600 {
                t.Errorf("expected max TTL 3600, got %d", h.MaxTTL)
        }
        if h.CompletenessScore < 70 {
                t.Errorf("expected completeness >= 70, got %d", h.CompletenessScore)
        }
        if len(h.TypeDistribution) == 0 {
                t.Error("expected type distribution")
        }
        if len(h.TTLByType) == 0 {
                t.Error("expected TTL by type")
        }
        if len(h.RecordsByType) == 0 {
                t.Error("expected records by type map")
        }
}

func TestAnalyzeHealthDNSSEC(t *testing.T) {
        records := []ParsedRecord{
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 1 3600 900 604800 86400"},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "DNSKEY", RData: "257 3 13 base64key=="},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "DNSKEY", RData: "256 3 13 base64zsk=="},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "SOA 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "NS 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
                {Name: "example.com.", TTL: 3600, Class: "IN", Type: "RRSIG", RData: "DNSKEY 13 2 3600 20250101000000 20240101000000 12345 example.com. sig=="},
                {Name: "example.com.", TTL: 0, Class: "IN", Type: "NSEC3PARAM", RData: "1 0 0 -"},
        }

        h := AnalyzeHealth(records)

        if !h.HasDNSSEC {
                t.Error("expected HasDNSSEC")
        }
        if h.DNSKEYCount != 2 {
                t.Errorf("expected 2 DNSKEYs, got %d", h.DNSKEYCount)
        }
        if h.RRSIGCount != 3 {
                t.Errorf("expected 3 RRSIGs, got %d", h.RRSIGCount)
        }
        if h.NSEC3Count != 0 {
                t.Errorf("expected 0 NSEC3 (only NSEC3PARAM present), got %d", h.NSEC3Count)
        }
        if h.NSEC3ParamCount != 1 {
                t.Errorf("expected 1 NSEC3PARAM, got %d", h.NSEC3ParamCount)
        }
}

func TestCompletenessVerdictComprehensive(t *testing.T) {
        records := []ParsedRecord{
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 1 3600 900 604800 86400"},
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
                {Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
                {Name: "ex.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "::1"},
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "MX", RData: "10 mail.ex.com."},
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 -all"},
                {Name: "_dmarc.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
                {Name: "sel._domainkey.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DKIM1; k=rsa; p=key"},
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "CAA", RData: "0 issue \"le.org\""},
                {Name: "ex.com.", TTL: 3600, Class: "IN", Type: "DNSKEY", RData: "257 3 13 key=="},
        }
        h := AnalyzeHealth(records)
        if h.CompletenessVerdict != "Comprehensive" {
                t.Errorf("expected Comprehensive, got %s (score %d)", h.CompletenessVerdict, h.CompletenessScore)
        }
        if h.CompletenessScore != 100 {
                t.Errorf("expected 100%% completeness, got %d", h.CompletenessScore)
        }
}

func TestCompletenessVerdictMinimal(t *testing.T) {
        records := []ParsedRecord{
                {Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
        }
        h := AnalyzeHealth(records)
        if h.CompletenessVerdict != "Minimal" {
                t.Errorf("expected Minimal, got %s (score %d)", h.CompletenessVerdict, h.CompletenessScore)
        }
        if h.CompletenessScore >= 30 {
                t.Errorf("expected score < 30, got %d", h.CompletenessScore)
        }
}
