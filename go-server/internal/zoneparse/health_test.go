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
	if h.StructuralScore != 0 {
		t.Errorf("expected 0 structural score, got %d", h.StructuralScore)
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

func TestStructuralScoreWellFormed(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "::1"},
	}
	h := AnalyzeHealth(records)
	if h.StructuralVerdict != "Well-Formed" {
		t.Errorf("expected Well-Formed, got %s (score %d)", h.StructuralVerdict, h.StructuralScore)
	}
	if h.StructuralScore < 90 {
		t.Errorf("expected structural score >= 90, got %d", h.StructuralScore)
	}
}

func TestStructuralScoreMinimal(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}
	h := AnalyzeHealth(records)
	if h.StructuralVerdict == "Well-Formed" {
		t.Errorf("expected non-Well-Formed verdict for A-only zone, got %s", h.StructuralVerdict)
	}
	if h.StructuralScore >= 50 {
		t.Errorf("expected structural score < 50, got %d", h.StructuralScore)
	}
}

func TestOperationalSignalsNotScored(t *testing.T) {
	withEmail := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 -all"},
		{Name: "_dmarc.ex.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=DMARC1; p=reject"},
	}
	withoutEmail := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 2025010101 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
		{Name: "ex.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
	}

	hWith := AnalyzeHealth(withEmail)
	hWithout := AnalyzeHealth(withoutEmail)

	if hWith.StructuralScore != hWithout.StructuralScore {
		t.Errorf("structural score should NOT change based on SPF/DMARC presence: with=%d, without=%d",
			hWith.StructuralScore, hWithout.StructuralScore)
	}

	if !hWith.HasSPF {
		t.Error("expected HasSPF when SPF TXT present")
	}
	if !hWith.HasDMARC {
		t.Error("expected HasDMARC when DMARC TXT present")
	}
	if hWithout.HasSPF {
		t.Error("expected no HasSPF when SPF TXT absent")
	}
}

func TestSOATimerAnalysis(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. admin.ex.com. 2025010101 3600 900 1209600 86400"},
	}
	h := AnalyzeHealth(records)
	if h.SOATimers == nil {
		t.Fatal("expected SOA timer analysis")
	}
	if h.SOATimers.Serial != 2025010101 {
		t.Errorf("expected serial 2025010101, got %d", h.SOATimers.Serial)
	}
	if h.SOATimers.Refresh != 3600 {
		t.Errorf("expected refresh 3600, got %d", h.SOATimers.Refresh)
	}
	if len(h.SOATimers.Findings) != 0 {
		t.Errorf("expected 0 SOA findings for well-formed SOA, got %d: %v", len(h.SOATimers.Findings), h.SOATimers.Findings)
	}
}

func TestSOATimerBadValues(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. admin.ex.com. 0 60 60 3600 172800"},
	}
	h := AnalyzeHealth(records)
	if h.SOATimers == nil {
		t.Fatal("expected SOA timer analysis")
	}
	if len(h.SOATimers.Findings) == 0 {
		t.Error("expected findings for bad SOA timers")
	}
	foundSerial := false
	foundRefresh := false
	foundRetry := false
	for _, f := range h.SOATimers.Findings {
		if f.Field == "serial" {
			foundSerial = true
		}
		if f.Field == "refresh" {
			foundRefresh = true
		}
		if f.Field == "retry" {
			foundRetry = true
		}
	}
	if !foundSerial {
		t.Error("expected serial=0 finding")
	}
	if !foundRefresh {
		t.Error("expected low refresh finding")
	}
	if !foundRetry {
		t.Error("expected retry >= refresh finding")
	}
}

func TestDuplicateDetection(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "A", RData: "5.6.7.8"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 1 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
	}
	h := AnalyzeHealth(records)
	if len(h.Duplicates) != 1 {
		t.Errorf("expected 1 duplicate RRset, got %d", len(h.Duplicates))
	}
	if len(h.Duplicates) > 0 && h.Duplicates[0].Count != 2 {
		t.Errorf("expected duplicate count 2, got %d", h.Duplicates[0].Count)
	}
}

func TestTTLSpreadHigh(t *testing.T) {
	records := []ParsedRecord{
		{Name: "ex.com.", TTL: 60, Class: "IN", Type: "A", RData: "1.2.3.4"},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "SOA", RData: "ns1.ex.com. a.ex.com. 1 3600 900 1209600 86400"},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "NS", RData: "ns1.ex.com."},
		{Name: "ex.com.", TTL: 86400, Class: "IN", Type: "NS", RData: "ns2.ex.com."},
	}
	h := AnalyzeHealth(records)
	if !h.TTLSpreadHigh {
		t.Error("expected TTLSpreadHigh for 60s vs 86400s")
	}
}
