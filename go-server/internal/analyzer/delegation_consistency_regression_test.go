// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// ---- regression tests for the 2026-08-30 four-defect fix (Carey's pq scan) ----
// Root causes fixed:
//   1. queryDNSKEYForDelegation: no EDNS0 advertised → truncated-UDP answers
//      accepted as final → "DNSKEY records missing at child" on healthy zones.
//   2. fetchNSTTLFromParent: parent answers child-NS with a REFERRAL
//      (authority section) → answer-section-only read returned nil.
//   3. CompareTTLs: missing input graded as failed-match ("Drift") instead
//      of not-measured.
//   4. SOA serial rendered through JSON float64 round-trip → 2.026083011e+09.

// exchangeScript answers ExchangeContext by the QUESTION RR's concrete type
// (the fork's Question section is []RR, so the qtype is the RR type itself).
type exchangeScript struct {
	MockDNSClient
	onDNSKEY func() *dns.Msg
	onDS     func() *dns.Msg
	onNS     func() *dns.Msg
	sawEDNS  bool
}

func (s *exchangeScript) ExchangeContext(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if msg.UDPSize > 512 {
		s.sawEDNS = true
	}
	var resp *dns.Msg
	if len(msg.Question) > 0 {
		switch fmt.Sprintf("%T", msg.Question[0]) {
		case "*dns.DNSKEY":
			if s.onDNSKEY != nil {
				resp = s.onDNSKEY()
			}
		case "*dns.DS":
			if s.onDS != nil {
				resp = s.onDS()
			}
		case "*dns.NS":
			if s.onNS != nil {
				resp = s.onNS()
			}
		}
	}
	if resp == nil {
		resp = new(dns.Msg)
		resp.Response = true
		resp.Question = msg.Question
	}
	resp.ID = msg.ID
	return resp, nil
}

func (s *exchangeScript) ExchangeContextToResolver(ctx context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
	return s.ExchangeContext(ctx, msg)
}

// DEFECT 1 regression: the DNSKEY delegation query must advertise EDNS0.
func TestQueryDNSKEYForDelegation_AdvertisesEDNS0(t *testing.T) {
	s := &exchangeScript{}
	a := &Analyzer{DNS: s}
	_ = a.queryDNSKEYForDelegation(context.Background(), "example.com")
	if !s.sawEDNS {
		t.Fatal("DNSKEY delegation query did not advertise EDNS0 — large RRsets get legacy-truncated")
	}
}

// DEFECT 1 regression: answer-section DNSKEYs are collected and parsed.
func TestQueryDNSKEYForDelegation_CollectsAnswerKeys(t *testing.T) {
	s := &exchangeScript{onDNSKEY: func() *dns.Msg {
		m := new(dns.Msg)
		m.Answer = append(m.Answer, &dns.DNSKEY{
			Hdr:    dns.Header{Name: "example.com.", TTL: 3600, Class: dns.ClassINET},
			DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: 13},
		})
		return m
	}}
	a := &Analyzer{DNS: s}

	keys := a.queryDNSKEYForDelegation(context.Background(), "example.com")
	if len(keys) != 1 {
		t.Fatalf("got %d DNSKEY records, want 1", len(keys))
	}
	if !keys[0].IsKSK || keys[0].Algorithm != 13 {
		t.Errorf("parsed key wrong: %+v", keys[0])
	}
}

// DEFECT 2 regression: parent NS TTL is read from the REFERRAL (authority
// section) — the shape Route 53 serves for delegated children.
func TestFetchNSTTLFromParent_ReadsReferralAuthority(t *testing.T) {
	s := &exchangeScript{}
	s.responses = map[string][]string{
		"NS:example.com":            {"ns-1878.awsdns-42.co.uk."},
		"A:ns-1878.awsdns-42.co.uk": {"1.2.3.4"},
	}
	s.onNS = func() *dns.Msg {
		m := new(dns.Msg)
		m.Ns = append(m.Ns, &dns.NS{
			Hdr: dns.Header{Name: "pq.example.com.", TTL: 172800, Class: dns.ClassINET},
			NS:  rdata.NS{Ns: "pqns.example.com."},
		})
		return m
	}
	a := &Analyzer{DNS: s}

	ttl := a.fetchNSTTLFromParent(context.Background(), "pq.example.com")
	if ttl == nil {
		t.Fatal("parent NS TTL not found — referral (authority-section) NS not read")
	}
	if *ttl != 172800 {
		t.Errorf("TTL = %d, want 172800 (the referral NS record TTL)", *ttl)
	}
}

// DEFECT 3 regression: unreadable input is not_measured, NOT a drift verdict.
func TestCompareTTLs_MissingInputIsNotMeasured(t *testing.T) {
	child := uint32(3600)
	res := CompareTTLs(nil, &child)

	if res.Match {
		t.Error("missing input must not report a match")
	}
	if !res.NotMeasured {
		t.Fatal("missing input must set NotMeasured — no comparison was performed")
	}
	if len(res.Issues) == 0 || !strings.Contains(res.Issues[0], "parent zone") {
		t.Errorf("issue text must name the unreadable side, got: %v", res.Issues)
	}
}

// DEFECT 3 serializer: not_measured must survive the map pipeline.
func TestTTLComparisonToMap_CarriesNotMeasured(t *testing.T) {
	res := CompareTTLs(nil, nil)
	m := ttlComparisonToMap(res)
	if m["not_measured"] != true {
		t.Fatal("not_measured lost in serialization — template would render Drift")
	}
}

// DEFECT 4 regression: DS records served in the AUTHORITY section (the signed-
// parent referral shape) are collected, not only answer-section ones.
func TestQueryDSForDelegation_CollectsAuthoritySectionDS(t *testing.T) {
	s := &exchangeScript{onDS: func() *dns.Msg {
		m := new(dns.Msg)
		m.Ns = append(m.Ns, &dns.DS{
			Hdr: dns.Header{Name: "pq.example.com.", TTL: 3600, Class: dns.ClassINET},
			DS:  rdata.DS{KeyTag: 33846, Algorithm: 18, DigestType: 2, Digest: "cf4d2257"},
		})
		return m
	}}
	a := &Analyzer{DNS: s}

	records := a.queryDSForDelegation(context.Background(), "pq.example.com")
	if len(records) != 1 {
		t.Fatalf("got %d DS records from authority section, want 1 — referral DS ignored", len(records))
	}
	if records[0].KeyTag != 33846 {
		t.Errorf("KeyTag = %d, want 33846", records[0].KeyTag)
	}
}
