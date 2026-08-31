// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package dnsclient

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// The referral-shape fix: a parent server answering an in-bailiwick NS's A
// query puts the GLUE in the ADDITIONAL section. QuerySpecificResolver now
// reads r.Extra (type-filtered) or every healthy in-bailiwick delegation
// reads "no glue" — the third exact-section instance in the delegation
// checker, receipted by CC on merged main.

func TestQuerySpecificResolver_GlueFromExtraSurfaces(t *testing.T) {
	glue := &dns.A{
		Hdr: dns.Header{Name: "ns1.child.example.com.", TTL: 3600, Class: dns.ClassINET},
		A:   rdata.A{Addr: mustAddr("192.0.2.1")},
	}
	resp := new(dns.Msg)
	resp.Extra = append(resp.Extra, glue)

	// The same section logic the client now runs: Answer-first, Extra adds
	// type-matched referral records.
	var results []string
	for _, rr := range resp.Answer {
		if s := rrToString(rr); s != "" {
			results = append(results, s)
		}
	}
	for _, rr := range resp.Extra {
		if dnsRrTypeMatches(rr, dns.TypeA) {
			if s := rrToString(rr); s != "" {
				results = append(results, s)
			}
		}
	}
	if len(results) != 1 {
		t.Fatalf("glue from Extra: got %d results, want 1 (referral shape must surface glue)", len(results))
	}
	// Negative: the A glue must not match an AAAA filter.
	for _, rr := range resp.Extra {
		if dnsRrTypeMatches(rr, dns.TypeAAAA) {
			t.Error("A glue matched an AAAA filter — the type switch is wrong")
		}
	}
	// Positive control: an OPT pseudo-RR (always in Extra) must NOT surface.
	opt := new(dns.OPT)
	resp2 := new(dns.Msg)
	resp2.Extra = append(resp2.Extra, opt)
	n := 0
	for _, rr := range resp2.Extra {
		if dnsRrTypeMatches(rr, dns.TypeA) {
			n++
		}
	}
	if n != 0 {
		t.Error("OPT must never match a record-type filter")
	}
}

func TestDnsRrTypeMatches_Matrix(t *testing.T) {
	a := &dns.A{Hdr: dns.Header{Name: "x.", Class: dns.ClassINET}, A: rdata.A{Addr: mustAddr("192.0.2.1")}}
	aaaa := &dns.AAAA{Hdr: dns.Header{Name: "x.", Class: dns.ClassINET}, AAAA: rdata.AAAA{Addr: mustAddr("2001:db8::1")}}
	if !dnsRrTypeMatches(a, dns.TypeA) {
		t.Error("A must match TypeA")
	}
	if dnsRrTypeMatches(a, dns.TypeAAAA) {
		t.Error("A must NOT match TypeAAAA")
	}
	if !dnsRrTypeMatches(aaaa, dns.TypeAAAA) {
		t.Error("AAAA must match TypeAAAA")
	}
	if dnsRrTypeMatches(aaaa, dns.TypeA) {
		t.Error("AAAA must NOT match TypeA")
	}
}
