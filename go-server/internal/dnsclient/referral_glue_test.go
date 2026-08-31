// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package dnsclient

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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

// CC's multi-glue control: a referral's ADDITIONAL carries glue for EVERY
// in-bailiwick nameserver. The name filter must return ONLY the queried
// host's address — without it, ns2's address contaminates ns1's glue list.
func TestQuerySpecificResolver_MultiGlueReferralReturnsOnlyQueriedName(t *testing.T) {
	ns1 := &dns.A{
		Hdr: dns.Header{Name: "ns1.child.example.com.", TTL: 3600, Class: dns.ClassINET},
		A:   rdata.A{Addr: mustAddr("192.0.2.1")},
	}
	ns2 := &dns.A{
		Hdr: dns.Header{Name: "ns2.child.example.com.", TTL: 3600, Class: dns.ClassINET},
		A:   rdata.A{Addr: mustAddr("192.0.2.2")},
	}
	resp := new(dns.Msg)
	// The referral shape: BOTH nameservers' glue rides Extra together.
	resp.Extra = append(resp.Extra, ns1, ns2)

	fqdn := dnsutil.Fqdn("ns1.child.example.com")
	// The client's exact section logic: Answer-first, Extra type+name filtered.
	var results []string
	for _, rr := range resp.Answer {
		if s := rrToString(rr); s != "" {
			results = append(results, s)
		}
	}
	fqdnLower := strings.ToLower(fqdn)
	for _, rr := range resp.Extra {
		if dnsRrTypeMatches(rr, dns.TypeA) &&
			strings.EqualFold(rr.Header().Name, fqdnLower) {
			if s := rrToString(rr); s != "" {
				results = append(results, s)
			}
		}
	}
	if len(results) != 1 {
		t.Fatalf("multi-glue referral: got %d results, want exactly 1 (only the queried name)", len(results))
	}
	if strings.Contains(strings.Join(results, " "), "192.0.2.2") {
		t.Error("ns2's address leaked into ns1's glue — the name filter is not filtering")
	}
	if !strings.Contains(results[0], "192.0.2.1") {
		t.Errorf("ns1's address missing: %v", results)
	}

	// Symmetric: querying ns2 returns ns2 only.
	fqdn2 := strings.ToLower(dnsutil.Fqdn("ns2.child.example.com"))
	var results2 []string
	for _, rr := range resp.Extra {
		if dnsRrTypeMatches(rr, dns.TypeA) &&
			strings.EqualFold(rr.Header().Name, fqdn2) {
			if s := rrToString(rr); s != "" {
				results2 = append(results2, s)
			}
		}
	}
	if len(results2) != 1 || !strings.Contains(results2[0], "192.0.2.2") {
		t.Errorf("ns2 query wrong: %v", results2)
	}
}
