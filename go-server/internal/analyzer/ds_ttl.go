// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"strings"
)

// AuthoritativeDSTTL is the result of querying a child's DS RRset directly at the
// parent zone's nameservers to capture the authoritative DS TTL (TTLds, RFC 7583).
//
// The sampling fields exist so a consumer never mistakes "we only measured once"
// for "two servers disagree." Four outcomes are distinguishable:
//
//   - SampledNS==1            — single nameserver, untested (Agreed/Disagreed false)
//   - Agreed                  — two nameservers, same TTL (reliable)
//   - Disagreed               — two nameservers, DIFFERENT TTL (a finding: the
//     registry serves inconsistent DS TTLs, so the outage window is unreliable)
//   - SampledNS==2, neither   — second nameserver unreachable (one effective
//     measurement despite two being sampled)
type AuthoritativeDSTTL struct {
	TTL       uint32 `json:"ttl"`                  // authoritative DS TTL in seconds
	Present   bool   `json:"present"`              // a DS RRset was returned carrying an authoritative TTL
	ParentNS  string `json:"parent_ns,omitempty"`  // parent nameserver IP that answered (provenance)
	SampledNS int    `json:"sampled_ns,omitempty"` // 1 or 2 parent nameservers queried for the DS
	Agreed    bool   `json:"agreed,omitempty"`     // 2 sampled + same TTL
	Disagreed bool   `json:"disagreed,omitempty"`  // 2 sampled + different TTL (the finding)
}

// queryAuthoritativeDSTTL resolves the parent zone's nameservers and queries the
// child's DS RRset directly at a parent server with recursion disabled, capturing
// the authoritative DS TTL (TTLds).
//
// Why the authoritative TTL matters: per RFC 7583 the retire interval for a KSK is
// Iret = DprpP + TTLds, so TTLds is the duration of a botched rollover — a
// validator holding a cached DS stays broken for up to TTLds seconds after an early
// key withdrawal. That number is what a client's outage window is, and it is set at
// the parent (registry), not the child.
//
// The TTL MUST be read from the parent authority (recursion disabled), never a
// recursive resolver: a recursive answer carries a decremented remainder, not the
// configured value (the cloudflare.com case — authoritative 86400s vs a recursive
// resolver's 91s), which would understate the outage window.
//
// A single nameserver's answer is a measurement, but it is also an assumption — the
// DS RRset is served by every parent authority, and a client's resolver may have
// cached it from any of them. So up to two parent servers are queried and the result
// distinguishes single (untested) from agreed (two matching) from disagreed (two
// different). A consumer that quotes the TTL as a client's outage window must treat
// only Agreed as cross-checked; SampledNS==1 or Disagreed each carry a caveat.
//
// Present is false when no DS RRset is returned. That covers both a genuinely
// unsigned zone and a parent that could not be reached; it does not by itself
// distinguish confirmed-absent from transport-failure. That distinction is
// queryParentAuthoritativeDS's job (RFC 4035 §3.2.3 absence discipline) and is
// deliberately left out of this function so the TTL capture stays separable from
// the DS-presence verdict path.
func (a *Analyzer) queryAuthoritativeDSTTL(ctx context.Context, domain string) AuthoritativeDSTTL {
	parentZone := parentZoneFromDomain(domain)
	if parentZone == "" {
		return AuthoritativeDSTTL{}
	}

	parentNSServers := a.DNS.QueryDNS(ctx, "NS", parentZone)
	if len(parentNSServers) == 0 {
		return AuthoritativeDSTTL{}
	}

	// Resolve up to two distinct parent nameservers. If none resolve, fail safe:
	// Present stays false (no measurement) rather than fabricating a verdict.
	var parentIPs []string
	seen := map[string]bool{}
	for _, ns := range parentNSServers {
		server := strings.TrimRight(ns, ".")
		for _, ip := range a.DNS.QueryDNS(ctx, "A", server) {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			parentIPs = append(parentIPs, ip)
			if len(parentIPs) == 2 {
				break
			}
		}
		if len(parentIPs) == 2 {
			break
		}
	}
	if len(parentIPs) == 0 {
		return AuthoritativeDSTTL{}
	}

	first := a.DNS.QueryWithTTLFromResolver(ctx, "DS", domain, parentIPs[0])
	if first.TTL == nil {
		return AuthoritativeDSTTL{}
	}

	out := AuthoritativeDSTTL{TTL: *first.TTL, Present: true, ParentNS: parentIPs[0], SampledNS: len(parentIPs)}

	if len(parentIPs) > 1 {
		second := a.DNS.QueryWithTTLFromResolver(ctx, "DS", domain, parentIPs[1])
		if second.TTL != nil {
			if *second.TTL == out.TTL {
				out.Agreed = true
			} else {
				out.Disagreed = true
			}
		}
		// second.TTL == nil: the second nameserver was unreachable — Agreed and
		// Disagreed both stay false (one effective measurement, not a contradiction).
	}

	return out
}
