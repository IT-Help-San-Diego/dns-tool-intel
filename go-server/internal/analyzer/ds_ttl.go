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
type AuthoritativeDSTTL struct {
	TTL     uint32 `json:"ttl"`     // authoritative DS TTL in seconds
	Present bool   `json:"present"` // a DS RRset was returned carrying an authoritative TTL
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

	parentServer := strings.TrimRight(parentNSServers[0], ".")
	parentIPs := a.DNS.QueryDNS(ctx, "A", parentServer)
	if len(parentIPs) == 0 {
		return AuthoritativeDSTTL{}
	}

	rec := a.DNS.QueryWithTTLFromResolver(ctx, "DS", domain, parentIPs[0])
	if rec.TTL == nil {
		return AuthoritativeDSTTL{}
	}
	return AuthoritativeDSTTL{TTL: *rec.TTL, Present: true}
}
