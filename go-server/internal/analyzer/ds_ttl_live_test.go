//go:build bigtests

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"testing"
	"time"

	"dnstool/go-server/internal/dnsclient"
)

// TestQueryAuthoritativeDSTTL_Live proves the authoritative DS TTL path end-to-end
// against the real parent nameservers. It is a network test (tag: bigtests) and is
// not run in the default suite.
//
// cloudflare.com is signed; its DS TTL at the .com parent is 86400s. The value is
// the AUTHORITATIVE one, re-verifiable with:
//
//	dig DS cloudflare.com @a.gtld-servers.net
//
// A recursive resolver returns a DECREMENTED remainder (91s at first measurement),
// which is exactly the defect this function exists to avoid — the TTL must be the
// configured value, not the remaining cache lifetime.
//
// google.com publishes no DS at all (re-verifiable the same way against
// a.gtld-servers.net), so Present must be false.
func TestQueryAuthoritativeDSTTL_Live(t *testing.T) {
	a := &Analyzer{DNS: dnsclient.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got := a.queryAuthoritativeDSTTL(ctx, "cloudflare.com")
	if !got.Present {
		t.Fatalf("cloudflare.com DS should be present, got %+v", got)
	}
	if got.TTL != 86400 {
		t.Fatalf("cloudflare.com authoritative DS TTL = %d, want 86400 (dig DS cloudflare.com @a.gtld-servers.net)", got.TTL)
	}
	if got.ParentNS == "" {
		t.Fatalf("cloudflare.com ParentNS should be recorded, got %+v", got)
	}

	unsigned := a.queryAuthoritativeDSTTL(ctx, "google.com")
	if unsigned.Present {
		t.Fatalf("google.com publishes no DS, got %+v", unsigned)
	}
}
