// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

func TestQueryAuthoritativeDSTTL_Present(t *testing.T) {
	mock := NewMockDNSClient()
	mock.AddResponse("NS", "com", []string{"a.gtld-servers.net."})
	mock.AddResponse("A", "a.gtld-servers.net", []string{"192.5.6.30"})
	ttl := uint32(86400)
	mock.AddTTLResponse("DS", "example.com", dnsclient.RecordWithTTL{
		Records: []string{"12345 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9"},
		TTL:     &ttl,
	})

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if !got.Present {
		t.Fatalf("expected DS present, got %+v", got)
	}
	if got.TTL != 86400 {
		t.Fatalf("expected TTL 86400, got %d", got.TTL)
	}
}

func TestQueryAuthoritativeDSTTL_Unsigned(t *testing.T) {
	mock := NewMockDNSClient()
	mock.AddResponse("NS", "com", []string{"a.gtld-servers.net."})
	mock.AddResponse("A", "a.gtld-servers.net", []string{"192.5.6.30"})
	// No DS TTL fixture: QueryWithTTLFromResolver returns an empty RecordWithTTL,
	// so the answer has no TTL and Present must be false.

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if got.Present {
		t.Fatalf("expected DS not present, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_NoParentNS(t *testing.T) {
	mock := NewMockDNSClient()
	// No NS fixture for the parent zone: parent discovery fails before any DS query.

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if got.Present {
		t.Fatalf("expected DS not present when parent NS is unavailable, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_NoParentIP(t *testing.T) {
	mock := NewMockDNSClient()
	mock.AddResponse("NS", "com", []string{"a.gtld-servers.net."})
	// No A fixture for the parent nameserver: no IP to query, so no TTL.

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if got.Present {
		t.Fatalf("expected DS not present when parent IP is unavailable, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_NoParentZone(t *testing.T) {
	mock := NewMockDNSClient()

	a := &Analyzer{DNS: mock}
	// A bare single-label input has no parent zone.
	got := a.queryAuthoritativeDSTTL(context.Background(), "localhost")
	if got.Present {
		t.Fatalf("expected DS not present for a single-label input, got %+v", got)
	}
}
