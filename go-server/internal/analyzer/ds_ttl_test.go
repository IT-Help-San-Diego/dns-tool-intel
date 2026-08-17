// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

const exampleDS = "12345 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9"

func addSingleParent(mock *MockDNSClient) {
	mock.AddResponse("NS", "com", []string{"a.gtld-servers.net."})
	mock.AddResponse("A", "a.gtld-servers.net", []string{"192.5.6.30"})
}

func addTwoParents(mock *MockDNSClient) {
	mock.AddResponse("NS", "com", []string{"a.gtld-servers.net.", "b.gtld-servers.net."})
	mock.AddResponse("A", "a.gtld-servers.net", []string{"192.5.6.30"})
	mock.AddResponse("A", "b.gtld-servers.net", []string{"192.5.6.31"})
}

func TestQueryAuthoritativeDSTTL_SingleNameserver(t *testing.T) {
	mock := NewMockDNSClient()
	addSingleParent(mock)
	ttl := uint32(86400)
	mock.AddTTLResponse("DS", "example.com", dnsclient.RecordWithTTL{Records: []string{exampleDS}, TTL: &ttl})

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if !got.Present || got.TTL != 86400 {
		t.Fatalf("expected present TTL 86400, got %+v", got)
	}
	if got.ParentNS != "192.5.6.30" {
		t.Fatalf("expected ParentNS 192.5.6.30, got %q", got.ParentNS)
	}
	if got.SampledNS != 1 {
		t.Fatalf("expected SampledNS 1, got %d", got.SampledNS)
	}
	if got.Agreed || got.Disagreed {
		t.Fatalf("single nameserver must set neither Agreed nor Disagreed, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_TwoNameserversAgree(t *testing.T) {
	mock := NewMockDNSClient()
	addTwoParents(mock)
	ttl := uint32(86400)
	// Resolver-agnostic fixture: both parent IPs resolve to the same TTL.
	mock.AddTTLResponse("DS", "example.com", dnsclient.RecordWithTTL{Records: []string{exampleDS}, TTL: &ttl})

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if !got.Present || got.TTL != 86400 {
		t.Fatalf("expected present TTL 86400, got %+v", got)
	}
	if got.SampledNS != 2 || !got.Agreed || got.Disagreed {
		t.Fatalf("expected SampledNS 2 + Agreed, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_TwoNameserversDisagree(t *testing.T) {
	mock := NewMockDNSClient()
	addTwoParents(mock)
	long := uint32(86400)
	short := uint32(3600)
	mock.AddSpecificResolverTTLResponse("DS", "example.com", "192.5.6.30", dnsclient.RecordWithTTL{Records: []string{exampleDS}, TTL: &long})
	mock.AddSpecificResolverTTLResponse("DS", "example.com", "192.5.6.31", dnsclient.RecordWithTTL{Records: []string{exampleDS}, TTL: &short})

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if !got.Present || got.TTL != 86400 {
		t.Fatalf("expected TTL from first nameserver (86400), got %+v", got)
	}
	if got.SampledNS != 2 || got.Agreed || !got.Disagreed {
		t.Fatalf("expected SampledNS 2 + Disagreed, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_SecondNameserverUnreachable(t *testing.T) {
	mock := NewMockDNSClient()
	addTwoParents(mock)
	ttl := uint32(86400)
	// Only the first parent IP has a DS TTL; the second returns nothing (unreachable).
	mock.AddSpecificResolverTTLResponse("DS", "example.com", "192.5.6.30", dnsclient.RecordWithTTL{Records: []string{exampleDS}, TTL: &ttl})

	a := &Analyzer{DNS: mock}
	got := a.queryAuthoritativeDSTTL(context.Background(), "example.com")
	if !got.Present || got.TTL != 86400 {
		t.Fatalf("expected present TTL 86400, got %+v", got)
	}
	if got.SampledNS != 2 || got.Agreed || got.Disagreed {
		t.Fatalf("unreachable second NS must set neither Agreed nor Disagreed, got %+v", got)
	}
}

func TestQueryAuthoritativeDSTTL_Unsigned(t *testing.T) {
	mock := NewMockDNSClient()
	addSingleParent(mock)
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
