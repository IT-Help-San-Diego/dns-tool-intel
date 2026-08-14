package dnsclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestQueryDNSWithStatus_CDFallbackRevealsBogusZoneRecords pins the fifth CD
// instance: a validating resolver SERVFAILs a broken-DNSSEC zone and hides its
// published records, so the CD=0 DoH pass returns empty for a domain that
// genuinely has records. The CD=1 positive-confirmation fallback must surface
// them as LookupResolved.
func TestQueryDNSWithStatus_CDFallbackRevealsBogusZoneRecords(t *testing.T) {
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"Status":2,"Answer":[]}` // validating resolver: SERVFAIL
		if req.URL.Query().Get("cd") == "1" {
			body = `{"Status":0,"Answer":[{"data":"96.99.227.255","TTL":60,"type":1}]}`
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/dns-json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})

	c := New(
		WithResolvers([]ResolverConfig{{Name: "unreachable", IP: "192.0.2.1"}}),
		WithHTTPClient(&http.Client{Transport: rt}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	records, status := c.QueryDNSWithStatus(ctx, "A", "dnssec-failed.org")
	if status != LookupResolved {
		t.Fatalf("expected LookupResolved via CD=1 fallback, got %v", status)
	}
	if len(records) != 1 || records[0] != "96.99.227.255" {
		t.Fatalf("expected the zone's published A record via CD fallback, got %v", records)
	}
}

// TestQueryDNSWithStatus_CDFallbackNeverAssertsAbsence pins the rule that
// absence is never asserted from a CD query: even with CD=1, an empty answer
// yields LookupError, never LookupAbsent.
func TestQueryDNSWithStatus_CDFallbackNeverAssertsAbsence(t *testing.T) {
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/dns-json"}},
			Body:       io.NopCloser(strings.NewReader(`{"Status":3,"Answer":[]}`)),
			Request:    req,
		}, nil
	})

	c := New(
		WithResolvers([]ResolverConfig{{Name: "unreachable", IP: "192.0.2.1"}}),
		WithHTTPClient(&http.Client{Transport: rt}),
		WithTimeout(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, status := c.QueryDNSWithStatus(ctx, "A", "genuinely-absent.example")
	if status != LookupError {
		t.Fatalf("expected LookupError (never LookupAbsent from a CD query), got %v", status)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
