package analyzer

import (
	"context"
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

// TestDetectDKIMWildcardLockdown pins the pure detector: the probe result is
// PREFETCHED (concurrent with the census — the detector must never be starved
// by the thing it detects), and the wildcard verdict requires both gates.
func TestDetectDKIMWildcardLockdown(t *testing.T) {
	revoked := map[string]map[string]any{
		"a._domainkey": {"key_info": []map[string]any{{"revoked": true}}},
		"b._domainkey": {"key_info": []map[string]any{{"revoked": true}}},
	}
	if ar, wc, _ := detectDKIMWildcardLockdown("probe._domainkey", []string{"v=DKIM1; p="}, revoked); !ar || !wc {
		t.Errorf("all-revoked + probe hit = (%v,%v), want (true,true)", ar, wc)
	}
	if ar, wc, _ := detectDKIMWildcardLockdown("", nil, revoked); !ar || wc {
		t.Errorf("all-revoked + probe MISS = (%v,%v), want (true,false) — absence of probe answer is not wildcard evidence", ar, wc)
	}
	live := map[string]map[string]any{
		"a._domainkey": {"key_info": []map[string]any{{"revoked": false}}},
	}
	if ar, wc, _ := detectDKIMWildcardLockdown("probe._domainkey", []string{"v=DKIM1; p=x"}, live); ar || wc {
		t.Errorf("unrevoked keys = (%v,%v), want (false,false) — a live key defeats the lockdown claim even beside a wildcard", ar, wc)
	}
}

// TestAnalyzeDKIM_WildcardProbeSeesThroughBogusZone pins the probe's QUERY
// PATH, not just its schedule. On a DNSSEC-bogus zone the flat QueryDNS path
// is deterministically blind — validating resolvers SERVFAIL and the flat
// client has no CD salvage — while the census's status-aware path resolves
// through the CD fallback (client.go QueryDNSWithStatus). A probe wired to
// the flat path reports wildcard_dkim=false while the zone wildcards live,
// and 81 phantom provider attributions persist (measured on prod row 18418,
// 2026-08-16: census 81/81 answers, probe blind). The probe must see what
// the census sees. The mock reproduces the split exactly: AddStatusResponse
// feeds ONLY QueryDNSWithStatus, so the flat path stays empty.
func TestAnalyzeDKIM_WildcardProbeSeesThroughBogusZone(t *testing.T) {
	mock := NewMockDNSClient()
	revoked := []string{"v=DKIM1; p="}
	mock.AddStatusResponse("TXT", "amazonses._domainkey.evil.test", revoked, dnsclient.LookupResolved)
	mock.AddStatusResponse("TXT", "barracuda._domainkey.evil.test", revoked, dnsclient.LookupResolved)
	mock.AddStatusResponse("TXT", dkimWildcardProbe+".evil.test", revoked, dnsclient.LookupResolved)

	a := &Analyzer{DNS: mock}
	result := a.AnalyzeDKIM(context.Background(), "evil.test", []string{"10 mail.evil.test."}, nil)

	if got := result["wildcard_dkim"]; got != true {
		t.Fatalf("wildcard_dkim = %v, want true — the probe must resolve through the same status-aware path as the census; a flat-path probe is blind on a bogus zone", got)
	}
	if got := result["all_revoked"]; got != true {
		t.Errorf("all_revoked = %v, want true", got)
	}
	selectors, _ := result["selectors"].(map[string]any)
	if len(selectors) != 1 {
		t.Fatalf("selectors should collapse to the single wildcard entry, got %d: %v", len(selectors), selectors)
	}
	if _, ok := selectors["*._domainkey"]; !ok {
		t.Fatalf("collapsed selector key should be *._domainkey, got %v", selectors)
	}
	providers, _ := result["found_providers"].([]string)
	if len(providers) != 0 {
		t.Errorf("found_providers must be suppressed under wildcard collapse, got %v", providers)
	}
}
