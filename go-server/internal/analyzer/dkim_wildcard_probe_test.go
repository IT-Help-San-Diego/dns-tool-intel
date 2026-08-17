package analyzer

import "testing"

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
