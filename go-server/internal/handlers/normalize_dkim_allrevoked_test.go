package handlers

import (
	"encoding/json"
	"testing"
)

// TestNormalizeResultsBackfillsDKIMAllRevoked pins the map-on-read backfill:
// legacy rows (no all_revoked field) derive it from key_info; a single live
// key, a missing key_info, or an existing field all defeat the backfill.
func TestNormalizeResultsBackfillsDKIMAllRevoked(t *testing.T) {
	rev := func() interface{} {
		return map[string]interface{}{"key_info": []interface{}{map[string]interface{}{"revoked": true}}}
	}
	legacy := map[string]interface{}{"dkim_analysis": map[string]interface{}{
		"selectors": map[string]interface{}{"a._domainkey": rev(), "b._domainkey": rev()},
	}}
	lb, _ := json.Marshal(legacy)
	out := NormalizeResults(lb)
	if v, _ := out["dkim_analysis"].(map[string]interface{})["all_revoked"].(bool); !v {
		t.Error("legacy all-revoked row did not backfill all_revoked=true")
	}

	mixed := map[string]interface{}{"dkim_analysis": map[string]interface{}{
		"selectors": map[string]interface{}{
			"a._domainkey": rev(),
			"b._domainkey": map[string]interface{}{"key_info": []interface{}{map[string]interface{}{"revoked": false}}},
		},
	}}
	mb, _ := json.Marshal(mixed)
	out = NormalizeResults(mb)
	if _, has := out["dkim_analysis"].(map[string]interface{})["all_revoked"]; has {
		t.Error("a live key must defeat the backfill — one unrevoked selector, no claim")
	}

	present := map[string]interface{}{"dkim_analysis": map[string]interface{}{
		"all_revoked": false,
		"selectors":   map[string]interface{}{"a._domainkey": rev()},
	}}
	pb, _ := json.Marshal(present)
	out = NormalizeResults(pb)
	if v, _ := out["dkim_analysis"].(map[string]interface{})["all_revoked"].(bool); v {
		t.Error("an existing all_revoked field must pass through verbatim, never be recomputed")
	}
}
