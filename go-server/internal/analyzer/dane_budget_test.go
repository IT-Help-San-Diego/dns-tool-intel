// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPerHostBudget(t *testing.T) {
	future := time.Now().Add(15 * time.Second)

	if got := perHostBudget(future, 6); got < 2400*time.Millisecond || got > 2500*time.Millisecond {
		t.Errorf("6 hosts over ~15s = %v, want ~2500ms", got)
	}
	if got := perHostBudget(future, 1); got < 14900*time.Millisecond || got > 15000*time.Millisecond {
		t.Errorf("1 host over ~15s = %v, want ~15s", got)
	}
	if got := perHostBudget(time.Now().Add(-1*time.Second), 6); got != 0 {
		t.Errorf("past deadline = %v, want 0", got)
	}
	if got := perHostBudget(future, 0); got != 0 {
		t.Errorf("zero hosts = %v, want 0", got)
	}
}

// TestVerifyDANEHosts_SlowHostDoesNotStarveLater pins the budget-division fix:
// one slow host may consume only its own slice of the parent's remaining budget,
// never the whole envelope, so a later sibling is still measured. Without the
// per-host deadline, the slow host would exhaust the shared budget and every host
// after it would record "unreachable" (a positional bias toward the first MX).
func TestVerifyDANEHosts_SlowHostDoesNotStarveLater(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if body.Host == "slow.example" {
			// Block until the per-host deadline cancels the request.
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "verified", "host": body.Host})
	}))
	defer srv.Close()

	a := &Analyzer{Probes: []ProbeEndpoint{{URL: srv.URL}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ver := verifyDANEHosts(ctx, a, []string{"slow.example", "fast.example"})
	if ver == nil {
		t.Fatal("verifyDANEHosts returned nil, want aggregate")
	}
	if ver["unreachable"] != 1 {
		t.Errorf("unreachable = %v, want 1 (the slow host)", ver["unreachable"])
	}
	if ver["verified"] != 1 {
		t.Errorf("verified = %v, want 1 (the fast host must still be measured, not starved)", ver["verified"])
	}
}
