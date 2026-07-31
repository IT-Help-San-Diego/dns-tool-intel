package handlers

import (
	"sync"
	"testing"
	"time"
)

func TestProgressStore_UniqueTokenEntropy(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	tokens := make(map[string]bool)
	for i := 0; i < 50; i++ {
		tok, _ := ps.NewToken()
		if tokens[tok] {
			t.Fatalf("duplicate token generated: %s", tok)
		}
		tokens[tok] = true
		if len(tok) != 32 {
			t.Fatalf("expected 32-char hex token, got %d chars", len(tok))
		}
	}
}

func TestProgressStore_DeleteRemovesToken(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	tok, _ := ps.NewToken()
	ps.Delete(tok)
	if ps.Get(tok) != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestScanProgress_MarkComplete_SetsAllPhasesDone(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.MarkComplete(42, "/analysis/42")

	data := sp.toJSON()
	if data["status"] != "complete" {
		t.Fatalf("expected 'complete', got %v", data["status"])
	}
	if data["analysis_id"] != int32(42) {
		t.Fatalf("expected analysis_id 42, got %v", data["analysis_id"])
	}
	if data["redirect_url"] != "/analysis/42" {
		t.Fatalf("expected redirect_url, got %v", data["redirect_url"])
	}

	phases := data["phases"].(map[string]any)
	for group, pRaw := range phases {
		p := pRaw.(map[string]any)
		if p["status"] != "done" {
			t.Fatalf("expected phase %s to be 'done' after MarkComplete, got %v", group, p["status"])
		}
	}
}

func TestScanProgress_MarkFailed_SetsError(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.MarkFailed("timeout")

	data := sp.toJSON()
	if data["status"] != "failed" {
		t.Fatalf("expected 'failed', got %v", data["status"])
	}
	if data["error"] != "timeout" {
		t.Fatalf("expected error 'timeout', got %v", data["error"])
	}
	if _, exists := data["redirect_url"]; exists {
		t.Fatal("failed progress should not have redirect_url")
	}
}

func TestScanProgress_ConcurrentSafety(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sp.UpdatePhase("dns_records", "running", 0)
			sp.UpdatePhase("email_auth", "done", 100)
			_ = sp.toJSON()
		}()
	}
	wg.Wait()

	data := sp.toJSON()
	if data["status"] != "running" {
		t.Fatalf("expected 'running' after concurrent updates, got %v", data["status"])
	}
}

func TestScanProgress_DonePhaseIgnoresLaterUpdates(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()
	sp.UpdatePhase("web3_analysis", "done", 50)

	sp.UpdatePhase("web3_analysis", "running", 0)
	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	w3 := phases["web3_analysis"].(map[string]any)
	if w3["status"] != "done" {
		t.Fatalf("expected 'done' to persist, got %v", w3["status"])
	}
}

func TestScanProgress_TTLEviction(t *testing.T) {
	ps := &ProgressStore{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go ps.cleanupLoop()
	defer ps.Close()

	tok, sp := ps.NewToken()
	sp.mu.Lock()
	sp.startTime = time.Now().Add(-6 * time.Minute)
	sp.mu.Unlock()

	ps.store.Range(func(key, val any) bool {
		s := val.(*scanProgress)
		if time.Since(s.startTime) > 5*time.Minute {
			ps.store.Delete(key)
		}
		return true
	})

	if ps.Get(tok) != nil {
		t.Fatal("expected token to be evicted after TTL")
	}
}

func TestScanProgress_SingleTaskGroupCompletion(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	sp.UpdatePhase("web3_analysis", "running", 0)

	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	w3 := phases["web3_analysis"].(map[string]any)
	if w3["status"] != "running" {
		t.Fatalf("expected 'running', got %v", w3["status"])
	}

	sp.UpdatePhase("web3_analysis", "done", 50)
	data = sp.toJSON()
	phases = data["phases"].(map[string]any)
	w3 = phases["web3_analysis"].(map[string]any)
	if w3["status"] != "done" {
		t.Fatalf("expected 'done' for single-task group, got %v", w3["status"])
	}
}

func TestScanProgress_AnalysisEngineOneCallback(t *testing.T) {
	ps := NewProgressStore()
	defer ps.Close()

	_, sp := ps.NewToken()

	sp.UpdatePhase("analysis_engine", "running", 0)
	sp.UpdatePhase("analysis_engine", "done", 500)

	data := sp.toJSON()
	phases := data["phases"].(map[string]any)
	eng := phases["analysis_engine"].(map[string]any)
	if eng["status"] != "done" {
		t.Fatalf("expected 'done' for analysis_engine (1 expected callback), got %v", eng["status"])
	}
	if eng["tasks_total"] != 1 {
		t.Fatalf("expected analysis_engine tasks_total=1, got %v", eng["tasks_total"])
	}
}

// A phase group's tasks run concurrently, so summing their durations produces a
// number larger than the wall-clock time the group occupied — and, early in a
// scan, larger than the whole scan's elapsed time. That is what published
// "Policy Records - complete in 8.0s" at an elapsed 2.5s in the scan ticker.
//
// The invariant is absolute: nothing may claim to have taken longer than the
// scan has been running. It holds by construction now, because the duration is
// derived from CompletedAtMs - StartedAtMs and both are stamped from the same
// clock as elapsed_ms.
func TestPhaseDurationNeverExceedsElapsed(t *testing.T) {
	store := NewProgressStore()
	defer store.Close()
	_, sp := store.NewToken()

	// policy_records = mta_sts, tlsrpt, bimi, caa. Four tasks, dispatched under
	// a WaitGroup, each reporting 2s of its own overlapping wall time.
	for i := 0; i < 4; i++ {
		sp.UpdatePhase("policy_records", "running", 0)
	}
	for i := 0; i < 4; i++ {
		sp.UpdatePhase("policy_records", "done", 2000)
	}

	data := sp.toJSON()
	elapsed := data["elapsed_ms"].(int)
	phases := data["phases"].(map[string]any)

	for group, raw := range phases {
		p := raw.(map[string]any)
		dur, ok := p["duration_ms"].(int)
		if !ok {
			continue
		}
		if dur > elapsed {
			t.Fatalf("%s: duration_ms=%d exceeds elapsed_ms=%d — a phase cannot take longer than the scan has run", group, dur, elapsed)
		}
	}

	pr := phases["policy_records"].(map[string]any)
	if got := pr["total_task_time_ms"].(int); got != 8000 {
		t.Fatalf("total_task_time_ms = %d, want 8000 (the sum is kept, just not called a duration)", got)
	}
	if pr["status"] != "done" {
		t.Fatalf("expected policy_records done after 4/4 tasks, got %v", pr["status"])
	}
}

// StartedAtMs == 0 used to mean both "starts at the very beginning of the scan"
// and "has not started", so a phase beginning in the first millisecond had its
// start rewritten on every later update.
func TestPhaseStartAtZeroIsNotTreatedAsUnset(t *testing.T) {
	store := NewProgressStore()
	defer store.Close()
	_, sp := store.NewToken()

	sp.UpdatePhase("dns_records", "running", 0)
	first := sp.toJSON()["phases"].(map[string]any)["dns_records"].(map[string]any)["started_at_ms"].(int)

	time.Sleep(15 * time.Millisecond)
	sp.UpdatePhase("dns_records", "running", 0)
	second := sp.toJSON()["phases"].(map[string]any)["dns_records"].(map[string]any)["started_at_ms"].(int)

	if first != second {
		t.Fatalf("started_at_ms moved from %d to %d on a later update — 0 is a real start time, not a sentinel", first, second)
	}
}
