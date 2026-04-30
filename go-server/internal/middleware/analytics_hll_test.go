// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package middleware

import (
        "context"
        "encoding/binary"
        "fmt"
        "math"
        "testing"
        "time"

        "github.com/axiomhq/hyperloglog"
        "golang.org/x/crypto/sha3"
)

// stableHash mirrors AnalyticsCollector.hllHash so the pure-algorithmic
// tests here don't need a fully-constructed collector. The production code
// uses the same primitive (SHA3-512, first 8 bytes), so any stability or
// uniformity bug in the test would mirror a real bug.
func stableHash(salt []byte, payload string) uint64 {
        h := sha3.New512()
        _, _ = h.Write(salt)
        _, _ = h.Write([]byte{'|'})
        _, _ = h.Write([]byte(payload))
        sum := h.Sum(nil)
        return binary.BigEndian.Uint64(sum[:8])
}

// TestHLLUnionDoesNotDoubleCountReturningVisitors is the core scientific
// regression test: a single visitor that visits on every day of a 30-day
// window must be counted as ONE distinct visitor in the lifetime stat,
// not as 30. The legacy SUM(unique_visitors) approach failed this test;
// the HLL union approach must pass it.
func TestHLLUnionDoesNotDoubleCountReturningVisitors(t *testing.T) {
        const days = 30
        salt := []byte("stable-test-salt-v1")
        visitor := "203.0.113.42|Mozilla/5.0 (test)"

        dailySketches := make([]*hyperloglog.Sketch, days)
        for d := 0; d < days; d++ {
                sk := hyperloglog.New14()
                sk.InsertHash(stableHash(salt, visitor))
                dailySketches[d] = sk
        }

        // LEGACY (broken) behaviour: sum daily distinct counts.
        legacySum := uint64(0)
        for _, sk := range dailySketches {
                legacySum += sk.Estimate()
        }
        if legacySum != days {
                t.Fatalf("test setup: each daily sketch should report 1 unique, got total %d", legacySum)
        }

        // CORRECT behaviour: union all daily sketches, then estimate.
        union := hyperloglog.New14()
        for _, sk := range dailySketches {
                if err := union.Merge(sk); err != nil {
                        t.Fatalf("merge failed: %v", err)
                }
        }
        got := union.Estimate()
        if got != 1 {
                t.Errorf("HLL union of one returning visitor across %d days = %d, want 1 (legacy SUM gave %d)",
                        days, got, legacySum)
        }
}

// TestHLLUnionPreservesDistinctVisitors confirms the converse: N truly
// distinct visitors across N days produce a union estimate ≈ N (within
// the documented HLL relative standard error).
func TestHLLUnionPreservesDistinctVisitors(t *testing.T) {
        const visitors = 1000
        const days = 30
        salt := []byte("stable-test-salt-v2")

        dailySketches := make([]*hyperloglog.Sketch, days)
        for d := 0; d < days; d++ {
                dailySketches[d] = hyperloglog.New14()
        }
        for i := 0; i < visitors; i++ {
                dailySketches[i%days].InsertHash(stableHash(salt, fmt.Sprintf("visitor-%d", i)))
        }

        union := hyperloglog.New14()
        for _, sk := range dailySketches {
                if err := union.Merge(sk); err != nil {
                        t.Fatalf("merge failed: %v", err)
                }
        }
        got := float64(union.Estimate())
        want := float64(visitors)

        // Theoretical relative standard error at p=14: 1.04 / sqrt(16384) ≈ 0.81%.
        // Allow 5x that margin for a single trial — generous but still tiny.
        tolerance := want * 0.04
        if math.Abs(got-want) > tolerance {
                t.Errorf("HLL union estimate %.0f outside tolerance ±%.0f of true count %.0f",
                        got, tolerance, want)
        }
}

// TestHLLSerializationRoundTrip verifies that MarshalBinary/UnmarshalBinary
// preserve the sketch exactly (no estimate drift, no merge failures). This
// is what the per-day BYTEA column relies on.
func TestHLLSerializationRoundTrip(t *testing.T) {
        salt := []byte("stable-test-salt-v3")

        original := hyperloglog.New14()
        for i := 0; i < 500; i++ {
                original.InsertHash(stableHash(salt, fmt.Sprintf("v-%d", i)))
        }
        originalEstimate := original.Estimate()

        blob, err := original.MarshalBinary()
        if err != nil {
                t.Fatalf("MarshalBinary failed: %v", err)
        }

        restored := hyperloglog.New14()
        if err := restored.UnmarshalBinary(blob); err != nil {
                t.Fatalf("UnmarshalBinary failed: %v", err)
        }
        if restored.Estimate() != originalEstimate {
                t.Errorf("post-roundtrip estimate %d ≠ original %d", restored.Estimate(), originalEstimate)
        }

        // Self-merge must not change the estimate either — confirms register
        // equality, not just cardinality equality.
        if err := restored.Merge(original); err != nil {
                t.Fatalf("post-roundtrip Merge failed: %v", err)
        }
        if restored.Estimate() != originalEstimate {
                t.Errorf("self-merge changed estimate: %d ≠ %d", restored.Estimate(), originalEstimate)
        }
}

// TestHLLHashStability is a unit test for AnalyticsCollector.hllHash:
// same (ip, ua) under same salt MUST produce the same hash; different
// inputs MUST produce different hashes. Stability across calls is what
// enables cross-day union mergeability.
func TestHLLHashStability(t *testing.T) {
        ac := &AnalyticsCollector{hllSalt: []byte("stable-test-salt-v4")}

        h1 := ac.hllHash("1.2.3.4", "Mozilla/5.0")
        h2 := ac.hllHash("1.2.3.4", "Mozilla/5.0")
        h3 := ac.hllHash("5.6.7.8", "Mozilla/5.0")
        h4 := ac.hllHash("1.2.3.4", "Chrome/99.0")

        if h1 != h2 {
                t.Error("same (ip, ua) under same salt must produce same hash")
        }
        if h1 == h3 {
                t.Error("different IPs should produce different hashes")
        }
        if h1 == h4 {
                t.Error("different UAs should produce different hashes")
        }

        // Different salt must change the hash, otherwise the daily salt and the
        // HLL salt would be interchangeable (they aren't — that's the whole
        // point of having two pipelines).
        ac2 := &AnalyticsCollector{hllSalt: []byte("a-different-stable-salt")}
        h5 := ac2.hllHash("1.2.3.4", "Mozilla/5.0")
        if h1 == h5 {
                t.Error("different salt must produce different hash")
        }
}

// TestHLLStdErrorPctMatchesTheory pins the documented precision so future
// precision changes (e.g. p=14 → p=16) are caught by failing tests and the
// template tooltip text gets updated alongside the number.
func TestHLLStdErrorPctMatchesTheory(t *testing.T) {
        got := hllStdErrorPct(14)
        want := 100.0 * 1.04 / math.Sqrt(16384)
        if math.Abs(got-want) > 1e-6 {
                t.Errorf("hllStdErrorPct(14) = %v, want %v", got, want)
        }
        if got > 1.0 {
                t.Errorf("p=14 std error %.4f%% should be < 1%%; if you raised precision, update template tooltips", got)
        }
}

// TestHLLDailyResetOnRotateSalt confirms that day rotation creates a fresh
// daily HLL sketch — last day's accumulated entries must not leak into the
// next day's in-memory accumulator (they have already been merged into
// their own DB row by the most recent Flush).
func TestHLLDailyResetOnRotateSalt(t *testing.T) {
        ac := &AnalyticsCollector{
                visitors:        make(map[string]bool),
                pageCounts:      make(map[string]int),
                refCounts:       make(map[string]int),
                analysisDomains: make(map[string]bool),
                dailyHLL:        hyperloglog.New14(),
                hllSalt:         []byte("stable-test-salt-v5"),
                hllEnabled:      true,
                saltDate:        "1999-01-01", // force rotation
        }
        for i := 0; i < 50; i++ {
                ac.dailyHLL.InsertHash(ac.hllHash(fmt.Sprintf("v-%d", i), "ua"))
        }
        if ac.dailyHLL.Estimate() == 0 {
                t.Fatal("test setup: dailyHLL should have entries before rotation")
        }

        ac.rotateSalt()
        if ac.dailyHLL.Estimate() != 0 {
                t.Errorf("after rotateSalt, dailyHLL estimate = %d, want 0", ac.dailyHLL.Estimate())
        }
}

// TestComputeTrueUniqueVisitorsNilPool guards the safe-fallback path used
// by handlers when the DB pool is unavailable: never panic, never return
// OK=true with garbage, always populate StdErrorPct so the UI can still
// describe the methodology even when the live count is missing.
func TestComputeTrueUniqueVisitorsNilPool(t *testing.T) {
        res := ComputeTrueUniqueVisitors(context.Background(), nil, time.Time{}, time.Time{})
        if res.OK {
                t.Error("OK should be false when pool is nil")
        }
        if res.Estimate != 0 || res.DaysCovered != 0 {
                t.Errorf("expected zeroed result with nil pool, got %+v", res)
        }
        if res.StdErrorPct == 0 {
                t.Error("StdErrorPct should be populated even when OK=false (UI may want to show methodology)")
        }
}
