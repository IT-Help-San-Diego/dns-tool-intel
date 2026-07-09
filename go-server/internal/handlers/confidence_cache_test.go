// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
	"testing"
	"time"

	"dnstool/go-server/internal/icae"
)

func TestConfidenceCacheFreshNilBundle(t *testing.T) {
	if confidenceBundleFresh(nil, "k", time.Now()) {
		t.Error("nil bundle must never be fresh")
	}
}

func TestConfidenceCacheFreshNilMetrics(t *testing.T) {
	b := &confidenceBundle{key: "k", computedAt: time.Now(), metrics: nil}
	if confidenceBundleFresh(b, "k", time.Now()) {
		t.Error("bundle with nil metrics must never be fresh")
	}
}

func TestConfidenceCacheFreshKeyMatch(t *testing.T) {
	now := time.Now()
	b := &confidenceBundle{key: "42|abc|100", computedAt: now, metrics: &icae.ReportMetrics{}}
	if !confidenceBundleFresh(b, "42|abc|100", now.Add(time.Second)) {
		t.Error("matching key within max age should be fresh")
	}
}

func TestConfidenceCacheStaleOnLedgerMove(t *testing.T) {
	now := time.Now()
	b := &confidenceBundle{key: "42|abc|100", computedAt: now, metrics: &icae.ReportMetrics{}}
	if confidenceBundleFresh(b, "43|def|101", now.Add(time.Second)) {
		t.Error("ledger head move must invalidate the cache")
	}
}

func TestConfidenceCacheStaleOnMaxAge(t *testing.T) {
	computed := time.Now().Add(-confidenceCacheMaxAge - time.Second)
	b := &confidenceBundle{key: "42|abc|100", computedAt: computed, metrics: &icae.ReportMetrics{}}
	if confidenceBundleFresh(b, "42|abc|100", time.Now()) {
		t.Error("bundle older than max age must be recomputed")
	}
}

func TestConfidenceCacheResetClearsBundle(t *testing.T) {
	confidenceCache.mu.Lock()
	confidenceCache.bundle = &confidenceBundle{key: "k", computedAt: time.Now(), metrics: &icae.ReportMetrics{}}
	confidenceCache.mu.Unlock()
	resetConfidenceCache()
	confidenceCache.mu.Lock()
	defer confidenceCache.mu.Unlock()
	if confidenceCache.bundle != nil {
		t.Error("reset should clear the cached bundle")
	}
}
