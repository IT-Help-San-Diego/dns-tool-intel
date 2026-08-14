// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import "testing"

// TestAnalysisHandlerNilFallbacks pins the nil-fallback contract of the three
// sibling accessor methods on a zero-value AnalysisHandler: with no injected
// store/execer and no DB, each must return nil (never a zero-value interface).
// These were previously untested; the execer() assertion that once existed was
// swept into agentpkg by the sub-package split (commit 7a15574e7) where the
// parent type is out of scope, silently failing to compile behind //go:build
// coverage. Restored here in the package that owns AnalysisHandler.
func TestAnalysisHandlerNilFallbacks(t *testing.T) {
	h := &AnalysisHandler{}

	if got := h.store(); got != nil {
		t.Errorf("store() on zero-value handler = %v, want nil", got)
	}
	if got := h.execer(); got != nil {
		t.Errorf("execer() on zero-value handler = %v, want nil", got)
	}
	if got := h.rawQueries(); got != nil {
		t.Errorf("rawQueries() on zero-value handler = %v, want nil", got)
	}
}
