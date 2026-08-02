// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
//
// The early listener answers before config load and after DB failure. Those
// states must read non-200: a load balancer keyed on the status code would
// otherwise route production traffic to a booting, crash-looping, or
// database-less process (measured 2026-08-01: startingHandler served 200 in
// the instant before a config-failure os.Exit — a crash-loop that polls
// healthy). The ONLY 200 /healthz is the ready router's.
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartingHandler_HealthzIsNot200(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	startingHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("starting /healthz must be 503, got %d — a 200 here makes a crash-loop read healthy", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"starting"`) {
		t.Errorf("body must still state the starting status for humans/scripts, got: %s", w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("starting /healthz should carry Retry-After")
	}
}

func TestStartingHandler_SplashPageIsNot200(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	startingHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("starting splash must be 503, got %d — an LB probing / would route to a booting box", w.Code)
	}
}

func TestDegradedHandler_HealthzIsNot200(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	degradedHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("degraded /healthz must be 503, got %d — degraded mode serves no analysis traffic", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"degraded"`) {
		t.Errorf("body must still state the degraded status, got: %s", w.Body.String())
	}
}
