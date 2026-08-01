// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import "testing"

// Deliberately NOT behind the coverage build tag: this is the local build's
// nothing-leaves guarantee, and a guard that only runs in the tagged suite is
// the blind spot this repo keeps rediscovering.
//
// Measured 2026-07-31: every successful non-private local scan fired a POST
// to web.archive.org naming BaseURL/analysis/N — the archive got an
// unreachable URL, but the request itself disclosed "this IP runs DNS Tool
// and produced analysis N". The domain never traveled (only the numeric ID),
// so the stronger promise — "your domains were never disclosed" — held; the
// weaker one — "nothing leaves" — did not. This test is what makes the
// isCloudDeployment term un-deletable: remove it and this fails.
func TestShouldArchiveToWayback_NeverOnLocalDeployment(t *testing.T) {
	if shouldArchiveToWayback(false, 42, true, false, false, false) {
		t.Fatal("local deployment archived to the Internet Archive — the nothing-leaves guarantee is broken for otherwise-archivable input")
	}
	// The same input archives on cloud, proving the local refusal above is
	// the gate term and not some other condition failing.
	if !shouldArchiveToWayback(true, 42, true, false, false, false) {
		t.Fatal("cloud deployment refused an archivable analysis — the fixture is not actually archivable, so the local assertion above proves nothing")
	}
}
