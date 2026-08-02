// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package db_test

import (
	"strings"
	"testing"

	"dnstool/go-server/internal/db"
)

// The production-database guard must fire under the platform-neutral
// CLOUD_DEPLOYMENT key alone: on AWS the legacy REPLIT_DEPLOYMENT is unset,
// and a guard still keyed to it would let prod boot against a dev database
// with no complaint.
func TestConnect_ProductionSafeguard_BlocksHeliumHost_CloudKey(t *testing.T) {
	t.Setenv("CLOUD_DEPLOYMENT", "1")
	t.Setenv("REPLIT_DEPLOYMENT", "")

	_, err := db.Connect("postgres://user:pass@helium:5432/testdb")
	if err == nil {
		t.Fatal("expected error when connecting to helium host under CLOUD_DEPLOYMENT, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "misconfiguration") || !strings.Contains(got, "helium") {
		t.Errorf("expected misconfiguration error mentioning helium, got: %s", got)
	}
}
