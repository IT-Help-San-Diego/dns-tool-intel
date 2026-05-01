// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/db"

	"github.com/jackc/pgx/v5/pgconn"
)

// schemaAlreadyAppliedSQLStates are the Postgres SQLSTATE codes we treat as
// "the schema is already loaded" — expected on dev-loop re-runs against a
// long-lived Postgres that already has the tables/indexes from a previous
// run. Any other error from applying schema.sql is a real failure (e.g. a
// fresh CI service container that genuinely could not load the schema, or a
// syntax error in schema.sql) and must fail the test loudly so the operator
// is not left chasing downstream "relation does not exist" errors.
var schemaAlreadyAppliedSQLStates = map[string]struct{}{
	"42P07": {}, // duplicate_table
	"42P06": {}, // duplicate_schema
	"42710": {}, // duplicate_object (indexes, constraints, types, ...)
	"42701": {}, // duplicate_column
	"42723": {}, // duplicate_function
}

// isSchemaAlreadyAppliedError reports whether err is a Postgres error
// indicating that some schema object already exists. It is used to
// distinguish the expected "re-run against a populated dev database" case
// from a genuine schema-apply failure.
func isSchemaAlreadyAppliedError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	_, ok := schemaAlreadyAppliedSQLStates[pgErr.Code]
	return ok
}

func setupTestDB(t *testing.T) *db.Database {
	t.Helper()
	database := getTestDB(t)

	_, thisFile, _, _ := runtime.Caller(0)
	schemaPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "schema", "schema.sql")
	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema.sql: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err = database.Pool.Exec(ctx, string(schemaSQL))
	if err != nil {
		if isSchemaAlreadyAppliedError(err) {
			var pgErr *pgconn.PgError
			_ = errors.As(err, &pgErr)
			t.Logf("schema already applied (pg sqlstate %s: %s) — assuming dev-loop re-run against populated database", pgErr.Code, pgErr.Message)
		} else {
			t.Fatalf("could not load schema from %s against test database: %v", schemaPath, err)
		}
	}

	return database
}

func cleanupTestDB(t *testing.T, database *db.Database) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tables := []string{
		"drift_notifications",
		"notification_endpoints",
		"domain_watchlist",
		"drift_events",
		"zone_imports",
		"user_analyses",
		"site_analytics",
		"ice_regressions",
		"ice_maturity",
		"ice_results",
		"ice_test_runs",
		"ice_protocols",
		"sessions",
		"analysis_stats",
		"data_governance_events",
		"domain_analyses",
		"users",
	}

	for _, table := range tables {
		_, err := database.Pool.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE")
		if err != nil {
			t.Logf("truncate %s: %v", table, err)
		}
	}
}

func testConfig() *config.Config {
	return &config.Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		SessionSecret:    "test-secret",
		Port:             "5000",
		AppVersion:       "test",
		SMTPProbeMode:    "skip",
		BaseURL:          "https://dnstool.it-help.tech",
		IsDevEnvironment: true,
		SectionTuning:    map[string]string{},
		BetaPages:        map[string]bool{},
	}
}

func TestGetTestDB(t *testing.T) {
	database := setupTestDB(t)
	cleanupTestDB(t, database)
}
