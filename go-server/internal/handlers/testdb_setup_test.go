// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
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

// schemaCreateTableRE matches `CREATE TABLE [IF NOT EXISTS] <name>` in the
// canonical schema.sql. It is intentionally tolerant of whitespace, case, and
// the optional IF NOT EXISTS clause, but does not attempt to parse quoted or
// schema-qualified table names — schema.sql does not currently use either.
var schemaCreateTableRE = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// parseSchemaTableNames extracts the set of table names declared by
// `CREATE TABLE` statements in schema.sql. It returns a sorted, deduplicated
// slice so callers can produce stable, diff-friendly error messages.
func parseSchemaTableNames(schemaSQL string) []string {
	matches := schemaCreateTableRE.FindAllStringSubmatch(schemaSQL, -1)
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		seen[strings.ToLower(m[1])] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// findMissingTables returns the subset of expected tables that are NOT
// present in the connected database's current schema. It is the dev-loop
// safety net that detects a stale local database where new tables added to
// schema.sql were silently never created (because Postgres aborted the
// multi-statement schema apply on the first duplicate-table error).
func findMissingTables(ctx context.Context, database *db.Database, expected []string) ([]string, error) {
	if len(expected) == 0 {
		return nil, nil
	}
	rows, err := database.Pool.Query(ctx,
		`SELECT table_name
                   FROM information_schema.tables
                  WHERE table_schema = current_schema()
                    AND table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, fmt.Errorf("query existing tables: %w", err)
	}
	defer rows.Close()

	present := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan existing tables: %w", err)
		}
		present[strings.ToLower(name)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate existing tables: %w", err)
	}

	var missing []string
	for _, name := range expected {
		if _, ok := present[name]; !ok {
			missing = append(missing, name)
		}
	}
	return missing, nil
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

	// Stale-dev-database guard: Postgres aborts a multi-statement Exec on the
	// FIRST duplicate-table error, which means every CREATE TABLE *after* that
	// point in schema.sql is silently skipped on a long-lived dev database.
	// Without this check, adding a new table to schema.sql and re-running the
	// handler tests against an existing dev database fails downstream with a
	// confusing "relation does not exist" error. Detect that case here and
	// fail loudly with an actionable message instead.
	expectedTables := parseSchemaTableNames(string(schemaSQL))
	missing, mErr := findMissingTables(ctx, database, expectedTables)
	if mErr != nil {
		t.Fatalf("could not verify schema completeness against test database: %v", mErr)
	}
	if len(missing) > 0 {
		t.Fatalf(
			"local test database is stale: schema.sql declares %d table(s) that are missing from the connected database: %s\n"+
				"This usually means tables were added to %s after the dev database was first created, "+
				"and Postgres aborted the schema reload on a pre-existing duplicate before reaching the new statements.\n"+
				"Drop and recreate the dev database (e.g. `psql \"$DATABASE_URL\" -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'` "+
				"and re-run the tests, or recreate the Replit database from the Database pane) so schema.sql can be applied to a clean database.",
			len(missing), strings.Join(missing, ", "), schemaPath)
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

// TestParseSchemaTableNames pins down the regex behavior used by the stale-DB
// guard. It runs without a database, so it executes in CI and locally even
// when DATABASE_URL is unset.
func TestParseSchemaTableNames(t *testing.T) {
	const sampleSQL = `
-- header comment
CREATE TABLE alpha (
    id SERIAL PRIMARY KEY
);

CREATE INDEX ix_alpha_id ON alpha (id);

create table   bravo (
    id SERIAL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS charlie (
    id SERIAL PRIMARY KEY
);

CREATE TABLE Delta (
    id SERIAL PRIMARY KEY
);

-- duplicate declaration should dedupe to one entry
CREATE TABLE alpha (
    id SERIAL PRIMARY KEY
);
`

	got := parseSchemaTableNames(sampleSQL)
	want := []string{"alpha", "bravo", "charlie", "delta"}
	if len(got) != len(want) {
		t.Fatalf("parseSchemaTableNames returned %d names, want %d: %v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("parseSchemaTableNames[%d] = %q, want %q (full result: %v)", i, got[i], name, got)
		}
	}
}

// TestParseSchemaTableNames_CanonicalSchema sanity-checks that the regex
// actually finds every table the canonical schema.sql declares — at least the
// well-known core tables that the cleanupTestDB truncate list also relies on.
// If schema.sql is reformatted in a way that breaks parsing, this test fails
// loudly instead of letting the stale-DB guard silently pass everything.
func TestParseSchemaTableNames_CanonicalSchema(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	schemaPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "schema", "schema.sql")
	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema.sql: %v", err)
	}

	got := parseSchemaTableNames(string(schemaSQL))
	if len(got) < 10 {
		t.Fatalf("parseSchemaTableNames found only %d tables in canonical schema.sql; regex likely broken: %v", len(got), got)
	}

	gotSet := make(map[string]struct{}, len(got))
	for _, name := range got {
		gotSet[name] = struct{}{}
	}

	// Spot-check a handful of representative tables spanning the schema:
	// the very first declaration, an `IF NOT EXISTS` declaration, and a
	// table from late in the file (added in a later migration). If any of
	// these is missing, parsing has regressed.
	mustHave := []string{"domain_analyses", "analytics_meta", "confidence_scores"}
	for _, name := range mustHave {
		if _, ok := gotSet[name]; !ok {
			t.Errorf("expected canonical schema.sql to contain table %q (parsed result: %v)", name, got)
		}
	}
}
