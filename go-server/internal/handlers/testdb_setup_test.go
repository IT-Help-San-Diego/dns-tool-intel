// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers_test

import (
	"context"
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
)

// schemaCreateTableRE matches `CREATE TABLE [IF NOT EXISTS] [schema.]<name> (`.
// schema.sql is now `pg_dump --schema-only` output, which qualifies every table
// as `public.<name>`; the optional qualifier and the optional IF NOT EXISTS
// keep this working against hand-written SQL too.
var schemaCreateTableRE = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

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

// ledgerTables are created by the migration runner rather than by a migration,
// so schema.sql does not document them and the drift check must not expect it
// to. See go-server/internal/db/migrate.go.
var ledgerTables = map[string]struct{}{
	"goose_db_version":           {},
	"schema_migration_checksums": {},
}

// databaseTableNames returns the base tables in the connected database, minus
// the version ledger.
func databaseTableNames(ctx context.Context, database *db.Database) ([]string, error) {
	rows, err := database.Pool.Query(ctx,
		`SELECT table_name
                   FROM information_schema.tables
                  WHERE table_schema = current_schema()
                    AND table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, fmt.Errorf("query existing tables: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan existing tables: %w", err)
		}
		name = strings.ToLower(name)
		if _, skip := ledgerTables[name]; skip {
			continue
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate existing tables: %w", err)
	}
	sort.Strings(names)
	return names, nil
}

func schemaDocPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "schema", "schema.sql")
}

// setupTestDB brings the test database to the version the binary expects, using
// exactly the path production uses.
//
// It used to apply go-server/db/schema/schema.sql directly and then tolerate
// "already exists" errors, which meant a stale dev database silently kept an
// old schema: Postgres aborts a multi-statement Exec on the first duplicate, so
// every statement after that point was skipped. There is nothing to tolerate
// now — the ledger records what has been applied, so an up-to-date database is
// a no-op and a stale one is upgraded.
func setupTestDB(t *testing.T) *db.Database {
	t.Helper()
	database := getTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := db.Migrate(ctx, os.Getenv("DATABASE_URL")); err != nil {
		t.Fatalf("could not migrate the test database: %v", err)
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

// TestSchemaDocMatchesMigratedDatabase is the drift detector.
//
// schema.sql is generated documentation now, but generated files go stale the
// moment someone adds a migration and forgets to re-run the generator — and a
// stale schema.sql is exactly what caused two reviewers to misread this schema
// in a single session. This compares the file against a database the chain
// actually built, so the two cannot silently disagree.
//
// Regenerate with ./scripts/regen-schema-doc.sh.
func TestSchemaDocMatchesMigratedDatabase(t *testing.T) {
	database := setupTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	schemaSQL, err := os.ReadFile(schemaDocPath())
	if err != nil {
		t.Fatalf("failed to read schema.sql: %v", err)
	}
	documented := parseSchemaTableNames(string(schemaSQL))

	actual, err := databaseTableNames(ctx, database)
	if err != nil {
		t.Fatalf("could not list tables in the test database: %v", err)
	}

	documentedSet := make(map[string]struct{}, len(documented))
	for _, name := range documented {
		documentedSet[name] = struct{}{}
	}
	actualSet := make(map[string]struct{}, len(actual))
	for _, name := range actual {
		actualSet[name] = struct{}{}
	}

	var undocumented, phantom []string
	for _, name := range actual {
		if _, ok := documentedSet[name]; !ok {
			undocumented = append(undocumented, name)
		}
	}
	for _, name := range documented {
		if _, ok := actualSet[name]; !ok {
			phantom = append(phantom, name)
		}
	}

	if len(undocumented) > 0 {
		t.Errorf("schema.sql is stale: the migration chain creates %d table(s) it does not document: %s\n"+
			"Regenerate it with ./scripts/regen-schema-doc.sh",
			len(undocumented), strings.Join(undocumented, ", "))
	}
	if len(phantom) > 0 {
		t.Errorf("schema.sql documents %d table(s) the migration chain does not create: %s\n"+
			"Either the table was dropped and schema.sql was not regenerated, or schema.sql was hand-edited. "+
			"Regenerate it with ./scripts/regen-schema-doc.sh",
			len(phantom), strings.Join(phantom, ", "))
	}
}

// TestParseSchemaTableNames pins down the regex behavior used by the drift
// check. It runs without a database, so it executes in CI and locally even when
// DATABASE_URL is unset.
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

-- pg_dump form: schema-qualified
CREATE TABLE public.echo (
    id integer NOT NULL
);

-- duplicate declaration should dedupe to one entry
CREATE TABLE alpha (
    id SERIAL PRIMARY KEY
);
`

	got := parseSchemaTableNames(sampleSQL)
	want := []string{"alpha", "bravo", "charlie", "delta", "echo"}
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
// actually finds the tables the generated schema.sql declares. If the dump
// format changes in a way that breaks parsing, this fails loudly instead of
// letting the drift check silently pass everything.
func TestParseSchemaTableNames_CanonicalSchema(t *testing.T) {
	schemaSQL, err := os.ReadFile(schemaDocPath())
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

	// Spot-check tables spanning the chain: one from the base schema, one
	// added late by a migration, and one created with IF NOT EXISTS.
	mustHave := []string{"domain_analyses", "analytics_meta", "confidence_scores"}
	for _, name := range mustHave {
		if _, ok := gotSet[name]; !ok {
			t.Errorf("expected canonical schema.sql to contain table %q (parsed result: %v)", name, got)
		}
	}
}
