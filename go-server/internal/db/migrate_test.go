// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"testing"

	migrations "dnstool/go-server/db/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// ---------------------------------------------------------------------------
// Unit tests — no database required, so these run everywhere.
// ---------------------------------------------------------------------------

// TestEmbeddedChainIsWellFormed is the guard that makes every other guarantee
// possible: the chain must be a contiguous, uniquely-numbered, goose-parseable
// sequence starting at 1. A gap or a duplicate here would silently change which
// migrations a database is considered to have.
func TestEmbeddedChainIsWellFormed(t *testing.T) {
	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no migrations embedded")
	}

	for i, f := range files {
		want := int64(i + 1)
		if f.Version != want {
			t.Errorf("migration %d is version %d, want %d — the chain has a gap or is misordered (%s)", i, f.Version, want, f.Filename)
		}
		data, err := migrationBytes(t, f.Filename)
		if err != nil {
			t.Fatalf("read %s: %v", f.Filename, err)
		}
		if !strings.HasPrefix(data, "-- +goose Up") {
			t.Errorf("%s does not start with the `-- +goose Up` annotation; goose will refuse to parse it", f.Filename)
		}
		if len(f.SHA256) != 64 {
			t.Errorf("%s has a %d-char checksum, want 64", f.Filename, len(f.SHA256))
		}
	}
}

// TestEmbeddedChainBuildsTheBaseTables pins the specific regression that made
// this work necessary: the chain used to be additive-only and assumed the core
// tables already existed, so it could not create a database from empty.
func TestEmbeddedChainBuildsTheBaseTables(t *testing.T) {
	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}

	created := map[string]bool{}
	for _, f := range files {
		for _, tbl := range f.Objects.Tables {
			created[tbl] = true
		}
	}

	// A representative slice of the tables that only ever existed in
	// schema.sql. If any of these stops being created by the chain, an empty
	// database can no longer be provisioned by the binary.
	for _, tbl := range []string{"domain_analyses", "users", "sessions", "site_analytics", "ice_test_runs", "icuae_scan_scores", "zone_imports"} {
		if !created[tbl] {
			t.Errorf("no migration creates %q — the chain cannot build a database from empty", tbl)
		}
	}
}

// TestNoUnsplittableStatements guards a trap that only shows up at boot, and
// only against a real database.
//
// goose splits multi-statement files with endsWithSemicolon(), which scans
// words and STOPS at the first one starting with "--". It is not quote-aware,
// so a shell flag inside a string literal — `--since=`, `--oneline` — reads as
// a line comment, the statement never appears to end, and goose fails to parse
// the whole migration. 013 hit this on three rows of verbatim evidence text.
//
// The fix is `-- +goose StatementBegin/End`, which hands the statement over
// without splitting it. This test finds any new instance before it reaches a
// database, so it can be caught with `go test` and no Postgres running.
func TestNoUnsplittableStatements(t *testing.T) {
	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}

	for _, f := range files {
		body, err := migrationBytes(t, f.Filename)
		if err != nil {
			t.Fatalf("read %s: %v", f.Filename, err)
		}

		inBlock := false
		for i, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "-- +goose StatementBegin"):
				inBlock = true
				continue
			case strings.HasPrefix(trimmed, "-- +goose StatementEnd"):
				inBlock = false
				continue
			case inBlock || strings.HasPrefix(trimmed, "--"):
				continue
			}
			if col, inLiteral := firstDoubleDash(line); inLiteral {
				t.Errorf("%s:%d:%d has `--` inside a string literal outside a StatementBegin/End block. "+
					"goose will read it as a comment and fail to parse the migration. Wrap the statement in "+
					"`-- +goose StatementBegin` / `-- +goose StatementEnd`.\n  %s",
					f.Filename, i+1, col, truncate(trimmed, 120))
			}
		}
	}
}

// firstDoubleDash reports the column of the first `--` that appears inside a
// single-quoted string on the line, treating a doubled quote as an escape.
func firstDoubleDash(line string) (col int, found bool) {
	inString := false
	for i := 0; i < len(line); i++ {
		if line[i] == '\'' {
			if inString && i+1 < len(line) && line[i+1] == '\'' {
				i++ // escaped quote inside a literal
				continue
			}
			inString = !inString
			continue
		}
		if inString && line[i] == '-' && i+1 < len(line) && line[i+1] == '-' {
			return i + 1, true
		}
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func TestVersionFromFilename(t *testing.T) {
	cases := []struct {
		name    string
		want    int64
		wantErr bool
	}{
		{name: "001_base_schema.sql", want: 1},
		{name: "015_confidence_scores_link_seed.sql", want: 15},
		{name: "0042_thing.sql", want: 42},
		{name: "000_zero.sql", wantErr: true}, // goose reserves 0
		{name: "nounderscore.sql", wantErr: true},
		{name: "_leading.sql", wantErr: true},
		{name: "abc_notanumber.sql", wantErr: true},
	}
	for _, tc := range cases {
		got, err := versionFromFilename(tc.name)
		if tc.wantErr {
			if err == nil {
				t.Errorf("versionFromFilename(%q) = %d, want error", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("versionFromFilename(%q): unexpected error %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("versionFromFilename(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestParseMigrationObjects(t *testing.T) {
	const sample = `
-- +goose Up
-- A comment that mentions CREATE TABLE decoy_from_comment and
-- ALTER TABLE decoy ADD COLUMN also_a_decoy TEXT.
CREATE TABLE alpha (
    id SERIAL PRIMARY KEY,
    note TEXT
);
CREATE INDEX ix_alpha_note ON alpha (note);
CREATE UNIQUE INDEX IF NOT EXISTS uq_alpha ON alpha (id) WHERE note IS NOT NULL;
create table if not exists Bravo (id INT);

ALTER TABLE alpha
    ADD COLUMN IF NOT EXISTS extra BYTEA;
`
	got := parseMigrationObjects(sample)

	assertSet(t, "tables", got.Tables, []string{"alpha", "bravo"})
	assertSet(t, "indexes", got.Indexes, []string{"ix_alpha_note", "uq_alpha"})

	if len(got.Columns) != 1 || got.Columns[0].String() != "alpha.extra" {
		t.Errorf("columns = %v, want [alpha.extra]", got.Columns)
	}
}

// TestParseMigrationObjects_RealChain checks the parser against the two shapes
// in the real chain that a naive regex gets wrong: a multi-line ALTER, and a
// migration whose only content is INSERTs.
func TestParseMigrationObjects_RealChain(t *testing.T) {
	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}
	byName := map[string]migrationFile{}
	for _, f := range files {
		byName[f.Filename] = f
	}

	hll, ok := byName["014_site_analytics_hll.sql"]
	if !ok {
		t.Fatal("014_site_analytics_hll.sql missing from the chain")
	}
	if len(hll.Objects.Columns) != 1 || hll.Objects.Columns[0].String() != "site_analytics.hll_visitors" {
		t.Errorf("014 columns = %v, want [site_analytics.hll_visitors] — the multi-line ALTER was not parsed", hll.Objects.Columns)
	}

	seed, ok := byName["013_seed_findings_and_ede.sql"]
	if !ok {
		t.Fatal("013_seed_findings_and_ede.sql missing from the chain")
	}
	if len(seed.Objects.Tables)+len(seed.Objects.Indexes)+len(seed.Objects.Columns) != 0 {
		t.Errorf("013 declares objects %+v, want none — it is pure INSERTs", seed.Objects)
	}
}

func TestAdoptionCutoff(t *testing.T) {
	chain := []migrationFile{
		{Version: 1, Filename: "001_a.sql", Objects: migrationObjects{Tables: []string{"alpha"}}},
		{Version: 2, Filename: "002_b.sql", Objects: migrationObjects{Tables: []string{"bravo"}, Indexes: []string{"ix_bravo"}}},
		{Version: 3, Filename: "003_seed.sql"}, // no observable objects
		{Version: 4, Filename: "004_c.sql", Objects: migrationObjects{Columns: []tableColumn{{Table: "alpha", Column: "extra"}}}},
	}

	t.Run("everything present adopts the whole chain", func(t *testing.T) {
		existing := schemaFrom([]string{"alpha", "bravo"}, []string{"ix_bravo"}, []tableColumn{{Table: "alpha", Column: "extra"}})
		got, err := adoptionCutoff(chain, existing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 4 {
			t.Errorf("cutoff = %d, want 4", got)
		}
	})

	t.Run("stops at the first fully-absent migration", func(t *testing.T) {
		// The production-shaped case: an old database that never received the
		// last few migrations. Everything up to 2 is stamped; 3 and 4 run.
		existing := schemaFrom([]string{"alpha", "bravo"}, []string{"ix_bravo"}, nil)
		got, err := adoptionCutoff(chain, existing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 3 {
			t.Errorf("cutoff = %d, want 3 (003 has no objects so it inherits the adopted run; 004 is pending)", got)
		}
	})

	t.Run("refuses a half-applied migration", func(t *testing.T) {
		existing := schemaFrom([]string{"alpha", "bravo"}, nil, nil) // bravo exists, its index does not
		_, err := adoptionCutoff(chain, existing)
		if err == nil {
			t.Fatal("expected an error for a half-applied migration, got nil")
		}
		if !strings.Contains(err.Error(), "HALF-WAY") || !strings.Contains(err.Error(), "002_b.sql") {
			t.Errorf("error should name the half-applied migration, got: %v", err)
		}
	})

	t.Run("later evidence outweighs objects a later migration dropped", func(t *testing.T) {
		// The platform-empty-ledger incident shape: 002 dropped alpha (so 001's
		// object is absent), but 002's and 004's objects are all present. A
		// per-migration probe reads 001 as pending and would re-run it; the
		// linear chain says everything through the last fully-present version
		// must have run.
		dropChain := []migrationFile{
			{Version: 1, Filename: "001_a.sql", Objects: migrationObjects{Tables: []string{"alpha"}}},
			{Version: 2, Filename: "002_b.sql", Objects: migrationObjects{Tables: []string{"bravo"}}},
			{Version: 3, Filename: "003_drop_alpha.sql"}, // pure DROP: no created objects
			{Version: 4, Filename: "004_c.sql", Objects: migrationObjects{Tables: []string{"charlie"}}},
			{Version: 5, Filename: "005_d.sql", Objects: migrationObjects{Tables: []string{"delta"}}},
		}
		existing := schemaFrom([]string{"bravo", "charlie"}, nil, nil) // alpha dropped, 005 pending
		got, err := adoptionCutoff(dropChain, existing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 4 {
			t.Errorf("cutoff = %d, want 4 (charlie present proves 001-004 ran; alpha's absence is 003's drop, not a pending 001)", got)
		}
	})

	t.Run("nothing recognisable adopts nothing", func(t *testing.T) {
		existing := schemaFrom([]string{"some_other_app"}, nil, nil)
		got, err := adoptionCutoff(chain, existing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("cutoff = %d, want 0", got)
		}
	})
}

func TestRefuseIfNewerThanBinary(t *testing.T) {
	files := []migrationFile{
		{Version: 1, Filename: "001_a.sql"},
		{Version: 2, Filename: "002_b.sql"},
	}

	t.Run("older database is allowed through", func(t *testing.T) {
		if err := refuseIfNewerThanBinary(map[int64]struct{}{1: {}}, files, 2); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("equal database is allowed through", func(t *testing.T) {
		if err := refuseIfNewerThanBinary(map[int64]struct{}{1: {}, 2: {}}, files, 2); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("newer database is refused, naming both versions", func(t *testing.T) {
		err := refuseIfNewerThanBinary(map[int64]struct{}{1: {}, 2: {}, 7: {}}, files, 2)
		if err == nil {
			t.Fatal("expected a refusal, got nil")
		}
		msg := err.Error()
		if !strings.Contains(msg, "version 7") {
			t.Errorf("refusal must name the database version 7, got: %s", msg)
		}
		if !strings.Contains(msg, "version 2") {
			t.Errorf("refusal must name the binary version 2, got: %s", msg)
		}
	})

	t.Run("applied version with no embedded file is refused", func(t *testing.T) {
		// Not "newer" — a migration that was applied and then deleted or
		// renamed. The chain and the database disagree either way.
		err := refuseIfNewerThanBinary(map[int64]struct{}{1: {}}, []migrationFile{{Version: 2, Filename: "002_b.sql"}}, 2)
		if err == nil {
			t.Fatal("expected a refusal, got nil")
		}
		if !strings.Contains(err.Error(), "renamed or deleted") {
			t.Errorf("refusal should explain the missing file, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Integration tests — each runs against its own scratch database, created and
// dropped by the test. They never touch the database DATABASE_URL points at.
// ---------------------------------------------------------------------------

// TestMigrate_CleanInstall is the claim compose now depends on: the binary can
// build a complete database from empty, with no schema.sql mounted anywhere.
func TestMigrate_CleanInstall(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("clean install failed: %v", err)
	}

	conn := openScratch(t, scratchURL)
	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(applied) != len(files) {
		t.Errorf("ledger records %d applied versions, want %d", len(applied), len(files))
	}

	sums, err := recordedChecksums(ctx, conn)
	if err != nil {
		t.Fatalf("recordedChecksums: %v", err)
	}
	for _, f := range files {
		if sums[f.Version] != f.SHA256 {
			t.Errorf("checksum for version %d = %q, want %q", f.Version, sums[f.Version], f.SHA256)
		}
	}

	// Every table the chain declares must actually be there.
	existing, err := inspectSchema(ctx, conn)
	if err != nil {
		t.Fatalf("inspectSchema: %v", err)
	}
	for _, f := range files {
		for _, tbl := range f.Objects.Tables {
			if _, ok := existing.Tables[tbl]; !ok {
				t.Errorf("table %q declared by %s was not created", tbl, f.Filename)
			}
		}
	}

	// Re-running must be a no-op, not a re-apply. This is the specific defect
	// in the loader this replaces: it re-executed its two files every boot.
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("second Migrate on an up-to-date database failed: %v", err)
	}
	applied2, err := appliedVersions(ctx, conn)
	if err != nil {
		t.Fatalf("appliedVersions after rerun: %v", err)
	}
	if len(applied2) != len(applied) {
		t.Errorf("rerun changed the applied set: %d -> %d", len(applied), len(applied2))
	}
}

// TestMigrate_AdoptsFullPreLedgerDatabase is the kept-volume scenario: a
// database provisioned the old way (full schema, no ledger) meets the new
// binary. It must be stamped, not rebuilt, and its rows must survive.
func TestMigrate_AdoptsFullPreLedgerDatabase(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	conn := openScratch(t, scratchURL)
	seedRow(t, ctx, conn)
	makePreLedger(t, ctx, conn)

	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("adoption of a full pre-ledger database failed: %v", err)
	}

	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}
	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(applied) != len(files) {
		t.Errorf("adoption stamped %d versions, want %d", len(applied), len(files))
	}
	assertRowSurvived(t, ctx, conn)
}

// TestMigrate_AdoptsPartialPreLedgerDatabase is the production-shaped case: a
// long-lived database that received the early migrations out of band but never
// the recent ones. The versions it has must be stamped and only the genuinely
// missing ones executed — with its data still in place afterwards.
func TestMigrate_AdoptsPartialPreLedgerDatabase(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	conn := openScratch(t, scratchURL)
	seedRow(t, ctx, conn)

	// Rewind past 014 and 015: drop the ledger, then remove exactly the objects
	// those two migrations create.
	makePreLedger(t, ctx, conn)
	mustExec(t, ctx, conn, "DROP TABLE IF EXISTS analytics_meta")
	mustExec(t, ctx, conn, "ALTER TABLE site_analytics DROP COLUMN IF EXISTS hll_visitors")
	mustExec(t, ctx, conn, "ALTER TABLE confidence_scores DROP COLUMN IF EXISTS analysis_id")

	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("adoption of a partial pre-ledger database failed: %v", err)
	}

	existing, err := inspectSchema(ctx, conn)
	if err != nil {
		t.Fatalf("inspectSchema: %v", err)
	}
	if _, ok := existing.Tables["analytics_meta"]; !ok {
		t.Error("migration 014 did not run: analytics_meta is still missing")
	}
	if _, ok := existing.Columns[tableColumn{Table: "site_analytics", Column: "hll_visitors"}]; !ok {
		t.Error("migration 014 did not run: site_analytics.hll_visitors is still missing")
	}
	if _, ok := existing.Columns[tableColumn{Table: "confidence_scores", Column: "analysis_id"}]; !ok {
		t.Error("migration 015 did not run: confidence_scores.analysis_id is still missing")
	}
	assertRowSurvived(t, ctx, conn)
}

// TestMigrate_RefusesUnrecognisedPopulatedDatabase covers the branch that
// protects data we cannot account for: a populated database that matches
// nothing in the chain is left completely alone.
func TestMigrate_RefusesUnrecognisedPopulatedDatabase(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	conn := openScratch(t, scratchURL)
	mustExec(t, ctx, conn, "CREATE TABLE someone_elses_data (id INT PRIMARY KEY, payload TEXT)")
	mustExec(t, ctx, conn, "INSERT INTO someone_elses_data VALUES (1, 'irreplaceable')")

	err := Migrate(ctx, scratchURL)
	if err == nil {
		t.Fatal("expected Migrate to refuse an unrecognised populated database")
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("unexpected error text: %v", err)
	}

	var payload string
	if qErr := conn.QueryRowContext(ctx, "SELECT payload FROM someone_elses_data WHERE id = 1").Scan(&payload); qErr != nil {
		t.Fatalf("the refused database was modified: %v", qErr)
	}
	if payload != "irreplaceable" {
		t.Errorf("payload = %q, want %q", payload, "irreplaceable")
	}
	if present, pErr := relationExists(ctx, conn, goose.TableName()); pErr != nil || present {
		t.Errorf("a ledger was created in a database we refused (present=%v, err=%v)", present, pErr)
	}
}

// TestMigrate_RefusesDatabaseNewerThanBinary is the downgrade guard: an older
// binary pointed at a schema a newer build produced must not start.
func TestMigrate_RefusesDatabaseNewerThanBinary(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	files, err := loadEmbeddedMigrations()
	if err != nil {
		t.Fatalf("loadEmbeddedMigrations: %v", err)
	}
	future := files[len(files)-1].Version + 1

	// Simulate a newer build having migrated this database. From this binary's
	// point of view that is exactly what it looks like.
	conn := openScratch(t, scratchURL)
	mustExec(t, ctx, conn, fmt.Sprintf("INSERT INTO %s (version_id, is_applied) VALUES (%d, true)", goose.TableName(), future))

	err = Migrate(ctx, scratchURL)
	if err == nil {
		t.Fatal("expected Migrate to refuse a database newer than the binary")
	}
	msg := err.Error()
	if !strings.Contains(msg, fmt.Sprintf("version %d", future)) {
		t.Errorf("refusal must name the database version %d, got: %s", future, msg)
	}
	if !strings.Contains(msg, fmt.Sprintf("version %d", files[len(files)-1].Version)) {
		t.Errorf("refusal must name the binary version %d, got: %s", files[len(files)-1].Version, msg)
	}
}

// TestMigrate_DetectsEditedMigration covers the failure a version-only ledger
// cannot see: an already-applied migration edited afterwards. Its version is
// stamped, so it will never run again, and without a checksum the difference
// between the file and the database is invisible.
func TestMigrate_DetectsEditedMigration(t *testing.T) {
	scratchURL, cleanup := scratchDatabase(t)
	defer cleanup()

	ctx := context.Background()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	// Rewriting the recorded checksum is equivalent to rewriting the file: the
	// runner compares the two and cannot tell which side moved.
	conn := openScratch(t, scratchURL)
	mustExec(t, ctx, conn, fmt.Sprintf(
		"UPDATE %s SET sha256 = repeat('0', 64) WHERE version_id = 7", checksumTable))

	err := Migrate(ctx, scratchURL)
	if err == nil {
		t.Fatal("expected Migrate to refuse a chain whose applied migration was edited")
	}
	if !strings.Contains(err.Error(), "edited since they ran") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// scratchDatabase creates a throwaway database beside the one DATABASE_URL
// names and returns a URL for it. The test's own database is created and
// dropped by the test; the configured one is only ever used to issue those two
// statements.
func scratchDatabase(t *testing.T) (scratchURL string, cleanup func()) {
	t.Helper()

	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set, skipping migration integration test")
	}

	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Skipf("DATABASE_URL is not a parseable URL (%v), skipping", err)
	}

	name := "dnstool_migtest_" + sanitizeForIdentifier(t.Name())
	if len(name) > 60 {
		name = name[:60]
	}

	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Skipf("cannot open DATABASE_URL (%v), skipping", err)
	}
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name); err != nil {
		admin.Close()
		t.Skipf("cannot manage scratch databases (%v) — the test role needs CREATEDB; skipping", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Skipf("cannot create scratch database (%v) — the test role needs CREATEDB; skipping", err)
	}

	parsed.Path = "/" + name
	scratchURL = parsed.String()

	return scratchURL, func() {
		defer admin.Close()
		// Terminate stragglers so DROP does not block on a lingering session.
		_, _ = admin.ExecContext(ctx,
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", name)
		if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name); err != nil {
			t.Logf("could not drop scratch database %s: %v", name, err)
		}
	}
}

func sanitizeForIdentifier(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func openScratch(t *testing.T, scratchURL string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("pgx", scratchURL)
	if err != nil {
		t.Fatalf("open scratch database: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func mustExec(t *testing.T, ctx context.Context, conn *sql.DB, query string) {
	t.Helper()
	if _, err := conn.ExecContext(ctx, query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// makePreLedger turns a migrated database back into one that predates the
// version ledger, which is what every existing deployment looks like.
func makePreLedger(t *testing.T, ctx context.Context, conn *sql.DB) {
	t.Helper()
	mustExec(t, ctx, conn, "DROP TABLE IF EXISTS "+goose.TableName())
	mustExec(t, ctx, conn, "DROP TABLE IF EXISTS "+checksumTable)
}

// seedRow writes the row that stands in for the data an upgrade must not lose.
func seedRow(t *testing.T, ctx context.Context, conn *sql.DB) {
	t.Helper()
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO domain_analyses (domain, ascii_domain, full_results)
		VALUES ('irreplaceable.example', 'irreplaceable.example', '{}'::json)`); err != nil {
		t.Fatalf("seed row: %v", err)
	}
}

func assertRowSurvived(t *testing.T, ctx context.Context, conn *sql.DB) {
	t.Helper()
	var count int
	if err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM domain_analyses WHERE domain = 'irreplaceable.example'").Scan(&count); err != nil {
		t.Fatalf("count seeded rows: %v", err)
	}
	if count != 1 {
		t.Errorf("seeded row count = %d, want 1 — the upgrade did not preserve existing data", count)
	}
}

func schemaFrom(tables, indexes []string, columns []tableColumn) schemaObjects {
	out := schemaObjects{
		Tables:  map[string]struct{}{},
		Indexes: map[string]struct{}{},
		Columns: map[tableColumn]struct{}{},
	}
	for _, t := range tables {
		out.Tables[t] = struct{}{}
	}
	for _, i := range indexes {
		out.Indexes[i] = struct{}{}
	}
	for _, c := range columns {
		out.Columns[c] = struct{}{}
	}
	return out
}

func assertSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", label, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, got, want)
			return
		}
	}
}

func migrationBytes(t *testing.T, name string) (string, error) {
	t.Helper()
	data, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
