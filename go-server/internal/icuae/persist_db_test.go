// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package icuae_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"testing"

	migrations "dnstool/go-server/db/migrations"
	"dnstool/go-server/internal/db"
	"dnstool/go-server/internal/dbq"
	"dnstool/go-server/internal/icuae"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// The columns behind these tests silently rejected three of the five grades
// for the project's entire life: 001_base_schema.sql sized them VARCHAR(5)
// for a letter vocabulary (A+..F) the producer never emitted, so excellent /
// adequate / degraded rows failed with SQLSTATE 22001 while good / stale
// landed — a stored distribution filtered by string length. Migration 018
// widened the columns; these tests exist so the producer vocabulary and the
// column width can never drift apart silently again.

// gradeWidthRE pulls the declared width out of 018's ALTERs. The width is
// read from the migration bytes rather than repeated here, so this file has
// no number to fall out of date.
var gradeWidthRE = regexp.MustCompile(`ALTER COLUMN (?:overall_grade|grade) TYPE VARCHAR\((\d+)\)`)

func TestGradeVocabularyFitsMigratedColumns(t *testing.T) {
	body, err := migrations.FS.ReadFile("018_icuae_grade_width.sql")
	if err != nil {
		t.Fatalf("read embedded 018_icuae_grade_width.sql: %v", err)
	}
	matches := gradeWidthRE.FindAllStringSubmatch(string(body), -1)
	// Apparatus check first: a regex that matches nothing would let the loop
	// below pass while measuring nothing.
	if len(matches) != 2 {
		t.Fatalf("expected 2 grade-column ALTERs in 018, found %d — the migration or this regex changed", len(matches))
	}
	width := -1
	for _, m := range matches {
		w, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("parse width %q: %v", m[1], err)
		}
		if width == -1 || w < width {
			width = w
		}
	}

	if len(icuae.GradeOrder) == 0 {
		t.Fatal("GradeOrder is empty — the vocabulary producer moved")
	}
	for grade := range icuae.GradeOrder {
		if len(grade) > width {
			t.Errorf("grade %q is %d chars; the migrated columns hold VARCHAR(%d). Widen via a NEW migration (018's comment explains why 001 stayed untouched).", grade, len(grade), width)
		}
	}
}

// TestRecordScanResultRoundTripsEveryGrade drives the REAL insert path
// (RecordScanResult -> dbq queries) against a freshly migrated scratch
// database and reads every grade back. Equality, not subset: each grade in
// the vocabulary must come back exactly once from each table, because the
// original defect was precisely a subset surviving.
//
// Gated on DATABASE_URL like the migration integration tests; the role needs
// CREATEDB (the dev recipe's postgres superuser has it).
func TestRecordScanResultRoundTripsEveryGrade(t *testing.T) {
	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set, skipping icuae round-trip test")
	}
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Skipf("DATABASE_URL is not a parseable URL (%v), skipping", err)
	}

	ctx := context.Background()
	const scratchName = "dnstool_icuae_roundtrip"
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Skipf("cannot open DATABASE_URL (%v), skipping", err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+scratchName); err != nil {
		t.Skipf("cannot manage scratch databases (%v) — the test role needs CREATEDB; skipping", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+scratchName); err != nil {
		t.Skipf("cannot create scratch database (%v), skipping", err)
	}
	defer func() {
		_, _ = admin.ExecContext(ctx,
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", scratchName)
		if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+scratchName); err != nil {
			t.Logf("could not drop scratch database %s: %v", scratchName, err)
		}
	}()

	parsed.Path = "/" + scratchName
	scratchURL := parsed.String()
	if err := db.Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("migrate scratch database: %v", err)
	}

	conn, err := pgx.Connect(ctx, scratchURL)
	if err != nil {
		t.Fatalf("connect scratch database: %v", err)
	}
	defer conn.Close(ctx)
	queries := dbq.New(conn)

	// One scan per grade so overall_grade covers the vocabulary; each scan
	// carries one dimension with the same grade so the dimension column is
	// exercised by the same values.
	grades := make([]string, 0, len(icuae.GradeOrder))
	for g := range icuae.GradeOrder {
		grades = append(grades, g)
	}
	for _, g := range grades {
		icuae.RecordScanResult(ctx, queries, "roundtrip-"+g+".example", icuae.CurrencyReport{
			OverallGrade: g,
			OverallScore: 50,
			Dimensions: []icuae.DimensionScore{{
				Dimension: icuae.DimensionTTLCompliance,
				Grade:     g,
				Score:     50,
			}},
			ResolverCount: 1,
			RecordCount:   1,
		}, "test")
	}

	// RecordScanResult reports storage failure only through slog, so the
	// readback below is the assertion that nothing was dropped.
	for table, col := range map[string]string{
		"icuae_scan_scores":      "overall_grade",
		"icuae_dimension_scores": "grade",
	} {
		got := map[string]int{}
		rows, err := conn.Query(ctx, "SELECT "+col+", COUNT(*) FROM "+table+" GROUP BY 1")
		if err != nil {
			t.Fatalf("read back %s: %v", table, err)
		}
		for rows.Next() {
			var g string
			var n int64
			if err := rows.Scan(&g, &n); err != nil {
				t.Fatalf("scan %s row: %v", table, err)
			}
			got[g] = int(n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate %s: %v", table, err)
		}
		for _, g := range grades {
			if got[g] != 1 {
				t.Errorf("%s.%s: grade %q recorded %d times, want exactly 1 — a grade the producer emits is being dropped or duplicated", table, col, g, got[g])
			}
		}
		if len(got) != len(grades) {
			t.Errorf("%s.%s holds %d distinct grades, want %d — something outside the vocabulary landed: %v", table, col, len(got), len(grades), got)
		}
	}
}
