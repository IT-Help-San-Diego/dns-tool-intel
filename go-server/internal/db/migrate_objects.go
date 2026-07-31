// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// What a migration creates, and what the database currently has, expressed in
// the same vocabulary so the adoption probe can compare them directly.
//
// This exists so that "is this pre-ledger database already at version N?" is
// answered by reading migration N's own SQL rather than by consulting a
// hand-maintained list of what version N was supposed to have produced. A
// hand-maintained list is a claim about the migrations that nothing verifies,
// and it goes stale the first time someone edits a migration without updating
// it — the same defect that let schema.sql drift away from the chain it was
// supposed to mirror.

type tableColumn struct {
	Table  string
	Column string
}

func (tc tableColumn) String() string { return tc.Table + "." + tc.Column }

// migrationObjects is the set of schema objects one migration creates.
type migrationObjects struct {
	Tables  []string
	Indexes []string
	Columns []tableColumn
}

// schemaObjects is the same vocabulary, read from a live database.
type schemaObjects struct {
	Tables  map[string]struct{}
	Indexes map[string]struct{}
	Columns map[tableColumn]struct{}
}

// partition splits a migration's objects into those already present in the
// database and those still absent, each as a sorted, human-readable list.
func (m migrationObjects) partition(existing schemaObjects) (present, absent []string) {
	for _, t := range m.Tables {
		if _, ok := existing.Tables[t]; ok {
			present = append(present, "table "+t)
		} else {
			absent = append(absent, "table "+t)
		}
	}
	for _, ix := range m.Indexes {
		if _, ok := existing.Indexes[ix]; ok {
			present = append(present, "index "+ix)
		} else {
			absent = append(absent, "index "+ix)
		}
	}
	for _, c := range m.Columns {
		// A column on a table that does not exist yet is reported as absent,
		// not as a separate failure — the missing table already says it.
		if _, ok := existing.Columns[c]; ok {
			present = append(present, "column "+c.String())
		} else {
			absent = append(absent, "column "+c.String())
		}
	}
	sort.Strings(present)
	sort.Strings(absent)
	return present, absent
}

var (
	// Anchored at line start so a name mentioned inside a comment or inside a
	// column definition cannot be mistaken for a declaration.
	reCreateTable = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)`)
	reCreateIndex = regexp.MustCompile(`(?im)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)`)

	// ALTER ... ADD COLUMN is routinely split across lines (014 and 015 both do
	// it), so this one spans newlines and cannot be line-anchored. Comments are
	// stripped before it runs, which is what keeps that safe.
	reAddColumn = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)`)

	reLineComment = regexp.MustCompile(`--[^\n]*`)
)

// parseMigrationObjects extracts the tables, indexes and columns a migration
// declares. It is deliberately conservative: it understands the SQL this
// project actually writes (unquoted, unqualified identifiers; no block
// comments — verified across all 15 migrations) and nothing more. Anything it
// cannot see simply does not participate in the adoption probe, which makes an
// unparsed construct a missed opportunity to adopt rather than a false claim
// that a migration has already run.
func parseMigrationObjects(sqlText string) migrationObjects {
	stripped := reLineComment.ReplaceAllString(sqlText, "")

	var objs migrationObjects
	seenTable := map[string]bool{}
	for _, m := range reCreateTable.FindAllStringSubmatch(stripped, -1) {
		name := strings.ToLower(m[1])
		if !seenTable[name] {
			seenTable[name] = true
			objs.Tables = append(objs.Tables, name)
		}
	}
	seenIndex := map[string]bool{}
	for _, m := range reCreateIndex.FindAllStringSubmatch(stripped, -1) {
		name := strings.ToLower(m[1])
		if !seenIndex[name] {
			seenIndex[name] = true
			objs.Indexes = append(objs.Indexes, name)
		}
	}
	seenCol := map[tableColumn]bool{}
	for _, m := range reAddColumn.FindAllStringSubmatch(stripped, -1) {
		tc := tableColumn{Table: strings.ToLower(m[1]), Column: strings.ToLower(m[2])}
		if !seenCol[tc] {
			seenCol[tc] = true
			objs.Columns = append(objs.Columns, tc)
		}
	}

	sort.Strings(objs.Tables)
	sort.Strings(objs.Indexes)
	sort.Slice(objs.Columns, func(i, j int) bool { return objs.Columns[i].String() < objs.Columns[j].String() })
	return objs
}

// inspectSchema reads the tables, indexes and columns the connected schema
// currently has. One round trip each, so the adoption probe never queries the
// database per migration.
func inspectSchema(ctx context.Context, sqlDB *sql.DB) (schemaObjects, error) {
	out := schemaObjects{
		Tables:  map[string]struct{}{},
		Indexes: map[string]struct{}{},
		Columns: map[tableColumn]struct{}{},
	}

	tableRows, err := sqlDB.QueryContext(ctx, `
		SELECT table_name
		  FROM information_schema.tables
		 WHERE table_schema = current_schema()
		   AND table_type = 'BASE TABLE'`)
	if err != nil {
		return out, fmt.Errorf("list tables: %w", err)
	}
	if err := scanInto(tableRows, func(name string) { out.Tables[strings.ToLower(name)] = struct{}{} }); err != nil {
		return out, fmt.Errorf("list tables: %w", err)
	}

	indexRows, err := sqlDB.QueryContext(ctx, `
		SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()`)
	if err != nil {
		return out, fmt.Errorf("list indexes: %w", err)
	}
	if err := scanInto(indexRows, func(name string) { out.Indexes[strings.ToLower(name)] = struct{}{} }); err != nil {
		return out, fmt.Errorf("list indexes: %w", err)
	}

	colRows, err := sqlDB.QueryContext(ctx, `
		SELECT table_name, column_name
		  FROM information_schema.columns
		 WHERE table_schema = current_schema()`)
	if err != nil {
		return out, fmt.Errorf("list columns: %w", err)
	}
	defer colRows.Close()
	for colRows.Next() {
		var table, column string
		if err := colRows.Scan(&table, &column); err != nil {
			return out, fmt.Errorf("list columns: %w", err)
		}
		out.Columns[tableColumn{Table: strings.ToLower(table), Column: strings.ToLower(column)}] = struct{}{}
	}
	if err := colRows.Err(); err != nil {
		return out, fmt.Errorf("list columns: %w", err)
	}

	return out, nil
}

func scanInto(rows *sql.Rows, collect func(string)) error {
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		collect(name)
	}
	return rows.Err()
}
