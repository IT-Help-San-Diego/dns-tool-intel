// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package dbq

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	migrations "dnstool/go-server/db/migrations"
)

// TestCountDNSSECUnmeasuredPredicateMatchesIndexExpression guards migration 022's
// ix_da_dnssec_chain_of_trust index against a silent plan regression.
//
// The /stats handler caches CountDNSSECUnmeasured for 5 minutes, so if the WHERE
// predicate drifts from the indexed expression (or the index is dropped), the
// query returns to a Seq Scan while the page stays fast on the cache — presenting
// as intermittent slowness rather than a broken page. This test asserts the
// predicate uses the exact expression the index was built on, so the divergence
// fails here the moment it is introduced, not as a production slowdown later.
func TestCountDNSSECUnmeasuredPredicateMatchesIndexExpression(t *testing.T) {
	indexExpr := findDNSSECUnmeasuredIndexExpr(t)
	if indexExpr == "" {
		t.Fatal("ix_da_dnssec_chain_of_trust not found in any embedded migration, or has no indexable expression")
	}
	if !strings.Contains(countDNSSECUnmeasured, indexExpr) {
		t.Fatalf("CountDNSSECUnmeasured predicate does not use the indexed expression %q — the query would Seq Scan while the 5-minute cache hides it", indexExpr)
	}
}

// findDNSSECUnmeasuredIndexExpr walks the embedded migration chain and returns
// the parenthesised expression behind ix_da_dnssec_chain_of_trust, resolved by
// index NAME rather than migration number so a future renumber does not
// false-positive.
func findDNSSECUnmeasuredIndexExpr(t *testing.T) string {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrations.FS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		if !strings.Contains(string(b), "ix_da_dnssec_chain_of_trust") {
			continue
		}
		if expr := extractDNSSECIndexExpr(string(b)); expr != "" {
			return expr
		}
	}
	return ""
}

// extractDNSSECIndexExpr pulls the expression from a
// CREATE INDEX ... ON <table> ((expr)) statement.
func extractDNSSECIndexExpr(sql string) string {
	re := regexp.MustCompile(`ON\s+\w+\s+\(\(([^)]+)\)\)`)
	m := re.FindStringSubmatch(sql)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}
