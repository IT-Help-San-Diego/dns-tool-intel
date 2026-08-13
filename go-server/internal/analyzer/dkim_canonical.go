// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"sort"
	"strings"
	"unicode"
)

// canonicalDKIMRecord reduces a DKIM key record to the one form shared by
// every transport representation of the same RDATA. A record longer than 255
// bytes travels as multiple DNS character-strings, and the rejoin differs by
// path: chunks concatenated bare, joined with a space, or each chunk quoted
// (`"a" "b"` — and after a naive outer-quote trim, `a" "b`). Per RFC 6376
// §3.6.1 the RDATA is the plain concatenation — quotes are wire framing and
// FWS inside tag values is not significant — so quotes and whitespace are
// dropped wholesale. Comparison/parsing only: stored records keep the observed
// bytes.
func canonicalDKIMRecord(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// canonicalDKIMRecordSet folds a scan's discovered selector→records map into
// one order-independent canonical string, so two scans can be asked "did the
// domain publish the same DKIM material?" independent of transport
// representation, selector iteration order, or verdict wording. Returns "" when
// the scan discovered nothing (an empty set proves nothing — the caller must
// not treat it as evidence of sameness OR of removal).
func canonicalDKIMRecordSet(results map[string]any) string {
	dkim, ok := results[mapKeyDkimAnalysis].(map[string]any)
	if !ok {
		return ""
	}
	selectors, ok := dkim["selectors"].(map[string]any)
	if !ok {
		return ""
	}
	var parts []string
	for selName, sd := range selectors {
		m, ok := sd.(map[string]any)
		if !ok {
			continue
		}
		var recs []string
		switch v := m[mapKeyRecords].(type) {
		case []any:
			for _, r := range v {
				if s, ok := r.(string); ok {
					recs = append(recs, canonicalDKIMRecord(s))
				}
			}
		case []string:
			for _, s := range v {
				recs = append(recs, canonicalDKIMRecord(s))
			}
		}
		if len(recs) == 0 {
			continue
		}
		sort.Strings(recs)
		parts = append(parts, strings.ToLower(strings.TrimSpace(selName))+"="+strings.Join(recs, "\x1f"))
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x1e")
}
