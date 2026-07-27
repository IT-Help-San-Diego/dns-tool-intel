// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestVerdictStatusesHaveClientAliases guards a synchronisation hazard that
// has no other enforcement: the analyzers emit status strings, the server
// passes them through verbatim (analysis_replay.go — "never collapsed into
// pass or fail"), and go-server/static/js/topology.js decides what colour each
// one draws. Those are two independent lists.
//
// When they drifted, the client knew four statuses and fell through to RED for
// everything else — so 'pass', 'present', 'ok' and 'found' drew failure rings,
// and 'skipped' drew a failure for something never measured. Affirmative
// results rendering as failures is the worst class of bug in an instrument
// whose entire job is honest reporting.
//
// The client now defaults unknown statuses to 'indeterminate', so drift is no
// longer dangerous — but it is still wrong, because a real state would render
// as "we don't know". This test makes the drift visible at build time.
func TestVerdictStatusesHaveClientAliases(t *testing.T) {
	emitted := collectAnalyzerStatuses(t)
	if len(emitted) < 5 {
		t.Fatalf("status scan found only %d literals — the extraction pattern has probably gone stale, which would make this test vacuous", len(emitted))
	}

	known := parseClientStatusVocabulary(t)
	if len(known) < 10 {
		t.Fatalf("parsed only %d client statuses from topology.js — parser likely broken", len(known))
	}

	var missing []string
	for s := range emitted {
		if !known[s] {
			missing = append(missing, s)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("analyzer emits status(es) the topology client does not recognise: %v\n"+
			"Add each to VERDICT_STATUS_ALIAS (or ABSENCE_STATUSES) in go-server/static/js/topology.js "+
			"and map it to success / warning / failed / indeterminate. Unrecognised states render as "+
			"'indeterminate', which is safe but wrong for a state we actually understand.", missing)
	}
}

// collectAnalyzerStatuses extracts status string literals from the shapes that
// actually serialise into full_results and therefore reach the client.
func collectAnalyzerStatuses(t *testing.T) map[string]bool {
	t.Helper()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`"status"\s*:\s*"([a-z_]+)"`),
		regexp.MustCompile(`\bStatus:\s*"([a-z_]+)"`),
		regexp.MustCompile(`\bstatus\s*=\s*"([a-z_]+)"`),
	}
	out := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				if len(m) > 1 && m[1] != "" {
					out[m[1]] = true
				}
			}
		}
	}
	return out
}

// parseClientStatusVocabulary reads the keys of VERDICT_STATUS_ALIAS and
// ABSENCE_STATUSES out of topology.js.
func parseClientStatusVocabulary(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "static", "js", "topology.js")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	src := string(b)
	known := map[string]bool{}
	keyRe := regexp.MustCompile(`([a-z_]+)\s*:`)
	for _, name := range []string{"VERDICT_STATUS_ALIAS", "ABSENCE_STATUSES"} {
		i := strings.Index(src, name)
		if i < 0 {
			t.Fatalf("%s not found in topology.js", name)
		}
		open := strings.Index(src[i:], "{")
		close := strings.Index(src[i:], "};")
		if open < 0 || close < 0 || close <= open {
			t.Fatalf("could not bound the %s literal", name)
		}
		for _, m := range keyRe.FindAllStringSubmatch(src[i+open:i+close], -1) {
			known[m[1]] = true
		}
	}
	return known
}
