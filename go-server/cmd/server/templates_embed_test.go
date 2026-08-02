// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
//
// Embedded-template contract: the full set parses (a syntax error fails the
// suite, never the first production boot) and parsing is cwd-independent —
// the property the embedding exists to guarantee. These tests replace
// TestFindTemplatesDir/Fallback, which pinned the disk-resolution behavior
// the embedding deletes.
package main

import (
	"os"
	"testing"

	templatesembed "dnstool/go-server/templates"
)

func TestParseEmbeddedTemplates(t *testing.T) {
	tmpl, err := parseEmbeddedTemplates()
	if err != nil {
		t.Fatalf("embedded template set failed to parse: %v", err)
	}
	// Boot-critical templates the router renders unconditionally; a rename
	// here should be a deliberate act that updates this list.
	for _, name := range []string{"index.html", "_head.html", "_nav.html", "_footer.html", "history.html", "topology.html"} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("embedded set is missing %s", name)
		}
	}
	entries, err := templatesembed.Files.ReadDir(".")
	if err != nil {
		t.Fatalf("reading embedded FS: %v", err)
	}
	// Drift floor, not an exact count: catches an embed glob that silently
	// matched a near-empty directory (e.g. after a bad move), not routine
	// template additions/removals.
	if len(entries) < 60 {
		t.Errorf("embedded FS holds %d templates — expected the full set (~73); the go:embed glob is matching the wrong directory", len(entries))
	}
}

func TestParseEmbeddedTemplates_CwdIndependent(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	// The old disk loader died from exactly this state (wrong cwd, no
	// templates dir anywhere) with os.Exit(1) in a systemd crash-loop.
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	tmpl, err := parseEmbeddedTemplates()
	if err != nil {
		t.Fatalf("embedded templates must parse from ANY cwd, got: %v", err)
	}
	if tmpl.Lookup("index.html") == nil {
		t.Error("index.html missing when parsed from a foreign cwd")
	}
}
