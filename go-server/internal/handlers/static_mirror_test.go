// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package handlers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestStaticMirrorSync fails when any file that exists in BOTH static/ and
// go-server/static/ has diverged. These two directories are mirrors: the
// server tries static/ first (findStaticDir), then go-server/static/. A file
// that differs between them serves different content depending on which
// directory the working directory happens to be — the same class as the
// stale main.min.js that sat three months behind its source.
//
// The pair list is derived by globbing both directories, not hardcoded, so
// a new mirrored file is checked automatically. A hand-written pair list
// finds only what someone remembered to add.
func TestStaticMirrorSync(t *testing.T) {
	dirs := []struct {
		name string
		path string
	}{
		{"static", "../../../static"},
		{"go-server/static", "../../static"},
	}

	// Collect all .txt, .xml, .json, .ico, .svg files from both directories.
	seen := map[string]bool{}
	var mismatches []string

	for _, d := range dirs {
		err := filepath.Walk(d.path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".txt" && ext != ".xml" && ext != ".json" && ext != ".ico" && ext != ".svg" {
				return nil
			}
			rel, relErr := filepath.Rel(d.path, path)
			if relErr != nil {
				return relErr
			}
			if seen[rel] {
				return nil // already checked from the other directory
			}
			seen[rel] = true

			// Build the sibling path in the other directory.
			var sibling string
			for _, other := range dirs {
				if other.path != d.path {
					sibling = filepath.Join(other.path, rel)
				}
			}
			if sibling == "" {
				return nil
			}

			// Only compare when the file exists in BOTH mirrors.
			siblingInfo, statErr := os.Stat(sibling)
			if statErr != nil || siblingInfo.IsDir() {
				return nil
			}

			a, errA := os.ReadFile(path)
			b, errB := os.ReadFile(sibling)
			if errA != nil || errB != nil {
				return nil
			}

			hashA := sha256.Sum256(a)
			hashB := sha256.Sum256(b)
			if hashA != hashB {
				mismatches = append(mismatches, fmt.Sprintf(
					"%s: %s (%d bytes) != %s (%d bytes)",
					rel, path, len(a), sibling, len(b),
				))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", d.path, err)
		}
	}

	if len(mismatches) > 0 {
		t.Errorf("static mirror divergence detected (%d file(s)):", len(mismatches))
		for _, m := range mismatches {
			t.Errorf("  %s", m)
		}
		t.Error("The two static mirrors must agree — sync static/ and go-server/static/.")
	}
}
