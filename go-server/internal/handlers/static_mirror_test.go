// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing
package handlers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mirrorOneSidedAllowed lists files (by path relative to the mirror root)
// permitted to exist in only one of the two static trees. Everything else
// must exist in BOTH trees with identical bytes.
var mirrorOneSidedAllowed = map[string]bool{
	"embed.go": true, // go:embed shim; a Go source file, not a served asset
}

// TestStaticMirrorSync fails when the static/ and go-server/static/ trees
// disagree: a file whose bytes differ between them, or a file present in only
// one tree (unless allowlisted above). These two directories are mirrors: the
// server tries static/ first (findStaticDir), then go-server/static/. A file
// that differs between them serves different content depending on which
// directory the working directory happens to be — the same class as the
// stale main.min.js that sat three months behind its source.
//
// Every regular file is compared, regardless of extension. An earlier version
// of this test filtered to .txt/.xml/.json/.ico/.svg and skipped files missing
// from either tree; behind that filter, print.min.css, sw.js, two owl PNGs,
// and a captions .vtt drifted for weeks undetected (synced 2026-08-01).
// Dotfiles (.DS_Store and friends) are skipped as filesystem noise.
func TestStaticMirrorSync(t *testing.T) {
	dirs := []struct {
		name string
		path string
	}{
		{"static", "../../../static"},
		{"go-server/static", "../../static"},
	}

	seen := map[string]bool{}
	var problems []string

	for _, d := range dirs {
		err := filepath.Walk(d.path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") {
				if info.IsDir() && base != "." && base != ".." {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
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
			var sibling, siblingName string
			for _, other := range dirs {
				if other.path != d.path {
					sibling = filepath.Join(other.path, rel)
					siblingName = other.name
				}
			}

			siblingInfo, statErr := os.Stat(sibling)
			if statErr != nil || siblingInfo.IsDir() {
				if !mirrorOneSidedAllowed[filepath.ToSlash(rel)] {
					problems = append(problems, fmt.Sprintf(
						"%s exists in %s but not in %s", rel, d.name, siblingName,
					))
				}
				return nil
			}

			a, errA := os.ReadFile(path)
			if errA != nil {
				return errA
			}
			b, errB := os.ReadFile(sibling)
			if errB != nil {
				return errB
			}

			hashA := sha256.Sum256(a)
			hashB := sha256.Sum256(b)
			if hashA != hashB {
				problems = append(problems, fmt.Sprintf(
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

	if len(problems) > 0 {
		t.Errorf("static mirror divergence detected (%d file(s)):", len(problems))
		for _, p := range problems {
			t.Errorf("  %s", p)
		}
		t.Error("The two static mirrors must agree — sync static/ and go-server/static/.")
	}
}
