// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Tests for this package cover the full product source.
package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Static assets live in two trees — repo-root static/ (what the server
// actually serves) and go-server/static/ (embedded) — and they are kept in
// sync by hand. Hand-sync is a promise, not a mechanism: the served
// main.min.js once sat three months behind its source, and a copy that has
// silently stopped matching is the same defect class as a fixture encoding a
// posture vocabulary the grader cannot emit. Both are references that cannot
// be reached, and neither announces itself.
//
// This test is the mechanism. It hashes every shared file in both trees and
// fails on any pair that differs.
//
// The already-divergent pairs below are recorded rather than fixed, because
// choosing which copy wins is a judgement about each file's purpose (a
// robots.txt or manifest.json may legitimately differ between a served tree
// and an embedded one) and guessing would freeze the wrong state. The list is
// a ratchet: a NEW divergence fails immediately, and every entry removed from
// it can never come back silently. It must only ever shrink.
var knownDivergentMirrors = map[string]string{
	"css/print.min.css":                   "unreviewed drift — decide which tree is canonical, then delete this entry",
	"images/owl-signature-160.png":        "unreviewed drift",
	"images/owl-signature-240.png":        "unreviewed drift",
	"llms-full.txt":                       "unreviewed drift",
	"llms.txt":                            "unreviewed drift",
	"manifest.json":                       "may be intentional: served vs embedded tree",
	"robots.txt":                          "may be intentional: served vs embedded tree",
	"sw.js":                               "may be intentional: service worker scope differs by tree",
	"video/forgotten-domain-captions.vtt": "unreviewed drift",
}

// go-server/static/embed.go exists only to embed the tree; it has no
// counterpart in the served tree by design.
var mirrorIgnore = map[string]bool{"embed.go": true}

func mirrorRoots(t *testing.T) (string, string) {
	t.Helper()
	for _, base := range []string{filepath.Join("..", "..", ".."), "."} {
		served := filepath.Join(base, "static")
		embedded := filepath.Join(base, "go-server", "static")
		if _, err := os.Stat(served); err != nil {
			continue
		}
		if _, err := os.Stat(embedded); err != nil {
			continue
		}
		return served, embedded
	}
	t.Skip("static trees not locatable from this working directory")
	return "", ""
}

func hashTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if mirrorIgnore[rel] || strings.HasPrefix(rel, ".") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestStaticMirrorsAgree(t *testing.T) {
	servedRoot, embeddedRoot := mirrorRoots(t)
	served := hashTree(t, servedRoot)
	embedded := hashTree(t, embeddedRoot)

	var newDrift, healed []string
	for rel, servedSum := range served {
		embeddedSum, present := embedded[rel]
		if !present {
			// Present in one tree only. Not a content mismatch — reported by
			// TestStaticMirrorsHaveSameFileSet so the two failures stay
			// distinguishable.
			continue
		}
		differs := servedSum != embeddedSum
		_, known := knownDivergentMirrors[rel]
		switch {
		case differs && !known:
			newDrift = append(newDrift, rel)
		case !differs && known:
			healed = append(healed, rel)
		}
	}
	sort.Strings(newDrift)
	sort.Strings(healed)

	for _, rel := range newDrift {
		t.Errorf("static mirror drift: static/%s and go-server/static/%s differ.\n"+
			"  The served tree and the embedded tree must carry identical bytes — a copy that has\n"+
			"  silently stopped matching is a reference nobody can reach. Re-sync the file (regenerate\n"+
			"  minified output rather than hand-editing it), or, if the difference is deliberate, add it\n"+
			"  to knownDivergentMirrors WITH the reason.", rel, rel)
	}
	for _, rel := range healed {
		t.Errorf("%s is listed in knownDivergentMirrors but the two copies now MATCH — "+
			"delete the entry so the ratchet keeps its meaning (the list must only ever shrink).", rel)
	}
	if len(newDrift) == 0 && len(healed) == 0 {
		t.Logf("%d shared static files compared; %d known divergences pending review",
			len(served), len(knownDivergentMirrors))
	}
}

// A file present in only one tree is its own failure mode: the served tree can
// gain an asset the embedded tree never receives, and nothing notices until a
// deployment serving from the embedded tree 404s it.
func TestStaticMirrorsHaveSameFileSet(t *testing.T) {
	servedRoot, embeddedRoot := mirrorRoots(t)
	served := hashTree(t, servedRoot)
	embedded := hashTree(t, embeddedRoot)

	var onlyServed, onlyEmbedded []string
	for rel := range served {
		if _, ok := embedded[rel]; !ok {
			onlyServed = append(onlyServed, rel)
		}
	}
	for rel := range embedded {
		if _, ok := served[rel]; !ok {
			onlyEmbedded = append(onlyEmbedded, rel)
		}
	}
	sort.Strings(onlyServed)
	sort.Strings(onlyEmbedded)

	// Recorded, not fixed: these are all owl-semaphore image variants that
	// exist only in the served tree. Copying them blind would add weight to
	// the embedded binary for assets that may be intentionally served-only,
	// so the set is pinned and any CHANGE to it fails.
	const knownOnlyServed = 10
	if len(onlyServed) != knownOnlyServed {
		t.Errorf("files present only in static/: got %d, pinned at %d.\n  %s\n"+
			"  If this grew, an asset was added to the served tree without the embedded one.\n"+
			"  If it shrank, update the pin — the set is deliberately frozen so drift is visible.",
			len(onlyServed), knownOnlyServed, strings.Join(onlyServed, "\n  "))
	}
	if len(onlyEmbedded) != 0 {
		t.Errorf("files present only in go-server/static/: %s", strings.Join(onlyEmbedded, ", "))
	}
}
