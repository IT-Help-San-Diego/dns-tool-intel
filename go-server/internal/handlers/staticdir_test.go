// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "os"
        "path/filepath"
        "testing"
        "time"
)

func resetIntegrityCache() {
        integrityCacheMu.Lock()
        integrityCache = IntegrityData{}
        integrityCacheTime = time.Time{}
        integrityCacheMu.Unlock()
}

// The /stats integrity read must resolve through the same candidate list as
// asset serving. The old bare "static/…" path silently emptied /stats
// whenever the live tree was candidate 2 (go-server/static) — this pins the
// fix by making candidate 2 the only tree that exists.
func TestLoadIntegrityData_ResolvesStaticDirCandidates(t *testing.T) {
        resetIntegrityCache()
        t.Cleanup(resetIntegrityCache)

        origDir, err := os.Getwd()
        if err != nil {
                t.Fatal(err)
        }
        t.Cleanup(func() { os.Chdir(origDir) })

        tmp := t.TempDir()
        dataDir := filepath.Join(tmp, "go-server", "static", "data")
        if err := os.MkdirAll(dataDir, 0o755); err != nil {
                t.Fatal(err)
        }
        if err := os.WriteFile(filepath.Join(dataDir, "integrity_stats.json"), []byte(`{"events":[]}`), 0o644); err != nil {
                t.Fatal(err)
        }
        if err := os.Chdir(tmp); err != nil {
                t.Fatal(err)
        }

        got := loadIntegrityData()
        if got.SHA3Hash == "" {
                t.Error("loadIntegrityData missed go-server/static (candidate 2) — the read is not going through ResolveStaticDir")
        }
}
