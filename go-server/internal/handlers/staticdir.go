// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "log/slog"
        "os"
)

// ResolveStaticDir returns the root of the live static tree, probing the
// same cwd-relative candidates the server has always used (root static/
// wins). It is THE single source for that resolution: main's asset mounting
// and the /stats integrity read both call it, so a cwd that serves assets
// from one tree can never read stats data from another — the bare
// "static/…" path in stats.go used to bypass this and break /stats silently
// whenever candidate 2 (go-server/static) was the live tree. A total miss
// warns and returns the default: static serving 404s and /stats degrades
// empty. With templates binary-embedded a wrong cwd no longer crashes
// anything — it fails SILENTLY, which is why the systemd unit pins
// WorkingDirectory and the deploy verifies a static asset after changes.
func ResolveStaticDir() string {
        candidates := []string{
                "static",
                "go-server/static",
                "../static",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        return c
                }
        }
        slog.Warn("Static directory not found, using default")
        return "static"
}
