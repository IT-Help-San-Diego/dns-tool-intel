// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// Package templates embeds every HTML template into the Go binary so the
// server's most boot-critical resource ships atomically with the build —
// there is no state in which the deployed binary and its templates disagree,
// and no working directory from which the binary cannot find them. Before
// this, templates were the ONLY fatal cwd-relative dependency (a wrong-cwd
// start meant os.Exit(1) in a systemd crash-loop); static assets remain on
// disk deliberately (73 MB, and the mirror-sync must land first — see the
// deploy README's phase notes).
//
// This file lives beside the .html it embeds because go:embed cannot reach
// sibling directories (same constraint as db/migrations/embed.go and
// static/embed.go).
package templates

import "embed"

// Files contains every *.html in go-server/templates at build time. The
// build fails if the glob matches nothing, so the binary cannot ship
// template-less; a template syntax error still surfaces at parse time, which
// TestParseEmbeddedTemplates pins at test time rather than first boot.
//
//go:embed *.html
var Files embed.FS
