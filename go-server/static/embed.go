// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
//
// Package static embeds binary-critical static assets directly into the Go
// binary so they ship atomically with the build. This eliminates a class of
// deployment-filesystem races where /docs/*.pdf were observed being served
// truncated or zero-length in production despite intact bytes on disk and in
// git (HEAD content-length correct, GET body short — see corpus regression).
//
// Only the corpus PDFs are embedded (~17 MB). Everything else under static/
// continues to be served from disk via findStaticDir() / c.File.
package static

import "embed"

// DocsPDFs contains every *.pdf in static/docs at build time. Filenames must
// be referenced as "docs/<name>.pdf" when reading from the FS. The build will
// fail if any file in the glob is missing, so the binary cannot ship without
// the full corpus.
//
//go:embed docs/*.pdf
var DocsPDFs embed.FS
