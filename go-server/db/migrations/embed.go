// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny plumbing

// Package migrations carries the SQL migration chain inside the binary.
//
// The chain used to be read from disk at a path relative to the process working
// directory ("go-server/db/migrations"), which meant the Dockerfile had to copy
// the directory into the image and the server had to be started from the repo
// root or it would silently find nothing. Embedding removes both constraints:
// `dns-tool-server` migrates correctly from any working directory, and the
// migrations that ship are exactly the ones that were compiled and checksummed.
//
// This file lives beside the .sql it embeds because go:embed cannot reach
// outside its own package directory. Keeping the SQL here rather than moving it
// under internal/ also keeps every existing docs and script reference to
// go-server/db/migrations/ valid.
package migrations

import "embed"

// FS holds every migration in the chain, applied in ascending version order by
// go-server/internal/db.Migrate.
//
//go:embed *.sql
var FS embed.FS
