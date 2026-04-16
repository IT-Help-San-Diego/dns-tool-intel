#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Drift guard: fails if any of the deleted handler shim files reappear in
# go-server/internal/handlers/. The handlers package was split into
# adminpkg, agentpkg, authpkg, badgepkg, contentpkg in v26.45.x — these
# names must never come back as bridge/shim files at the package root.
set -euo pipefail

DIR="go-server/internal/handlers"
FORBIDDEN=(admin.go agent.go auth.go badge.go badge_owl.go)
fail=0

for f in "${FORBIDDEN[@]}"; do
  if [[ -f "$DIR/$f" ]]; then
    echo "ERROR: forbidden shim file reappeared: $DIR/$f" >&2
    echo "       This file was deleted during the handlers package split." >&2
    echo "       Domain code belongs in the appropriate subpackage" >&2
    echo "       (adminpkg/agentpkg/authpkg/badgepkg/contentpkg)." >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  exit 1
fi

echo "handlers/ shim guard: OK (no forbidden files)"
