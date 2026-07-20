#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Lockstep guard: build.sh GOTOOLCHAIN vs workflow go-version pins.
#
# Why this exists:
# scripts/check-workflow-pin-sync.sh only scans .github/workflows/*.yml,
# so it structurally cannot see build.sh. But build.sh exports its OWN
# toolchain literal (`export GOTOOLCHAIN=go1.25.X`) which overrides
# whatever setup-go installed — release.yml's "Build release binary"
# step and the Replit dev/deploy builds all run `bash build.sh`. During
# the GO-2026-5856 bump this literal was missed while all five workflow
# pins were updated: the dependency-audit lane went green (it scans
# under setup-go's toolchain directly) while every actually-shipped
# binary kept compiling against the vulnerable stdlib. A green gate over
# a still-vulnerable artifact is exactly the silent divergence the
# pin-sync family of guards exists to prevent.
#
# What this script does:
#   1. Extracts the `export GOTOOLCHAIN=goX.Y.Z` literal from build.sh.
#   2. Extracts every literal `go-version:` pin from active workflow
#      files (same anchoring rules as check-workflow-pin-sync.sh:
#      `*.yml`/`*.yaml` only, `.disabled` files excluded, the
#      `go-version-file:` key does NOT match).
#   3. Fails with file:line-cited output unless build.sh's version and
#      every workflow pin are all identical.
#
# Usage:
#   bash scripts/check-buildsh-toolchain-sync.sh
#
# Exit codes:
#   0 — build.sh GOTOOLCHAIN matches every workflow go-version pin
#   1 — drift detected, or either side could not be parsed
set -euo pipefail

BUILD_SH="build.sh"
WORKFLOW_DIR=".github/workflows"

if [[ ! -f "$BUILD_SH" ]]; then
  echo "ERROR: $BUILD_SH not found (run from repo root)." >&2
  exit 1
fi

# --- build.sh side ----------------------------------------------------
# Anchor on `export GOTOOLCHAIN=go` at line start so comment prose
# (e.g. "GOTOOLCHAIN=go1.25.X" in the bump instructions) never matches.
mapfile -t buildsh_matches < <(
  grep -En '^export GOTOOLCHAIN=go[0-9]' "$BUILD_SH" || true
)

if [[ ${#buildsh_matches[@]} -ne 1 ]]; then
  echo "ERROR: expected exactly one 'export GOTOOLCHAIN=go<ver>' line in ${BUILD_SH}," >&2
  echo "       found ${#buildsh_matches[@]}. The lockstep guard cannot compare." >&2
  printf '  %s\n' "${buildsh_matches[@]}" >&2
  exit 1
fi

buildsh_line="${buildsh_matches[0]}"
buildsh_version="${buildsh_line##*GOTOOLCHAIN=go}"
buildsh_version="${buildsh_version%%[[:space:]#]*}"

# --- workflow side ----------------------------------------------------
mapfile -t wf_matches < <(
  grep -REn \
    '^[[:space:]]*go-version:[[:space:]]' \
    --include='*.yml' \
    --include='*.yaml' \
    "$WORKFLOW_DIR" 2>/dev/null \
    | sort -u \
    || true
)

if [[ ${#wf_matches[@]} -eq 0 ]]; then
  echo "ERROR: no 'go-version:' pins found in ${WORKFLOW_DIR}/*.{yml,yaml}." >&2
  exit 1
fi

drift=0
for line in "${wf_matches[@]}"; do
  content="${line#*:}"
  content="${content#*:}"
  content="${content#"${content%%[![:space:]]*}"}"
  content="${content#go-version:}"
  content="${content#"${content%%[![:space:]]*}"}"
  if [[ "$content" =~ ^\'([^\']*)\' ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$content" =~ ^\"([^\"]*)\" ]]; then
    value="${BASH_REMATCH[1]}"
  else
    value="${content%%[[:space:]#]*}"
  fi
  if [[ "$value" != "$buildsh_version" ]]; then
    if [[ $drift -eq 0 ]]; then
      echo "ERROR: build.sh GOTOOLCHAIN / workflow go-version drift detected." >&2
      echo "" >&2
      echo "  ${BUILD_SH}: export GOTOOLCHAIN=go${buildsh_version}   (${buildsh_line%%:*}:$(echo "$buildsh_line" | cut -d: -f2))" >&2
      echo "" >&2
      echo "Workflow pins that disagree:" >&2
    fi
    echo "  ${line}" >&2
    drift=1
  fi
done

if [[ $drift -ne 0 ]]; then
  {
    echo ""
    echo "The binary that actually ships (release.yml → bash build.sh --deploy,"
    echo "Replit dev/deploy workflows) compiles with build.sh's GOTOOLCHAIN, NOT"
    echo "with setup-go's go-version. If these diverge, security gates can go"
    echo "green while the shipped artifact still embeds the old stdlib."
    echo ""
    echo "To fix: on a Go bump, update build.sh's 'export GOTOOLCHAIN=go<ver>'"
    echo "AND every workflow 'go-version:' literal together, then reverify:"
    echo "  GOSUMDB=sum.golang.org GOTOOLCHAIN=go<ver> govulncheck ./go-server/..."
  } >&2
  exit 1
fi

echo "buildsh-toolchain sync: OK (build.sh go${buildsh_version} matches ${#wf_matches[@]} workflow pin(s))"
exit 0
