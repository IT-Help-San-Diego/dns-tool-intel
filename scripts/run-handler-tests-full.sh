#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Run the full handlers/ test suite as a series of separately-compiled
# tag passes so each compile fits within standard CI memory budgets.
# Without this split, the combined ~41K-line handlers test corpus has
# OOM-killed the Go compiler at ~5 GB available RAM (see task #90).
#
# Each pass compiles its own test binary, so peak per-process memory
# stays bounded by the size of one tag bucket plus the package's
# production code (~12K lines).
#
# Usage:
#   bash scripts/run-handler-tests-full.sh           # all passes
#   bash scripts/run-handler-tests-full.sh -short    # forwarded to go test
#
# Pass flags: any args are forwarded verbatim to every `go test` invocation
# (e.g. -short, -count=1, -timeout=120s, -v).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PKG=./go-server/internal/handlers/
EXTRA_ARGS=("$@")

# Default to safe go test flags if none supplied.
if [ ${#EXTRA_ARGS[@]} -eq 0 ]; then
  EXTRA_ARGS=(-short -count=1 -timeout=300s)
fi

# Tag passes in order from largest impact to smallest.
# Empty string = the default untagged pass.
TAG_PASSES=(
  ""
  "bigtests"
  "coverage"
  "scientific"
  # dbtest and integration are excluded by default — they require a
  # live PostgreSQL and a real network respectively. CI lanes that
  # provide those services should override this list via the
  # HANDLER_TAG_PASSES env var (see below) so the per-tag memory
  # contract is preserved.
)

# HANDLER_TAG_PASSES — space-separated override of TAG_PASSES for the
# current invocation. Use the literal token "default" to request the
# untagged pass. CI lanes with a Postgres service and network egress
# set this to "dbtest integration" to run only the buckets that the
# default lane intentionally skips, without recompiling the larger
# coverage/bigtests buckets a second time.
#
# Example:
#   HANDLER_TAG_PASSES="dbtest integration" \
#     bash scripts/run-handler-tests-full.sh -short -count=1 -timeout=300s
if [ -n "${HANDLER_TAG_PASSES:-}" ]; then
  # shellcheck disable=SC2206  # intentional word-splitting on whitespace
  override=(${HANDLER_TAG_PASSES})
  TAG_PASSES=()
  for t in "${override[@]}"; do
    if [ "$t" = "default" ]; then
      TAG_PASSES+=("")
    else
      TAG_PASSES+=("$t")
    fi
  done
fi

failed=0
for tags in "${TAG_PASSES[@]}"; do
  label="${tags:-default}"
  echo
  echo "========================================"
  echo "Pass: ${label}"
  echo "========================================"
  if [ -z "$tags" ]; then
    if ! go test "${EXTRA_ARGS[@]}" "$PKG"; then
      echo "FAIL: ${label}" >&2
      failed=1
    fi
  else
    if ! go test -tags "$tags" "${EXTRA_ARGS[@]}" "$PKG"; then
      echo "FAIL: ${label}" >&2
      failed=1
    fi
  fi
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "One or more handler test passes failed." >&2
  exit 1
fi

echo
echo "All handler test passes succeeded."
