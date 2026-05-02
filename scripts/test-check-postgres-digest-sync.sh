#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Self-test for scripts/check-postgres-digest-sync.sh (task #115).
#
# Why this exists:
#   Task #109 added the drift guard but had no automated test of the
#   guard itself. A future refactor (tightened regex, swapped grep for
#   awk, changed exit codes) could silently break the failure path —
#   CI would keep printing "OK" forever and we'd never notice the
#   placebo. This test exercises all three branches of the guard
#   against synthetic YAML fixtures so a regression in the guard fails
#   the same PR that introduced it.
#
# Strategy:
#   The guard reads from the relative path `.github/workflows`. By
#   cd-ing into a tempdir that contains a fake `.github/workflows/`
#   tree and invoking the guard via its absolute path, we can feed it
#   arbitrary synthetic fixtures without touching the real workflow
#   files.
#
# Cases covered:
#   1. Matching   — two YAML files with identical @sha256 digests →
#                   exit 0, stdout contains "OK".
#   2. Mismatched — two YAML files with DIFFERENT @sha256 digests →
#                   exit 1, stderr names both file paths and both
#                   digests.
#   3. Empty      — a workflows dir with no Postgres references at all
#                   → exit 1, stderr contains the suspicious-default
#                   message ("no digest-pinned ... references found").
#
# This script is invoked from .github/workflows/ci.yml right after the
# drift guard itself, so any regression in the guard surfaces on the
# same PR.
set -euo pipefail

# Resolve the absolute path to the script under test BEFORE we cd
# anywhere — the guard uses a relative WORKFLOW_DIR and we need to
# invoke it from inside each fixture tempdir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${SCRIPT_DIR}/check-postgres-digest-sync.sh"

if [[ ! -x "$GUARD" ]]; then
  echo "ERROR: guard script not found or not executable: $GUARD" >&2
  exit 1
fi

# Two distinct, syntactically valid SHA-256 digests for the fixtures.
# Values are deliberately arbitrary — the guard only checks string
# equality, not registry resolvability.
DIGEST_A="sha256:1111111111111111111111111111111111111111111111111111111111111111"
DIGEST_B="sha256:2222222222222222222222222222222222222222222222222222222222222222"

PASS=0
FAIL=0

run_case() {
  # Args: <case name> <expected exit code> <pattern that must appear in combined output>
  local name="$1"
  local expected_exit="$2"
  local must_match="$3"
  local workdir="$4"

  local out exit_code
  set +e
  out=$(cd "$workdir" && bash "$GUARD" 2>&1)
  exit_code=$?
  set -e

  local ok=1
  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    ok=0
    echo "FAIL [$name]: expected exit $expected_exit, got $exit_code" >&2
  fi
  if ! grep -qE "$must_match" <<<"$out"; then
    ok=0
    echo "FAIL [$name]: output did not match pattern: $must_match" >&2
    echo "----- output -----" >&2
    echo "$out" >&2
    echo "------------------" >&2
  fi

  if [[ "$ok" -eq 1 ]]; then
    echo "PASS [$name] (exit $exit_code)"
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------
# Case 1: matching digests across two files → exit 0, "OK" in stdout.
# ---------------------------------------------------------------------
TMP_MATCH=$(mktemp -d)
trap 'rm -rf "$TMP_MATCH" "$TMP_MISMATCH" "$TMP_EMPTY"' EXIT
mkdir -p "$TMP_MATCH/.github/workflows"
cat >"$TMP_MATCH/.github/workflows/a.yml" <<EOF
services:
  postgres:
    image: mirror.gcr.io/library/postgres:16-alpine@${DIGEST_A}
EOF
cat >"$TMP_MATCH/.github/workflows/b.yml" <<EOF
services:
  postgres:
    image: mirror.gcr.io/library/postgres:16-alpine@${DIGEST_A}
EOF
run_case "matching digests" 0 "postgres digest sync: OK" "$TMP_MATCH"

# Bonus assertion for the matching case: the success message must
# include the digest (so a maintainer reading green CI logs can
# confirm WHICH digest is currently the canonical one).
match_out=$(cd "$TMP_MATCH" && bash "$GUARD" 2>&1)
if grep -q "$DIGEST_A" <<<"$match_out"; then
  echo "PASS [matching digests prints digest]"
  PASS=$((PASS + 1))
else
  echo "FAIL [matching digests prints digest]: success message did not include the canonical digest" >&2
  echo "$match_out" >&2
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------
# Case 2: mismatched digests → exit 1, both file paths and both
# digests appear in stderr.
# ---------------------------------------------------------------------
TMP_MISMATCH=$(mktemp -d)
mkdir -p "$TMP_MISMATCH/.github/workflows"
cat >"$TMP_MISMATCH/.github/workflows/ci.yml" <<EOF
services:
  postgres:
    image: mirror.gcr.io/library/postgres:16-alpine@${DIGEST_A}
EOF
cat >"$TMP_MISMATCH/.github/workflows/cross-browser-tests.yml" <<EOF
services:
  postgres:
    image: mirror.gcr.io/library/postgres:16-alpine@${DIGEST_B}
EOF
run_case "mismatched digests exits 1" 1 "drift detected" "$TMP_MISMATCH"

# Granular assertions: the error must name BOTH files AND BOTH
# digests (anything less and a maintainer can't tell what to fix).
mismatch_out=$(cd "$TMP_MISMATCH" && bash "$GUARD" 2>&1 || true)
for needle in "ci.yml" "cross-browser-tests.yml" "$DIGEST_A" "$DIGEST_B"; do
  if grep -q "$needle" <<<"$mismatch_out"; then
    echo "PASS [mismatch error names: $needle]"
    PASS=$((PASS + 1))
  else
    echo "FAIL [mismatch error names: $needle]: not present in error output" >&2
    echo "$mismatch_out" >&2
    FAIL=$((FAIL + 1))
  fi
done

# ---------------------------------------------------------------------
# Case 3: empty / no Postgres references → exit 1 with the
# suspicious-default message.
# ---------------------------------------------------------------------
TMP_EMPTY=$(mktemp -d)
mkdir -p "$TMP_EMPTY/.github/workflows"
cat >"$TMP_EMPTY/.github/workflows/unrelated.yml" <<'EOF'
name: Unrelated workflow
on: [push]
jobs:
  noop:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no postgres here"
EOF
run_case "no postgres references exits 1" 1 "no digest-pinned mirror.gcr.io/library/postgres references found" "$TMP_EMPTY"

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo ""
echo "test-check-postgres-digest-sync.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
