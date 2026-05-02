#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Drift guard (task #109): the CI pipeline pins the Postgres service image
# by SHA-256 digest in MULTIPLE workflow files so unit/integration tests
# (.github/workflows/ci.yml — the `handler-tests-db-integration` job) and
# end-to-end browser tests (.github/workflows/cross-browser-tests.yml) all
# run against bit-for-bit identical Postgres bytes. The whole point of
# pinning by digest in both files is to guarantee that drift in one lane
# cannot cause silent divergence from another.
#
# But two files can drift independently: a future Postgres patch bump may
# update the digest in ci.yml while the human forgets to update
# cross-browser-tests.yml (or vice versa). The in-file comments politely
# ask humans to update both, but politeness is not a control. This script
# is the control.
#
# What it does:
#   1. Scans every .github/workflows/*.yml file for any reference to
#      `mirror.gcr.io/library/postgres:` (the prefix is intentionally
#      lenient so a future workflow that pins a different tag — e.g.
#      `:17-alpine` after a major version bump — is still picked up).
#   2. Extracts the @sha256:... digest from each occurrence.
#   3. Fails with a clear error message naming all file paths and all
#      digests if the digests are not all identical.
#
# Bonus / anti-drift property: because the script DISCOVERS the workflow
# files instead of taking a hard-coded list, any future workflow that
# adds a `mirror.gcr.io/library/postgres:` reference is automatically
# included in the comparison set. There is no "remember to update the
# script" step.
#
# Lines without an @sha256:... suffix (e.g. the comments above the
# `image:` line that mention `mirror.gcr.io/library/postgres:16-alpine`
# in human prose) are deliberately ignored — only digest-pinned
# references participate in the equality check.
set -euo pipefail

WORKFLOW_DIR=".github/workflows"

if [[ ! -d "$WORKFLOW_DIR" ]]; then
  echo "ERROR: workflow directory not found: $WORKFLOW_DIR" >&2
  exit 1
fi

# Collect "<file>:<digest>" pairs for every digest-pinned occurrence.
# Pattern: mirror.gcr.io/library/postgres:<tag>@sha256:<64 hex chars>
# The grep -E pattern requires the @sha256: suffix so prose mentions in
# comments (which lack a digest) do not get pulled in.
mapfile -t matches < <(
  grep -REn \
    'mirror\.gcr\.io/library/postgres:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' \
    "$WORKFLOW_DIR" 2>/dev/null \
    | sort -u \
    || true
)

if [[ ${#matches[@]} -eq 0 ]]; then
  # No digest-pinned references at all. This is suspicious — task #102
  # and #104 established digest pinning as a hard requirement — but the
  # safe default is to fail loudly rather than silently pass.
  echo "ERROR: no digest-pinned mirror.gcr.io/library/postgres references found in $WORKFLOW_DIR/." >&2
  echo "       Tasks #102 and #104 established digest pinning as the canonical control." >&2
  echo "       If you intentionally removed all Postgres CI services, also remove this guard." >&2
  exit 1
fi

# Extract just the digest portion (the 64-char hex after @sha256:) from
# each match so we can compare them. Keep the file:line:full-line for the
# error message.
declare -a files_lines
declare -a digests

for line in "${matches[@]}"; do
  # `grep -REn` emits "<path>:<lineno>:<full line>".
  digest=$(printf '%s\n' "$line" | grep -oE '@sha256:[0-9a-f]{64}' | head -n1)
  files_lines+=("$line")
  digests+=("$digest")
done

# Are all digests identical?
unique_digests=$(printf '%s\n' "${digests[@]}" | sort -u)
unique_count=$(printf '%s\n' "$unique_digests" | wc -l | tr -d ' ')

if [[ "$unique_count" -eq 1 ]]; then
  count="${#digests[@]}"
  echo "postgres digest sync: OK ($count digest-pinned reference(s), all matching $unique_digests)"
  exit 0
fi

# Drift detected — emit a maximally helpful failure so the fix is obvious.
{
  echo "ERROR: Postgres CI image digest drift detected across workflow files."
  echo ""
  echo "Multiple .github/workflows/*.yml files reference"
  echo "mirror.gcr.io/library/postgres:... but with DIFFERENT @sha256 digests."
  echo "The whole point of digest pinning (tasks #102 and #104) is that every"
  echo "CI lane tests against bit-for-bit identical Postgres bytes — divergence"
  echo "here means handler tests and end-to-end browser tests are no longer"
  echo "running against the same Postgres build."
  echo ""
  echo "Found ${#digests[@]} digest-pinned reference(s), $unique_count distinct digest(s):"
  echo ""
  for line in "${files_lines[@]}"; do
    echo "  $line"
  done
  echo ""
  echo "To fix: pick the intended digest (typically the most recent deliberate"
  echo "Postgres patch bump — verify with"
  echo "'docker buildx imagetools inspect mirror.gcr.io/library/postgres:16-alpine')"
  echo "and update every file above to use the SAME @sha256:... suffix."
} >&2
exit 1
