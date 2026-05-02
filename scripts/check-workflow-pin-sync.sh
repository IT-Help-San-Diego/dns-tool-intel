#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Drift guard (task #114): generalization of the postgres-digest-sync
# pattern (task #109, scripts/check-postgres-digest-sync.sh).
#
# Why this exists:
# Several CI version pins are deliberately duplicated across multiple
# workflow files because each workflow needs to install the same
# toolchain. The Go compiler version is the canonical case:
#
#   .github/workflows/ci.yml                  (build job)
#       go-version: '1.25.9'
#   .github/workflows/ci.yml                  (handler-tests-db-integration)
#       go-version: '1.25.9'
#   .github/workflows/cross-browser-tests.yml (E2E lane)
#       go-version: '1.25.9'
#
# If a future Go bump updates one of those occurrences but the human
# forgets the others, the build job and the integration job (or the
# E2E lane) will start compiling against different Go releases. That is
# exactly the kind of silent divergence task #109 fixed for the
# Postgres service container — and the same control belongs here.
#
# What this script does:
#   1. Takes a YAML key as its single argument (e.g. `go-version`).
#   2. Scans every active .github/workflows/*.yml file (the `*.yml`
#      glob deliberately excludes archived `*.yml.disabled` files).
#   3. Extracts every literal `<key>: <value>` pin (anchored on the
#      colon so unrelated keys like `go-version-file:` do NOT match,
#      and prose mentions in comments do NOT match).
#   4. Fails with a clear, file:line-cited error message if the values
#      are not all identical.
#
# Anti-drift property: like the Postgres guard, this script DISCOVERS
# the workflow files instead of taking a hard-coded list. Adding a
# fourth workflow that pins the same key is automatically included in
# the comparison set — there is no "remember to update the script"
# step.
#
# Future use cases this same script handles without modification:
#   - bash scripts/check-workflow-pin-sync.sh node-version
#       (only meaningful once Node is intentionally shared across
#       workflows; today dependency-audit pins 22 and cross-browser
#       pins 20 by design, so do NOT wire that up yet)
#   - bash scripts/check-workflow-pin-sync.sh <other-key>
#       for any future shared pin.
#
# Usage:
#   bash scripts/check-workflow-pin-sync.sh <yaml-key>
#
# Exit codes:
#   0  — all pins agree (or the key has only one pin)
#   1  — drift detected, or no pins of this key found at all
#   2  — usage error (missing argument)
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <yaml-key>" >&2
  echo "Example: $0 go-version" >&2
  exit 2
fi

KEY="$1"
WORKFLOW_DIR=".github/workflows"

if [[ ! -d "$WORKFLOW_DIR" ]]; then
  echo "ERROR: workflow directory not found: $WORKFLOW_DIR" >&2
  exit 1
fi

# Find every line of the form `<leading-ws><KEY>:<ws><value...>` in
# active workflow files. The leading-whitespace + KEY + literal `:`
# anchor is what filters out:
#   - `go-version-file: go.mod`     (different key, no colon after KEY)
#   - `# go-version was bumped...`  (comment prose, no colon at start)
#   - `      foo-go-version: '1.0'` (substring match in another key)
# The `--include` flags deliberately match both `*.yml` and `*.yaml`
# (today this repo standardizes on `.yml`, but GitHub Actions accepts
# either, so a future workflow named `*.yaml` is still auto-included
# in the comparison set). Both globs deliberately exclude archived
# `*.yml.disabled` files, which would otherwise pollute the result
# with stale values that nobody is maintaining.
#
# `|| true` keeps the pipeline alive when grep matches zero lines so
# the explicit zero-match check below is the failure path, not a
# silent shell exit under `set -e`.
mapfile -t matches < <(
  grep -REn \
    "^[[:space:]]*${KEY}:[[:space:]]" \
    --include='*.yml' \
    --include='*.yaml' \
    "$WORKFLOW_DIR" 2>/dev/null \
    | sort -u \
    || true
)

if [[ ${#matches[@]} -eq 0 ]]; then
  echo "ERROR: no '${KEY}:' pins found in ${WORKFLOW_DIR}/*.{yml,yaml}." >&2
  echo "       Either the key was renamed across all workflows or every" >&2
  echo "       workflow stopped pinning it. If this guard is no longer" >&2
  echo "       relevant, remove the corresponding step in ci.yml." >&2
  exit 1
fi

# Parse each match into its raw file:line context (kept for the error
# message) and the bare value (used for the equality check).
declare -a files_lines=()
declare -a values=()

for line in "${matches[@]}"; do
  # `grep -REn` emits "<path>:<lineno>:<full line>". Strip the first
  # two colon-delimited fields to recover the line content. Workflow
  # paths under .github/workflows/*.yml never contain colons, so this
  # is unambiguous.
  content="${line#*:}"
  content="${content#*:}"
  # Strip leading whitespace.
  content="${content#"${content%%[![:space:]]*}"}"
  # Strip the literal `KEY:` prefix.
  content="${content#"${KEY}":}"
  # Strip leading whitespace after the colon.
  content="${content#"${content%%[![:space:]]*}"}"
  # The value may be single-quoted, double-quoted, or unquoted. In all
  # three cases we want just the bare value (no quotes, no trailing
  # comment, no trailing whitespace) so equality is meaningful.
  if [[ "$content" =~ ^\'([^\']*)\' ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$content" =~ ^\"([^\"]*)\" ]]; then
    value="${BASH_REMATCH[1]}"
  else
    # Unquoted: take everything up to the first whitespace or `#`
    # (start of YAML comment).
    value="${content%%[[:space:]#]*}"
  fi
  files_lines+=("$line")
  values+=("$value")
done

unique_values=$(printf '%s\n' "${values[@]}" | sort -u)
unique_count=$(printf '%s\n' "$unique_values" | wc -l | tr -d ' ')

if [[ "$unique_count" -eq 1 ]]; then
  count="${#values[@]}"
  echo "${KEY} sync: OK (${count} pin(s), all matching '${unique_values}')"
  exit 0
fi

# Drift detected — emit a maximally helpful failure so the fix is
# obvious. Cite every offending file:line and every distinct value.
{
  echo "ERROR: '${KEY}' drift detected across workflow files."
  echo ""
  echo "Multiple .github/workflows/*.yml files set '${KEY}:' but with"
  echo "DIFFERENT values. The whole point of pinning the same toolchain"
  echo "version in multiple lanes is that every CI job compiles/runs"
  echo "against the same release — divergence here means jobs that are"
  echo "supposed to be testing the same code are silently testing"
  echo "against different toolchains."
  echo ""
  echo "Found ${#values[@]} pin(s), ${unique_count} distinct value(s):"
  echo ""
  for line in "${files_lines[@]}"; do
    echo "  ${line}"
  done
  echo ""
  echo "Distinct values:"
  while IFS= read -r v; do
    echo "  '${v}'"
  done <<< "$unique_values"
  echo ""
  echo "To fix: pick the intended value (typically the most recent"
  echo "deliberate bump) and update every file above to use the same"
  echo "'${KEY}:' value."
} >&2
exit 1
