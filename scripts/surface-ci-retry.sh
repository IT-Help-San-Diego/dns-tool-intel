#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny plumbing
#
# Surface a "saved by silent retry" signal for the dbtest + integration
# handler-test lane (task #105, hardened by task #111).
#
# Why this is its own script (not inline in ci.yml):
#   The original implementation lived as an inline `run: |` block in
#   .github/workflows/ci.yml. That meant the only way to verify the
#   marker/warning logic actually fires under the right conditions was
#   to push to CI and induce a real flake — not realistic. Extracting
#   to a script lets a unit test (scripts/surface-ci-retry.test.sh)
#   exercise every branch in milliseconds, so a future edit that
#   silently breaks the marker output (renamed env var, busted guard,
#   typo in the prefix) fails fast in CI instead of going unnoticed
#   until the next real flake.
#
# Inputs (env vars, set by the caller / the workflow step):
#   TOTAL_ATTEMPTS  — total_attempts output from nick-fields/retry@v3.
#                     Defaults to "1" if unset/empty: a missing value
#                     means we stay quiet rather than emit a false
#                     flake signal.
#   STEP_OUTCOME    — outcome of the retry step ("success" | "failure"
#                     | "cancelled" | ...). Defaults to "unknown".
#   GITHUB_STEP_SUMMARY — path to the run-summary markdown file that
#                     GitHub Actions makes available. When unset (e.g.
#                     local invocation, unit test) the summary block
#                     is skipped but the ::warning:: still goes to
#                     stdout so the behaviour is observable.
#
# Behaviour:
#   - Always prints a single status line to stdout for the job log.
#   - When outcome == "success" AND attempts > 1:
#       * Echoes the bare marker `DBTEST_INTEGRATION_RETRY_USED
#         attempts=N` to stdout so it lands in the raw job log. Step-
#         summary content is not exposed by the
#         /actions/jobs/{id}/logs endpoint, so without this echo the
#         silent-retry-trend aggregator added in task #110 cannot see
#         the marker. Same prefix is written to both surfaces so a
#         single grep target works for human run-page reading AND for
#         log-based tooling.
#       * Appends a markdown summary block (including the same marker
#         in an HTML comment) to $GITHUB_STEP_SUMMARY if that path is
#         writable.
#       * Emits a `::warning::` workflow annotation on stdout.
#   - Otherwise: stays silent. A retried-and-still-failed step is
#     already loud (job is red), so we don't double-signal it here.
#
# Exit code: always 0. This script is observability, not a gate.
#
# DO NOT change the marker prefix `DBTEST_INTEGRATION_RETRY_USED`
# without updating downstream tooling that scans run summaries for
# trend data, AND updating scripts/surface-ci-retry.test.sh.

set -euo pipefail

attempts="${TOTAL_ATTEMPTS:-1}"
outcome="${STEP_OUTCOME:-unknown}"

echo "dbtest+integration lane: total_attempts=${attempts} outcome=${outcome}"

# Guard: only surface when retry was both used (attempts > 1) AND the
# step ultimately succeeded. The `-n` check defends against the env
# var being explicitly set to the empty string.
if [ "${outcome}" != "success" ]; then
  exit 0
fi
if [ -z "${attempts}" ] || [ "${attempts}" = "1" ]; then
  exit 0
fi

# Stable grep marker — DO NOT change without updating
# scripts/surface-ci-retry.test.sh and any downstream trend tooling.
marker="DBTEST_INTEGRATION_RETRY_USED attempts=${attempts}"

# Echo the marker to stdout so it lands in the raw job log, not just
# in $GITHUB_STEP_SUMMARY. The silent-retry-trend aggregator added in
# task #110 reads from /actions/jobs/{id}/logs which does NOT include
# step-summary content, so removing this echo would silently break
# the monthly trend report. Tested in scripts/surface-ci-retry.test.sh.
echo "${marker}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## ⚠️ dbtest + integration lane saved by automatic retry"
    echo ""
    echo "The \`Run dbtest + integration handler passes\` step needed **${attempts} attempts** to pass."
    echo ""
    echo "This is the self-healing path added in task #103 working as designed — but a sustained increase in retry frequency indicates the underlying infra (mirror.gcr.io pulls, Postgres service startup, runner CPU contention) is degrading. If you see this annotation appearing on most runs, investigate before both attempts start failing."
    echo ""
    echo "<!-- ${marker} -->"
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo "::warning title=Silent CI retry used::dbtest + integration lane passed on attempt ${attempts}/2 (task #105). Job is green but infra flakiness is creeping up — see job summary."
