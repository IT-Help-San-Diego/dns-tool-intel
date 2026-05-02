#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny plumbing
#
# Unit tests for scripts/surface-ci-retry.sh (task #111).
#
# Purpose: catch a future edit to the silent-retry surfacing logic
# that silently breaks the marker / warning output. Without these
# tests the only signal that the snippet stopped working is the
# absence of an annotation that, by definition, only appears on
# rare flake — i.e. nobody would notice for weeks.
#
# Run locally:
#   bash scripts/surface-ci-retry.test.sh
#
# Wired into CI by the "Unit-test the silent-retry surfacing script"
# step in .github/workflows/ci.yml. Exits non-zero on any failure so
# CI fails fast.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/surface-ci-retry.sh"

if [ ! -x "${TARGET}" ] && [ ! -r "${TARGET}" ]; then
  echo "FAIL: ${TARGET} not found"
  exit 1
fi

# Stable marker prefix that downstream trend tooling greps for. If a
# future edit changes this in surface-ci-retry.sh, the tests below
# fail and force the author to also update the downstream consumers.
MARKER_PREFIX="DBTEST_INTEGRATION_RETRY_USED"
WARNING_TITLE="Silent CI retry used"

PASS=0
FAIL=0
FAILED_NAMES=()

# run_case <name> <attempts> <outcome> <use_summary: 0|1>
# Sets globals: STDOUT, SUMMARY (file contents), EXIT_CODE
run_case() {
  local name="$1" attempts="$2" outcome="$3" use_summary="$4"
  local tmp_summary=""
  local stdout_file
  stdout_file="$(mktemp)"

  local -a env_args=()
  env_args+=("TOTAL_ATTEMPTS=${attempts}")
  env_args+=("STEP_OUTCOME=${outcome}")
  if [ "${use_summary}" = "1" ]; then
    tmp_summary="$(mktemp)"
    env_args+=("GITHUB_STEP_SUMMARY=${tmp_summary}")
  else
    # Explicitly unset to simulate non-Actions execution.
    env_args+=("GITHUB_STEP_SUMMARY=")
  fi

  set +e
  env -i PATH="$PATH" "${env_args[@]}" bash "${TARGET}" >"${stdout_file}" 2>&1
  EXIT_CODE=$?
  set -e

  STDOUT="$(cat "${stdout_file}")"
  rm -f "${stdout_file}"
  if [ -n "${tmp_summary}" ] && [ -f "${tmp_summary}" ]; then
    SUMMARY="$(cat "${tmp_summary}")"
    rm -f "${tmp_summary}"
  else
    SUMMARY=""
  fi
  CASE_NAME="${name}"
}

# assert_contains <haystack-var-name> <needle> <description>
assert_contains() {
  local var_name="$1" needle="$2" desc="$3"
  local hay="${!var_name}"
  if [[ "${hay}" == *"${needle}"* ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: ${desc}"
  else
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("${CASE_NAME}: ${desc}")
    echo "  FAIL: ${desc}"
    echo "    expected to find: ${needle}"
    echo "    in ${var_name}: ${hay}"
  fi
}

assert_not_contains() {
  local var_name="$1" needle="$2" desc="$3"
  local hay="${!var_name}"
  if [[ "${hay}" != *"${needle}"* ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: ${desc}"
  else
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("${CASE_NAME}: ${desc}")
    echo "  FAIL: ${desc}"
    echo "    expected NOT to find: ${needle}"
    echo "    in ${var_name}: ${hay}"
  fi
}

assert_equals() {
  local actual="$1" expected="$2" desc="$3"
  if [ "${actual}" = "${expected}" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: ${desc}"
  else
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("${CASE_NAME}: ${desc}")
    echo "  FAIL: ${desc} (expected '${expected}', got '${actual}')"
  fi
}

# ----------------------------------------------------------------------
# Case 1: success on attempt 2 — the headline scenario. Marker MUST be
# written to the summary file, ::warning:: MUST be emitted, exit 0.
# ----------------------------------------------------------------------
echo "Case: success after retry (attempts=2, outcome=success)"
run_case "success-after-retry" "2" "success" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0"
assert_contains STDOUT "total_attempts=2 outcome=success" "logs the status line"
assert_contains STDOUT "::warning title=${WARNING_TITLE}" "emits ::warning:: annotation"
assert_contains STDOUT "attempt 2/2" "warning includes attempt count"
# Marker MUST appear on stdout (not only in the step summary) so the
# silent-retry-trend aggregator added in task #110 — which reads
# /actions/jobs/{id}/logs and does NOT see step-summary content — can
# scrape it. Removing this echo would silently break the trend report.
assert_contains STDOUT "${MARKER_PREFIX} attempts=2" "marker echoed to stdout for log-based aggregator (task #110)"
assert_contains SUMMARY "${MARKER_PREFIX} attempts=2" "summary contains stable grep marker"
assert_contains SUMMARY "saved by automatic retry" "summary contains human-readable header"

# ----------------------------------------------------------------------
# Case 2: success on attempt 3 — the marker must reflect the actual
# attempt count, not a hardcoded "2".
# ----------------------------------------------------------------------
echo "Case: success after multiple retries (attempts=3, outcome=success)"
run_case "success-after-multiple-retries" "3" "success" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0"
assert_contains STDOUT "${MARKER_PREFIX} attempts=3" "stdout marker reflects actual attempt count"
assert_contains SUMMARY "${MARKER_PREFIX} attempts=3" "summary marker reflects actual attempt count"
assert_contains STDOUT "attempt 3/2" "warning includes actual attempt count"

# ----------------------------------------------------------------------
# Case 3: success on attempt 1 — the happy path. MUST stay completely
# silent (no marker, no warning), otherwise every green run would emit
# a false flake signal.
# ----------------------------------------------------------------------
echo "Case: clean success (attempts=1, outcome=success)"
run_case "clean-success" "1" "success" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0"
assert_contains STDOUT "total_attempts=1 outcome=success" "logs the status line"
assert_not_contains STDOUT "::warning" "no warning annotation"
assert_not_contains STDOUT "${MARKER_PREFIX}" "no marker on stdout"
assert_not_contains SUMMARY "${MARKER_PREFIX}" "no marker in summary"

# ----------------------------------------------------------------------
# Case 4: failed after retry (attempts=2, outcome=failure). The job is
# already red — we must NOT double-signal it here.
# ----------------------------------------------------------------------
echo "Case: failure after retry (attempts=2, outcome=failure)"
run_case "failure-after-retry" "2" "failure" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0 (script is observability, not a gate)"
assert_not_contains STDOUT "::warning" "no warning annotation on failure"
assert_not_contains STDOUT "${MARKER_PREFIX}" "no marker on stdout on failure"
assert_not_contains SUMMARY "${MARKER_PREFIX}" "no marker in summary on failure"

# ----------------------------------------------------------------------
# Case 5: cancelled / unknown outcome with retry. Same rule — only
# `success` triggers the marker.
# ----------------------------------------------------------------------
echo "Case: cancelled outcome (attempts=2, outcome=cancelled)"
run_case "cancelled" "2" "cancelled" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0"
assert_not_contains STDOUT "::warning" "no warning on cancelled"
assert_not_contains STDOUT "${MARKER_PREFIX}" "no stdout marker on cancelled"
assert_not_contains SUMMARY "${MARKER_PREFIX}" "no summary marker on cancelled"

# ----------------------------------------------------------------------
# Case 6: missing TOTAL_ATTEMPTS (e.g. the retry action failed to start
# and never produced an output). We must default to "1 attempt" and
# stay silent.
# ----------------------------------------------------------------------
echo "Case: missing attempts (attempts=, outcome=success)"
run_case "missing-attempts" "" "success" "1"
assert_equals "${EXIT_CODE}" "0" "exits 0"
assert_contains STDOUT "total_attempts=1 outcome=success" "defaults missing attempts to 1"
assert_not_contains STDOUT "::warning" "stays silent on missing attempts"
assert_not_contains STDOUT "${MARKER_PREFIX}" "no stdout marker on missing attempts"
assert_not_contains SUMMARY "${MARKER_PREFIX}" "no false flake marker"

# ----------------------------------------------------------------------
# Case 7: no GITHUB_STEP_SUMMARY (local invocation / non-Actions).
# Warning still goes to stdout so behaviour is observable, but no
# summary file is written and no crash from a redirect to "".
# ----------------------------------------------------------------------
echo "Case: no GITHUB_STEP_SUMMARY (attempts=2, outcome=success)"
run_case "no-summary-file" "2" "success" "0"
assert_equals "${EXIT_CODE}" "0" "exits 0 even without summary file"
assert_contains STDOUT "::warning title=${WARNING_TITLE}" "warning still emitted"
# The stdout marker is the ONLY surface available without a summary
# file — task #110's aggregator depends on this path.
assert_contains STDOUT "${MARKER_PREFIX} attempts=2" "marker still echoed to stdout when summary file unavailable"

# ----------------------------------------------------------------------
echo ""
echo "----------------------------------------------------------------"
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -gt 0 ]; then
  echo ""
  echo "Failures:"
  for name in "${FAILED_NAMES[@]}"; do
    echo "  - ${name}"
  done
  exit 1
fi
echo "All silent-retry surfacing assertions passed."
exit 0
