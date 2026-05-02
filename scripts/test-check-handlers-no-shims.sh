#!/usr/bin/env bash
# Copyright (c) 2024-2026 IT Help San Diego Inc.
# Licensed under BUSL-1.1 — See LICENSE for terms.
# dns-tool:scrutiny design
#
# Self-test for scripts/check-handlers-no-shims.sh (task #120).
#
# Why this exists:
#   The handlers shim drift guard prevents the deleted bridge files
#   (admin.go, agent.go, auth.go, badge.go, badge_owl.go) from
#   reappearing at go-server/internal/handlers/ after the v26.45.x
#   package split. The guard itself has the same silent-rot risk as
#   the Postgres digest guard (task #115): a future refactor of its
#   loop, path handling, or exit-code logic could quietly turn it
#   into a placebo, and CI would keep printing green forever. This
#   self-test exercises both branches of the guard against synthetic
#   handler-package fixtures so a regression in the guard fails the
#   same PR that introduced it.
#
# Strategy:
#   The guard reads from the relative path
#   `go-server/internal/handlers`. By cd-ing into a tempdir that
#   contains a fake handlers/ tree and invoking the guard via its
#   absolute path, we can feed it arbitrary synthetic fixtures
#   without touching the real handler packages.
#
# Cases covered:
#   1. Clean       — handlers/ exists with only allowed files →
#                    exit 0, stdout contains "OK".
#   2. Drift       — a synthetic shim file is present →
#                    exit 1, stderr names the offending file path.
#   3. Multi-drift — several shim files present at once →
#                    exit 1, stderr names ALL of them (so a
#                    maintainer doesn't have to fix-and-rerun in a
#                    loop).
#   4. Each file   — every name in the FORBIDDEN list triggers a
#                    failure on its own (catches a regression that
#                    silently drops one entry from the list).
#
# This script is invoked from .github/workflows/ci.yml right after
# the drift guard itself, so any regression in the guard surfaces on
# the SAME PR.
set -euo pipefail

# Resolve the absolute path to the script under test BEFORE we cd
# anywhere — the guard uses a relative DIR and we need to invoke it
# from inside each fixture tempdir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${SCRIPT_DIR}/check-handlers-no-shims.sh"

if [[ ! -x "$GUARD" ]]; then
  echo "ERROR: guard script not found or not executable: $GUARD" >&2
  exit 1
fi

# Keep the forbidden list here in sync with the guard. Drift between
# this list and the guard's FORBIDDEN array would itself be caught:
# adding a name here without adding it to the guard makes the
# per-file case below fail; removing a name from the guard without
# removing it here also fails the per-file case.
FORBIDDEN=(admin.go agent.go auth.go badge.go badge_owl.go)

PASS=0
FAIL=0
TMP_DIRS=()

cleanup() {
  for d in "${TMP_DIRS[@]}"; do
    rm -rf "$d"
  done
}
trap cleanup EXIT

# Build a minimal fake handlers/ tree inside a fresh tempdir and
# echo the tempdir path on stdout.
make_fixture() {
  local d
  d=$(mktemp -d)
  TMP_DIRS+=("$d")
  mkdir -p "$d/go-server/internal/handlers"
  # A couple of innocuous files that must NEVER trigger the guard.
  # Their presence proves the guard is matching by exact filename,
  # not by substring or by "any .go file".
  cat >"$d/go-server/internal/handlers/router.go" <<'EOF'
package handlers
EOF
  cat >"$d/go-server/internal/handlers/middleware.go" <<'EOF'
package handlers
EOF
  echo "$d"
}

run_case() {
  # Args: <case name> <expected exit code> <pattern that must appear in combined output> <workdir>
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
# Case 1: clean handlers/ (no shim files) → exit 0, "OK" in stdout.
# ---------------------------------------------------------------------
TMP_CLEAN=$(make_fixture)
run_case "clean handlers tree" 0 "handlers/ shim guard: OK" "$TMP_CLEAN"

# ---------------------------------------------------------------------
# Case 2: drift — one synthetic shim file present → exit 1, error
# names the offending file path.
# ---------------------------------------------------------------------
TMP_DRIFT=$(make_fixture)
cat >"$TMP_DRIFT/go-server/internal/handlers/admin.go" <<'EOF'
package handlers

// Synthetic shim reintroduced for drift-guard self-test.
EOF
run_case "single shim file exits 1" 1 "forbidden shim file reappeared" "$TMP_DRIFT"

# Granular assertion: the error must name the exact offending path
# (anything less and a maintainer can't tell which file to delete).
drift_out=$(cd "$TMP_DRIFT" && bash "$GUARD" 2>&1 || true)
if grep -q "go-server/internal/handlers/admin.go" <<<"$drift_out"; then
  echo "PASS [single shim error names offending path]"
  PASS=$((PASS + 1))
else
  echo "FAIL [single shim error names offending path]: path not in error output" >&2
  echo "$drift_out" >&2
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------
# Case 3: multi-drift — several shim files at once → exit 1, error
# names EVERY offending file (so a maintainer fixes them in one pass
# instead of fix-and-rerun).
# ---------------------------------------------------------------------
TMP_MULTI=$(make_fixture)
for f in admin.go agent.go badge_owl.go; do
  cat >"$TMP_MULTI/go-server/internal/handlers/$f" <<EOF
package handlers
// synthetic shim: $f
EOF
done
run_case "multiple shim files exit 1" 1 "forbidden shim file reappeared" "$TMP_MULTI"

multi_out=$(cd "$TMP_MULTI" && bash "$GUARD" 2>&1 || true)
for needle in admin.go agent.go badge_owl.go; do
  if grep -q "go-server/internal/handlers/$needle" <<<"$multi_out"; then
    echo "PASS [multi shim error names: $needle]"
    PASS=$((PASS + 1))
  else
    echo "FAIL [multi shim error names: $needle]: not present in error output" >&2
    echo "$multi_out" >&2
    FAIL=$((FAIL + 1))
  fi
done

# ---------------------------------------------------------------------
# Case 4: per-file coverage — each FORBIDDEN entry triggers a failure
# on its own. Catches a regression that silently drops one name from
# the guard's list (e.g. a refactor that rewrites the loop and
# accidentally truncates the array).
# ---------------------------------------------------------------------
for f in "${FORBIDDEN[@]}"; do
  TMP_ONE=$(make_fixture)
  cat >"$TMP_ONE/go-server/internal/handlers/$f" <<EOF
package handlers
// synthetic shim: $f
EOF
  set +e
  one_out=$(cd "$TMP_ONE" && bash "$GUARD" 2>&1)
  one_exit=$?
  set -e
  if [[ "$one_exit" -eq 1 ]] && grep -q "go-server/internal/handlers/$f" <<<"$one_out"; then
    echo "PASS [per-file: $f triggers guard]"
    PASS=$((PASS + 1))
  else
    echo "FAIL [per-file: $f did not trigger guard cleanly] (exit $one_exit)" >&2
    echo "$one_out" >&2
    FAIL=$((FAIL + 1))
  fi
done

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo ""
echo "test-check-handlers-no-shims.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
