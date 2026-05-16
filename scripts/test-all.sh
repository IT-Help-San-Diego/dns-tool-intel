#!/usr/bin/env bash
# Full Go test matrix — single canonical entry point for "did I break anything?"
# Usage: bash scripts/test-all.sh
#
# Runs (in order, fail-fast):
#   1. go vet ./go-server/...
#   2. go test ./go-server/... -count=1 -short  (core, ~33K lines, default tags)
#   3. run-handler-tests-full.sh (per-tag passes: default, bigtests, coverage, scientific)
#   4. RFC attack vector tests (analyzer/ -run RFCAttack)
#
# What this DOESN'T run (use other scripts):
#   - dbtest / integration tags (need live PostgreSQL + network)
#   - Lighthouse / Observatory (use scripts/quality-gate.sh)
#   - SonarCloud (CI-only)
#
# Build tags reference:
#   default     ~33K core lines
#   bigtests    large fixtures / corpus
#   coverage    coverage / sprint batch
#   scientific  scientific methodology tests
#   dbtest      requires live PostgreSQL  (CI lane only)
#   integration requires network egress   (CI lane only)

set -uo pipefail
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════"
echo "  DNS Tool — Full Test Matrix"
echo "═══════════════════════════════════════════════"
echo ""

FAIL=0
START=$(date +%s)

# 1. go vet — must be clean before any tests
echo "▸ [1/4] go vet ./go-server/..."
if (cd go-server && go vet ./... 2>&1); then
  echo "  ✓ go vet clean"
else
  echo "  ✗ go vet FAILED — stopping (vet must be clean before tests)"
  exit 1
fi

# 2. Core test suite (default tags, all packages)
echo ""
echo "▸ [2/4] core Go tests (default tags, all packages)..."
if (cd go-server && go test ./... -short -count=1 -timeout=300s 2>&1 | tail -20); then
  echo "  ✓ core tests passed"
else
  echo "  ✗ core tests FAILED"
  FAIL=1
fi

# 3. Per-tag handler test passes (memory-bounded per task #90)
echo ""
echo "▸ [3/4] full handler test matrix (per-tag passes)..."
if bash scripts/run-handler-tests-full.sh -short -count=1 -timeout=300s 2>&1 | tail -10; then
  echo "  ✓ all handler tag passes succeeded"
else
  echo "  ✗ handler tag pass(es) FAILED"
  FAIL=1
fi

# 4. RFC attack vector regression tests (security-critical analyzers)
echo ""
echo "▸ [4/4] RFC attack vector tests (analyzer/ -run RFCAttack)..."
if (cd go-server && go test ./internal/analyzer/ -run "RFCAttack" -timeout=60s -count=1 2>&1 | tail -5); then
  echo "  ✓ RFC attack tests passed"
else
  echo "  ✗ RFC attack tests FAILED"
  FAIL=1
fi

ELAPSED=$(( $(date +%s) - START ))
echo ""
echo "═══════════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
  echo "  TEST MATRIX: PASSED ✓  (${ELAPSED}s)"
  echo "  Next: bash scripts/quality-gate.sh"
else
  echo "  TEST MATRIX: FAILED ✗  (${ELAPSED}s)"
  echo "  Fix failing tests before running quality-gate / shipping."
fi
echo "═══════════════════════════════════════════════"
exit $FAIL
