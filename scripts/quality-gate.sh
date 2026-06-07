#!/usr/bin/env bash
# Quality gate — pre-ship verification of the standing gates from replit.md.
# Usage: bash scripts/quality-gate.sh
#
# Runs (fail-fast on critical, soft-warn on advisory):
#   1. go vet (critical)
#   2. R009 — CSS cohesion audit (critical)
#   3. R010 — scientific color tokens (critical)
#   4. R011 — feature inventory (critical)
#   5. core analyzer tests (critical)
#   6. RFC attack vector tests (critical)
#   7. csso minification check (advisory — warn if drift)
#   8. Lighthouse drive-by against localhost:5000 (advisory — full audit on demand)
#
# What this DOESN'T run (separate scripts):
#   - Full handler test matrix → scripts/test-all.sh
#   - Lighthouse 100/100/100/100 deep run → npx lighthouse manually
#   - Observatory 145+ → web UI at https://developer.mozilla.org/en-US/observatory
#   - SonarCloud A/A/A → CI-only

set -uo pipefail
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════"
echo "  DNS Tool — Pre-Ship Quality Gate"
echo "═══════════════════════════════════════════════"
echo ""

FAIL=0
WARN=0
START=$(date +%s)

# 1. go vet — must be clean
# Defense-in-depth: ensure the configured Go cache/tmp dirs exist before any go
# command. .replit [userenv.shared] points GOCACHE/GOMODCACHE/GOTMPDIR at
# workspace-relative dirs (persistent, gitignored); mkdir -p is a harmless no-op when
# they already exist and self-heals if anything ever removed them.
mkdir -p \
  "${GOCACHE:-/home/runner/workspace/.go-build-cache}" \
  "${GOMODCACHE:-/home/runner/workspace/.go-mod-cache}" \
  "${GOTMPDIR:-/home/runner/workspace/.go-tmp}" 2>/dev/null || true
echo "▸ [1/8] go vet ./go-server/..."
if (cd go-server && go vet ./... 2>&1 >/dev/null); then
  echo "  ✓ go vet clean"
else
  echo "  ✗ go vet FAILED"
  FAIL=1
fi

# 2. R009 — CSS cohesion (replit.md: "Always before delivering")
echo ""
echo "▸ [2/8] R009 — CSS cohesion audit..."
if node scripts/audit-css-cohesion.js 2>&1 | tail -3; then
  echo "  ✓ R009 passed"
else
  echo "  ✗ R009 FAILED — fix CSS cohesion issues before shipping"
  FAIL=1
fi

# 3. R010 — scientific color tokens
echo ""
echo "▸ [3/8] R010 — scientific color validation..."
if node scripts/validate-scientific-colors.js 2>&1 | tail -3; then
  echo "  ✓ R010 passed"
else
  echo "  ✗ R010 FAILED — scientific color tokens out of spec"
  FAIL=1
fi

# 4. R011 — feature inventory
echo ""
echo "▸ [4/8] R011 — feature inventory..."
if node scripts/feature-inventory.js 2>&1 | tail -3; then
  echo "  ✓ R011 passed"
else
  echo "  ✗ R011 FAILED — feature inventory drift"
  FAIL=1
fi

# 5. Core analyzer/middleware/entitlements tests
# Note: analyzer suite runs ~110s warm; 240s gives headroom for cold cache.
echo ""
echo "▸ [5/8] core analyzer/middleware/entitlements tests..."
if (cd go-server && go test ./internal/analyzer/ ./internal/middleware/ ./internal/entitlements/ -timeout 240s -count=1 2>&1 | tail -5); then
  echo "  ✓ core tests passed"
else
  echo "  ✗ core tests FAILED"
  FAIL=1
fi

# 6. RFC attack vector regression tests
echo ""
echo "▸ [6/8] RFC attack vector tests..."
if (cd go-server && go test ./internal/analyzer/ -run "RFCAttack" -timeout 60s -count=1 2>&1 | tail -3); then
  echo "  ✓ RFC attack tests passed"
else
  echo "  ✗ RFC attack tests FAILED"
  FAIL=1
fi

# 7. csso minified CSS freshness (advisory — drift warning)
echo ""
echo "▸ [7/8] csso minified CSS freshness (advisory)..."
if [ -f static/css/custom.min.css ] && [ -f static/css/custom.css ]; then
  if [ static/css/custom.css -nt static/css/custom.min.css ]; then
    echo "  ⚠ custom.css newer than custom.min.css — run: npx csso static/css/custom.min.css"
    WARN=1
  else
    echo "  ✓ custom.min.css is fresh"
  fi
else
  echo "  ⚠ custom.css or custom.min.css missing — verify CSS pipeline"
  WARN=1
fi

# 8. Lighthouse drive-by (advisory — quick smoke vs full audit)
echo ""
echo "▸ [8/8] Lighthouse drive-by (advisory)..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/healthz 2>/dev/null | grep -q "200"; then
  echo "  ✓ dev server reachable at localhost:5000"
  echo "    Full audit: npx lighthouse http://localhost:5000 --only-categories=performance,accessibility,best-practices,seo --quiet"
  echo "    Standing gate: 100/100/100/100 (replit.md)"
else
  echo "  ⚠ dev server not reachable — start workflow first if you want a Lighthouse run"
  WARN=1
fi

ELAPSED=$(( $(date +%s) - START ))
echo ""
echo "═══════════════════════════════════════════════"
if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
  echo "  QUALITY GATE: PASSED ✓  (${ELAPSED}s)"
  echo "  Next: bash scripts/git-push.sh"
elif [ "$FAIL" -eq 0 ]; then
  echo "  QUALITY GATE: PASSED with advisories ⚠  (${ELAPSED}s)"
  echo "  Address warnings above, then: bash scripts/git-push.sh"
else
  echo "  QUALITY GATE: FAILED ✗  (${ELAPSED}s)"
  echo "  Fix all critical failures before shipping."
fi
echo "═══════════════════════════════════════════════"
exit $FAIL
