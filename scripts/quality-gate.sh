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
#   9. gofmt ratchet — no NEW unformatted files (critical)
#  10. staticcheck ratchet — findings may not exceed baseline (critical)
#  11. gocyclo ratchet — functions over 15 may not exceed baseline (critical)
#  12. file-size cap — no non-test .go file >900 lines outside exception list (critical)
#  13. scrutiny tag audit — every non-test .go file classified (critical)
#
# Ratchet baselines live in scripts/quality-baselines/ and may only shrink.
# When you fix debt, tighten the baseline in the same ship so it can't regress.
#
# What this DOESN'T run (separate scripts):
#   - Full handler test matrix → scripts/test-all.sh
#   - Lighthouse 100/100/100/100 deep run → npx lighthouse manually
#   - Observatory 145+ → web UI at https://developer.mozilla.org/en-US/observatory

set -uo pipefail
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════"
echo "  DNS Tool — Pre-Ship Quality Gate"
echo "═══════════════════════════════════════════════"
echo ""

FAIL=0
WARN=0
START=$(date +%s)
BASE_DIR="scripts/quality-baselines"

# 1. go vet — must be clean
# Defense-in-depth: ensure the configured Go cache/tmp dirs exist before any go
# command. .replit [userenv.shared] points GOCACHE/GOMODCACHE/GOTMPDIR at
# workspace-relative dirs (persistent, gitignored); mkdir -p is a harmless no-op when
# they already exist and self-heals if anything ever removed them.
mkdir -p \
  "${GOCACHE:-/home/runner/workspace/.go-build-cache}" \
  "${GOMODCACHE:-/home/runner/workspace/.go-mod-cache}" \
  "${GOTMPDIR:-/home/runner/workspace/.go-tmp}" 2>/dev/null || true
echo "▸ [1/13] go vet ./go-server/..."
if (cd go-server && go vet ./... 2>&1 >/dev/null); then
  echo "  ✓ go vet clean"
else
  echo "  ✗ go vet FAILED"
  FAIL=1
fi

# 2. R009 — CSS cohesion (replit.md: "Always before delivering")
echo ""
echo "▸ [2/13] R009 — CSS cohesion audit..."
if node scripts/audit-css-cohesion.js 2>&1 | tail -3; then
  echo "  ✓ R009 passed"
else
  echo "  ✗ R009 FAILED — fix CSS cohesion issues before shipping"
  FAIL=1
fi

# 3. R010 — scientific color tokens
echo ""
echo "▸ [3/13] R010 — scientific color validation..."
if node scripts/validate-scientific-colors.js 2>&1 | tail -3; then
  echo "  ✓ R010 passed"
else
  echo "  ✗ R010 FAILED — scientific color tokens out of spec"
  FAIL=1
fi

# 4. R011 — feature inventory
echo ""
echo "▸ [4/13] R011 — feature inventory..."
if node scripts/feature-inventory.js 2>&1 | tail -3; then
  echo "  ✓ R011 passed"
else
  echo "  ✗ R011 FAILED — feature inventory drift"
  FAIL=1
fi

# 5. Core analyzer/middleware/entitlements tests
# Note: analyzer suite runs ~110s warm; 240s gives headroom for cold cache.
echo ""
echo "▸ [5/13] core analyzer/middleware/entitlements tests..."
if (cd go-server && go test ./internal/analyzer/ ./internal/middleware/ ./internal/entitlements/ -timeout 240s -count=1 2>&1 | tail -5); then
  echo "  ✓ core tests passed"
else
  echo "  ✗ core tests FAILED"
  FAIL=1
fi

# 6. RFC attack vector regression tests
echo ""
echo "▸ [6/13] RFC attack vector tests..."
if (cd go-server && go test ./internal/analyzer/ -run "RFCAttack" -timeout 60s -count=1 2>&1 | tail -3); then
  echo "  ✓ RFC attack tests passed"
else
  echo "  ✗ RFC attack tests FAILED"
  FAIL=1
fi

# 7. csso minified CSS freshness (advisory — drift warning)
echo ""
echo "▸ [7/13] csso minified CSS freshness (advisory)..."
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
echo "▸ [8/13] Lighthouse drive-by (advisory)..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/healthz 2>/dev/null | grep -q "200"; then
  echo "  ✓ dev server reachable at localhost:5000"
  echo "    Full audit: npx lighthouse http://localhost:5000 --only-categories=performance,accessibility,best-practices,seo --quiet"
  echo "    Standing gate: 100/100/100/100 (replit.md)"
else
  echo "  ⚠ dev server not reachable — start workflow first if you want a Lighthouse run"
  WARN=1
fi

# Project Go file inventory shared by steps 9–13.
# Prunes go-server/.go-* (module/build caches live INSIDE go-server — never walk them).
PROJECT_GO_FILES=$(find go-server -path "go-server/.go-*" -prune -o -type f -name "*.go" -print)

# 9. gofmt ratchet — new/edited files must be gofmt-clean; legacy files grandfathered.
echo ""
echo "▸ [9/13] gofmt ratchet (no NEW unformatted files)..."
if [ -f "$BASE_DIR/gofmt-unformatted.txt" ]; then
  GOFMT_NEW=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qxF "$f" "$BASE_DIR/gofmt-unformatted.txt"; then
      echo "  ✗ NEW unformatted file: $f — run: gofmt -w $f"
      GOFMT_NEW=1
    fi
  done < <(gofmt -l $PROJECT_GO_FILES 2>/dev/null)
  if [ "$GOFMT_NEW" -eq 0 ]; then
    echo "  ✓ no new unformatted files (legacy baseline: $(wc -l < "$BASE_DIR/gofmt-unformatted.txt") files)"
  else
    FAIL=1
  fi
else
  echo "  ✗ baseline missing: $BASE_DIR/gofmt-unformatted.txt"
  FAIL=1
fi

# 10. staticcheck ratchet — pinned version; finding count may only shrink.
# GOFLAGS=-buildvcs=false: VCS stamping trips the workspace git guard.
echo ""
echo "▸ [10/13] staticcheck ratchet (pinned 2025.1.1)..."
if [ -f "$BASE_DIR/staticcheck.count" ]; then
  SC_BASE=$(cat "$BASE_DIR/staticcheck.count")
  SC_OUT=$(GOFLAGS=-buildvcs=false go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./go-server/... 2>&1)
  SC_CUR=$(printf '%s' "$SC_OUT" | grep -c . || true)
  if [ "$SC_CUR" -le "$SC_BASE" ]; then
    echo "  ✓ staticcheck: $SC_CUR line(s) (baseline $SC_BASE)"
    if [ "$SC_CUR" -lt "$SC_BASE" ]; then
      echo "    ↓ debt paid — tighten baseline: echo $SC_CUR > $BASE_DIR/staticcheck.count"
    fi
  else
    echo "  ✗ staticcheck REGRESSION: $SC_CUR line(s) vs baseline $SC_BASE. New findings:"
    printf '%s\n' "$SC_OUT" | tail -15
    FAIL=1
  fi
else
  echo "  ✗ baseline missing: $BASE_DIR/staticcheck.count"
  FAIL=1
fi

# 11. gocyclo ratchet — functions with complexity >15 may only shrink.
echo ""
echo "▸ [11/13] gocyclo ratchet (complexity >15)..."
if [ -f "$BASE_DIR/gocyclo.count" ]; then
  GC_BASE=$(cat "$BASE_DIR/gocyclo.count")
  GC_OUT=$(go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 15 go-server/cmd go-server/internal 2>&1 || true)
  GC_CUR=$(printf '%s' "$GC_OUT" | grep -c . || true)
  if [ "$GC_CUR" -le "$GC_BASE" ]; then
    echo "  ✓ gocyclo: $GC_CUR function(s) over 15 (baseline $GC_BASE)"
    if [ "$GC_CUR" -lt "$GC_BASE" ]; then
      echo "    ↓ debt paid — tighten baseline: echo $GC_CUR > $BASE_DIR/gocyclo.count"
    fi
  else
    echo "  ✗ gocyclo REGRESSION: $GC_CUR function(s) vs baseline $GC_BASE. Worst offenders:"
    printf '%s\n' "$GC_OUT" | sort -rn | head -10
    FAIL=1
  fi
else
  echo "  ✗ baseline missing: $BASE_DIR/gocyclo.count"
  FAIL=1
fi

# 12. File-size cap — no non-test .go file over 900 lines outside the exception list.
# The exception list is the shrink-only inventory of legacy monoliths.
echo ""
echo "▸ [12/13] file-size cap (900 lines, non-test)..."
if [ -f "$BASE_DIR/filesize-exceptions.txt" ]; then
  SIZE_FAIL=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$f" in *_test.go) continue ;; esac
    LINES=$(wc -l < "$f")
    if [ "$LINES" -gt 900 ] && ! grep -qxF "$f" "$BASE_DIR/filesize-exceptions.txt"; then
      echo "  ✗ $f is $LINES lines (>900) and not in the exception list — split it"
      SIZE_FAIL=1
    fi
  done <<< "$PROJECT_GO_FILES"
  if [ "$SIZE_FAIL" -eq 0 ]; then
    echo "  ✓ no new oversized files (exception list: $(wc -l < "$BASE_DIR/filesize-exceptions.txt") legacy files)"
  else
    FAIL=1
  fi
else
  echo "  ✗ baseline missing: $BASE_DIR/filesize-exceptions.txt"
  FAIL=1
fi

# 13. Scrutiny tag audit — every non-test .go file must carry a dns-tool:scrutiny tag.
echo ""
echo "▸ [13/13] scrutiny tag audit..."
if bash scripts/audit-scrutiny-tags.sh 2>&1 | tail -3; then
  echo "  ✓ all files classified"
else
  echo "  ✗ scrutiny tag audit FAILED — tag the files listed above"
  FAIL=1
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
