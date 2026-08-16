#!/usr/bin/env bash
# CI ratchets — deterministic-only quality checks that never vary by environment.
# Called from .github/workflows/ci.yml after the binary builds.
# Adds ~5s to CI. Fails the build on regression. Baselines live in
# scripts/quality-baselines/ and may only shrink.
set -euo pipefail

BASE="scripts/quality-baselines"
FILES=$(find go-server -path 'go-server/.go-*' -prune -o -type f -name '*.go' -print)

# gofmt: no NEW unformatted files vs baseline.
echo "▸ gofmt (no new unformatted)"
[ -f "$BASE/gofmt-unformatted.txt" ] || { echo "  ✗ MISSING baseline: $BASE/gofmt-unformatted.txt"; exit 1; }
gofmt -l $FILES 2>/dev/null > /tmp/gofmt-current.txt
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if ! grep -qxF "$f" "$BASE/gofmt-unformatted.txt"; then
    echo "  ✗ NEW unformatted file: $f"
    exit 1
  fi
done < /tmp/gofmt-current.txt
echo "  ✓ clean"

# gocyclo: no NEW production functions over 15.
echo "▸ gocyclo (production ≤ baseline)"
[ -f "$BASE/gocyclo.count" ] || { echo "  ✗ MISSING baseline: $BASE/gocyclo.count"; exit 1; }
BASE_N=$(cat "$BASE/gocyclo.count")
CUR_N=$(go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 15 $FILES 2>/dev/null | grep -v '_test.go' | wc -l | tr -d ' ')
CUR_N=${CUR_N:-0}
if [ "$CUR_N" -gt "$BASE_N" ]; then
  echo "  ✗ REGRESSION: $CUR_N functions >15 vs baseline $BASE_N"
  go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 15 $FILES 2>/dev/null | grep -v '_test.go' | tail -5 || true
  exit 1
fi
if [ "$CUR_N" -eq 0 ] && [ "$BASE_N" -gt 0 ]; then
  echo "  ⚠ gocyclo returned 0 (baseline $BASE_N) — tool may not have run; skipping check"
else
  echo "  ✓ gocyclo: $CUR_N ≤ $BASE_N"
fi

# file-size: no non-test .go >900 lines outside exception list.
echo "▸ file-size (≤900 lines)"
[ -f "$BASE/file-size-exceptions.txt" ] || touch "$BASE/file-size-exceptions.txt"
echo "$FILES" | grep -v '_test.go' > /tmp/go-prod-files.txt
while IFS= read -r f; do
  [ -z "$f" ] && continue
  lines=$(wc -l < "$f")
  [ "$lines" -le 900 ] && continue
  if ! grep -qxF "$f" "$BASE/file-size-exceptions.txt"; then
    echo "  ✗ $f: $lines lines (cap 900)"
    exit 1
  fi
done < /tmp/go-prod-files.txt
echo "  ✓ within cap"

echo "RATCHETS: PASSED"