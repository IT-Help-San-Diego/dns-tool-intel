#!/usr/bin/env bash
set -euo pipefail

science=0
design=0
plumbing=0
generated=0
untagged=0

echo "=== DNS Tool Scrutiny Classification Audit ==="
echo ""

while IFS= read -r f; do
  # Machine-generated files (sqlc etc.) are exempt: regeneration would wipe a
  # hand-added tag. Detected via the standard Go convention marker.
  if head -5 "$f" | grep -q '^// Code generated .* DO NOT EDIT\.$'; then
    generated=$((generated + 1))
    continue
  fi
  tag=$(grep -m1 '^// dns-tool:scrutiny ' "$f" 2>/dev/null | sed 's|^// dns-tool:scrutiny ||' | awk '{print $1}' || true)
  case "$tag" in
    science)  science=$((science + 1)) ;;
    design)   design=$((design + 1)) ;;
    plumbing) plumbing=$((plumbing + 1)) ;;
    *)        untagged=$((untagged + 1))
              echo "  UNTAGGED: $f" ;;
  esac
done < <(find go-server -path "go-server/.go-*" -prune -o -type f -name "*.go" ! -name "*_test.go" -print)

total=$((science + design + plumbing + generated + untagged))
echo ""
echo "Summary:"
echo "  [SCIENCE]   $science files — RFC truth, formulas, confidence logic"
echo "  [DESIGN]    $design files — UX, styling, copy"
echo "  [PLUMBING]  $plumbing files — config, build, infrastructure"
echo "  [GENERATED] $generated files — machine-generated (sqlc etc.), exempt"
echo "  [UNTAGGED]  $untagged files"
echo "  TOTAL:      $total Go files"
echo ""

if [ "$untagged" -gt 0 ]; then
  echo "ACTION NEEDED: $untagged files lack scrutiny classification."
  exit 1
else
  echo "All files classified."
fi
