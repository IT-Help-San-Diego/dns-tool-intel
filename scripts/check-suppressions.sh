#!/usr/bin/env bash
# Suppression drift gate — see security/suppressions.yaml.
#
# A suppression is a time-bound claim, not a dismissal. This gate re-scans
# with the pinned gosec and enforces two invariants:
#   (1) NO finding may exist without a ledger entry (unaccounted = fix it, or
#       suppress it WITH a reason + assumption + date).
#   (2) NO ledger entry may exist whose finding has disappeared (stale = the
#       code drifted; either you fixed it — remove the entry — or it moved —
#       re-locate and re-verify it).
#
# Exit 0 only when the ledger and the scan agree. This is the mechanical
# answer to suppression drift: a "false positive" that the world turns real
# re-surfaces here as a finding instead of rotting silently.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
LEDGER="$REPO_ROOT/security/suppressions.yaml"

echo "▸ Re-scanning with pinned gosec (v2.22.5) ..."
GOSEC_OUT="$(cd go-server && GOFLAGS=-buildvcs=false go run github.com/securego/gosec/v2/cmd/gosec@v2.22.5 -quiet ./... 2>&1 || true)"

# Normalize current findings to "file:line|RULE" (start line only; ranges
# collapse to their first line so line-drift is detectable, not silently
# re-matched by the range tail).
findings="$(printf '%s\n' "$GOSEC_OUT" \
  | perl -ne 'print "$1:$2|$3\n" if /go-server\/([A-Za-z0-9_\/.-]+\.go):(\d+)(?:-\d+)?\] - (G\d+)/' \
  | sort -u)"

# Normalize ledger entries to the same "file:line|RULE" form. Each entry is a
# YAML block beginning with "- rule:", followed by "file:" and "line:" keys.
suppressed="$(awk '
  $1 == "-" && $2 == "rule:" { rule=$3; file=""; line=""; next }
  $1 == "file:" { file=$2; next }
  $1 == "line:" { line=$2; if (rule!="" && file!="" && line!="") { print file ":" line "|" rule; rule=file=line="" } }
' "$LEDGER" | sort -u)"

unaccounted="$(comm -13 <(printf '%s\n' "$suppressed") <(printf '%s\n' "$findings") | grep -v '^$' || true)"
stale="$(comm -23 <(printf '%s\n' "$suppressed") <(printf '%s\n' "$findings") | grep -v '^$' || true)"

unaccounted_count="$(printf '%s\n' "$unaccounted" | grep -c . || true)"
stale_count="$(printf '%s\n' "$stale" | grep -c . || true)"

if [ -n "$unaccounted" ]; then
  echo ""
  echo "✗ Unaccounted findings (fix them, OR add a REASONED ledger entry):"
  printf '%s\n' "$unaccounted" | sed 's/^/    /'
fi
if [ -n "$stale" ]; then
  echo ""
  echo "✗ Stale suppressions (finding drifted or vanished — re-review or remove the entry):"
  printf '%s\n' "$stale" | sed 's/^/    /'
fi

if [ -z "$unaccounted" ] && [ -z "$stale" ]; then
  echo "✓ Suppression ledger and scan agree — every finding accounted, every suppression live."
  exit 0
fi

echo ""
echo "SUPPRESSION DRIFT GATE FAILED (unaccounted: ${unaccounted_count}, stale: ${stale_count})."
exit 1
