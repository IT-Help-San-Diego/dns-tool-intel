#!/usr/bin/env bash
# Suppression drift gate — see security/suppressions.yaml.
#
# A suppression is a time-bound claim, not a dismissal. This gate re-scans
# with the pinned gosec and enforces three invariants:
#   (1) NO finding may exist without a ledger entry (unaccounted = fix it, or
#       suppress it WITH a reason + assumption + date).
#   (2) NO ledger entry may exist whose finding has disappeared (stale = the
#       code drifted; either you fixed it — remove the entry — or it moved —
#       re-locate and re-verify it).
#   (3) NO entry whose safety depends on a GUARD may survive that guard
#       changing or vanishing (see guard_check.py) — a suppression whose
#       validator was deleted must go stale, not silently keep suppressing.
#
# The match key is CONTENT, not line number: each finding is keyed as
# `file|rule|hash` where hash = sha256 of the flagged statement (via
# scripts/gosec_hash.py, paths repo-root-relative). An unrelated edit above a
# finding moves its line but not its content, so the entry stays valid; a
# fixed/changed finding changes its content and goes stale for re-review.
# Identical flagged statements at different lines share a hash — a suppression
# is a claim about the statement PATTERN, not the location.
#
# Exit 0 only when the ledger and the scan agree. This is the mechanical
# answer to suppression drift: a "false positive" that the world turns real
# re-surfaces here as a finding instead of rotting silently.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
LEDGER="$REPO_ROOT/security/suppressions.yaml"
HASHER="$REPO_ROOT/scripts/gosec_hash.py"
GUARD_CHECK="$REPO_ROOT/scripts/guard_check.py"

# --- Positive controls: verify each instrument fires before trusting a zero. ---
# A broken instrument (empty output, a head cap, a skipped conditional, interface
# indirection, a wrong package) reads as "nothing found". One assertion per
# instrument: run it against a KNOWN-PRESENT case and confirm it fires.

# gosec-hash self-test: a synthetic one-issue JSON must emit `file|rule|hash`.
py_selftest="$(printf '%s' '{"Issues":[{"rule_id":"G402","file":"/fake-root/go-server/internal/analyzer/foo.go","line":"42","code":"42: \t\ttls.InsecureSkipVerify = true\n","details":"x"}]}' \
  | PYTHONPATH= python3 "$HASHER" --root /fake-root)"
if ! printf '%s\n' "$py_selftest" | grep -qE '^go-server/internal/analyzer/foo\.go\|G402\|[0-9a-f]{16}$'; then
  echo "::error:: gosec-hash self-test FAILED — the hasher no longer emits 'file|rule|hash'. Instrument broken; refusing to report a number."
  exit 2
fi

# Ledger-parser self-test: a synthetic entry must emit `file|rule|hash`.
awk_selftest="$(printf '%s\n' '- rule: G402' '  file: go-server/internal/analyzer/foo.go' '  hash: ffe1fb81ec6d6840' \
  | awk '$1 == "-" && $2 == "rule:" { rule=$3; file=""; hash=""; next } $1 == "file:" { file=$2; next } $1 == "hash:" { hash=$2; if (rule!="" && file!="" && hash!="") { print file "|" rule "|" hash; rule=file=hash="" } }')"
if [ "$awk_selftest" != "go-server/internal/analyzer/foo.go|G402|ffe1fb81ec6d6840" ]; then
  echo "::error:: ledger-parsing self-test FAILED — the awk no longer parses a known entry. Instrument broken; refusing to report a number."
  exit 2
fi

echo "▸ Re-scanning with pinned gosec (v2.22.5) ..."
# gosec exits non-zero (1) when it finds issues, and `go run` prints "exit
# status 1" to stderr — that is normal, not a failure. Capture stdout (the JSON)
# only and discard stderr so the JSON stays parseable.
GOSEC_OUT="$(cd go-server && GOFLAGS=-buildvcs=false go run github.com/securego/gosec/v2/cmd/gosec@v2.22.5 -fmt json -quiet ./... 2>/dev/null || true)"

# gosec's JSON always carries a "GosecVersion" key when it completes, even with
# zero issues. Its absence means gosec did not run to completion — do not read
# that as "clean".
if ! printf '%s\n' "$GOSEC_OUT" | grep -q '"GosecVersion"'; then
  echo "::error:: gosec produced no JSON summary — it did not run to completion. Refusing to treat this as 'no findings'."
  exit 2
fi

# Normalize current findings to "file|rule|hash" (repo-root-relative, content-keyed).
findings="$(printf '%s\n' "$GOSEC_OUT" | PYTHONPATH= python3 "$HASHER" --root "$REPO_ROOT" | sort -u)"

# Normalize ledger entries to the same "file|rule|hash" form.
suppressed="$(awk '
  $1 == "-" && $2 == "rule:" { rule=$3; file=""; hash=""; next }
  $1 == "file:" { file=$2; next }
  $1 == "hash:" { hash=$2; if (rule!="" && file!="" && hash!="") { print file "|" rule "|" hash; rule=file=hash="" } }
' "$LEDGER" | sort -u)"

# Guard verification: any entry whose safety depends on a validator must still
# see that validator unchanged (or present at all).
if ! PYTHONPATH= python3 "$GUARD_CHECK" --ledger "$LEDGER" --root "$REPO_ROOT"; then
  echo "::error:: guard verification failed — a suppression's guard vanished or changed. Re-reason before it silently continues to suppress."
  exit 3
fi

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
