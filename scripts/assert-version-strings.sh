#!/usr/bin/env bash
# assert-version-strings.sh — unconditional build gate for deposit-version sync.
#
# WHY THIS EXISTS (the defect it removes):
#   The deposit version was stamped by sed patterns that match only well-formed
#   versions. A sed that matches nothing exits 0, so "{10}" and "DNS Tool v10"
#   sat wrong since April while the build reported success. A discovery pattern
#   tuned to well-formed versions inherits the same blindness — it cannot find
#   the malformed strings that go stale.
#
# THE RULE (discover by KEY, assert the VALUE):
#   A version declares the current deposit version only as the value of a
#   version-keyed field ("version":, version:, version = {, Version X, DNS Tool vX).
#   Everything else is a citation (a changelog row, an archive filename, a
#   parenthetical after a date) and is out of scope by construction — no path
#   exclusion list is needed, because a citation is not a keyed field.
#
# WHAT IT DOES, every build, unconditionally:
#   1. Read the deposit-file manifest from scripts/version-files.sh (the single
#      producer the PDF generator also reads).
#   2. In each manifested file, find every version-keyed occurrence and assert
#      its value equals the expected version. A present key with a wrong value
#      (e.g. "{10}") FAILS LOUDLY — that is the catch.
#   3. WARN (not fail) on any UNMANIFESTED tracked file that carries a version
#      in a version-keyed position. No opt-in, no failure — a human reads it and
#      either adds the file to the manifest or ignores it. This is discovery
#      without a gate that can't pass.
#
# USAGE:
#   bash scripts/assert-version-strings.sh [EXPECTED]
#   EXPECTED defaults to the deposit version recorded in .zenodo.json (the
#   canonical deposit-metadata file). Pass explicitly to assert a bump.
#
# EXIT: 0 = all manifested version keys carry the expected version.
#       1 = a manifested file has a version key whose value disagrees.
#
# shellcheck shell=bash
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=version-files.sh
source scripts/version-files.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Expected version: explicit arg, else the deposit metadata's own record.
EXPECTED="${1:-}"
if [ -z "$EXPECTED" ]; then
  EXPECTED=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' .zenodo.json \
             | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$EXPECTED" ]; then
  echo -e "${RED}FAIL${NC} — could not determine expected version (pass it as \$1 or fix .zenodo.json)"
  exit 1
fi
EXPECTED="${EXPECTED#v}"
echo "Asserting deposit version = ${EXPECTED} across ${#DEPOSIT_VERSION_FILES[@]} manifested files"

# Extract every version-keyed VALUE from a file, one per line.
# Key shapes (deposit-metadata formats), captured with explicit groups so the
# value — including a malformed one like {10} — is what's emitted:
#   "version": "X"        (JSON)
#   version: "X"          (CFF/YAML)
#   version      = {X}    (BibTeX)
#   Version X             (markdown heading)
#   Version</span>&ensp;X (HTML)
#   version&nbsp;...= {X} (HTML BibTeX)
#   DNS Tool vX           (prose/badge)
# A present key with a wrong value is emitted (and later flagged), not skipped.
extract_version_values() {
  local f="$1"
  # cff-version is the citation-format schema, not the software version — drop
  # that line first so its value is never emitted as a candidate.
  grep -v '^cff-version:' "$f" 2>/dev/null \
    | sed -nE \
        -e 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' \
        -e 's/^version[[:space:]]*:[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/p' \
        -e 's/.*version[[:space:]]*=[[:space:]]*\{([^}]*)\}.*/\1/p' \
        -e 's/.*Version<\/span>&ensp;([^&<]*).*/\1/p' \
        -e 's/.*version(&nbsp;)+[[:space:]]*=[[:space:]]*\{([^}]*)\}.*/\2/p' \
        -e 's/^Version[[:space:]]+([^[:space:]]+).*/\1/p' \
        -e 's/.*DNS Tool v([^[:space:]]+).*/\1/p' \
        -e 's/.*Enforced values as of v([0-9][0-9A-Za-z.\-]*).*/\1/p' \
    | sed -E 's/["{},]//g; s/^[[:space:]]+//; s/[[:space:]]+$//' \
    | grep -vE '^$' || true
}

FAILED=0

# --- Step 1+2: each manifested file's version keys must equal EXPECTED ---------
for f in "${DEPOSIT_VERSION_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo -e "${RED}FAIL${NC} — manifested file missing: $f"
    FAILED=1
    continue
  fi
  # cff-version is the citation-format schema, NOT the software version.
  # Exclude that key when scanning CITATION.cff.
  if [ "$f" = "CITATION.cff" ]; then
    VALUES=$(grep -vE '^cff-version:' "$f" >/dev/null 2>&1; extract_version_values "$f")
  else
    VALUES=$(extract_version_values "$f")
  fi
  if [ -z "$VALUES" ]; then
    echo -e "${RED}FAIL${NC} — $f: no version-keyed field found (expected at least one)"
    FAILED=1
    continue
  fi
  while IFS= read -r val; do
    v="${val#v}"
    # cff-version schema value is not the software version.
    [ "$v" = "1.2.0" ] && [ "$f" = "CITATION.cff" ] && continue
    if [ "$v" != "$EXPECTED" ]; then
      echo -e "${RED}FAIL${NC} — $f: version key has value '$val', expected '$EXPECTED'"
      FAILED=1
    fi
  done <<< "$VALUES"
done

# --- Step 3: unconditional WARNING for unmanifested version-keyed 26.x.y ------
# Discovery without a gate. A file carrying a version-keyed 26.N.N that is NOT
# in the manifest might be a deposit file nobody declared — surface it, never
# fail. A citation (non-keyed) does not match this pattern by construction.
MANIFEST_RE=$(printf '|%s' "${DEPOSIT_VERSION_FILES[@]}"); MANIFEST_RE="${MANIFEST_RE:1}"
UNMANIFESTED=$(git ls-files \
  | grep -vE "^(${MANIFEST_RE})$" \
  | grep -vE 'node_modules|package-lock|/tools/|\.claude/|skills-lock\.json|dependabot\.yml|sqlc\.yaml|registry\.yaml|pyproject\.toml|/package\.json$|pipeline-config\.json' \
  | while read -r f; do
      [ -f "$f" ] || continue
      if grep -qE '("version"[[:space:]]*:[[:space:]]*"|^version[[:space:]]*:[[:space:]]*"|^Version[[:space:]]+|DNS Tool v)26\.[0-9]+\.[0-9]+' "$f" 2>/dev/null; then
        echo "$f"
      fi
    done)
if [ -n "$UNMANIFESTED" ]; then
  echo -e "${YELLOW}WARN${NC} — files with a version-keyed 26.x.y NOT in the manifest (add to scripts/version-files.sh if any declares the deposit version):"
  echo "$UNMANIFESTED" | sed 's/^/       - /'
fi

if [ "$FAILED" -eq 1 ]; then
  echo -e "${RED}FAIL${NC} — deposit version strings disagree. Fix the mismatches above."
  exit 1
fi
echo -e "${GREEN}PASS${NC} — all manifested version keys = ${EXPECTED}"
