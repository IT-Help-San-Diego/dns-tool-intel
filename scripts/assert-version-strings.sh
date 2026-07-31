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
# DISCOVERY IS INVERTED (2026-07-31): sweep for the VALUE `26.N.N` first — a
# match that cannot miss any markup style — then CLASSIFY each hit. The narrow
# part is the classification, never the discovery. A discovery regex that must
# anticipate every markup style is always one style behind (the gate found 2
# files, a manual sweep found 6, a wide sweep finds 31 — three layers of the
# same miss). The classification is DOI-based, not markup-based:
#
#   1. Manifest member              -> asserted = deposit version (step 1+2)
#   2. Distinct Version DOI         -> CITATION of a past deposit (exempt)
#   3. Record-type exemption list   -> exempt, each with a stated reason
#   4. everything else with 26.N.N  -> WARN (human reads; a NEW record-type file
#                                      lands here until someone declares it)
#
# The exemption list IS the mechanism. The assertion-vs-record proxy ("a version
# is an assertion iff it is the subject's own current version, a record iff it
# is about a past/incident version") is the RATIONALE, not something the gate
# evaluates. Do NOT replace this list with a pattern that implements the proxy —
# that is the same move one iteration later. Record-type files are declared here
# with reasons; a new one fails loudly into WARN until declared.
CONCEPT_DOI="19468134"

# Record-type files/paths: their version strings RECORD a past version or pin a
# historical shape; bumping them would destroy the record or falsify a fixture.
# Path-rules (trailing /) cover dated logs and scan captures that accrete.
RECORD_TYPE_EXEMPT=(
  "docs/ARCHIVED_BUILD_TAG_HISTORY.md|historical build-tag archive; versions record past releases"
  "docs/evolution/|dated evolution logs; versions are historical records (new logs accrete)"
  "dns-eval/|recorded scan-capture fixtures; bumping falsifies the captures"
  "go-server/internal/icsae/testdata/|recorded scan-capture fixtures; bumping falsifies the captures"
  "go-server/internal/handlers/agentpkg/agent_test.go|test fixture pinning a historical response shape"
  "go-server/internal/handlers/corpus_pdf_integrity_test.go|test comments recording incident history"
  "scripts/verify-zenodo-release.sh|comments narrating past release incidents"
)

is_record_exempt() {
  local f="$1" entry path
  for entry in "${RECORD_TYPE_EXEMPT[@]}"; do
    path="${entry%%|*}"
    case "$path" in
      */) case "$f" in "$path"*) return 0;; esac ;;
      *)  [ "$f" = "$path" ] && return 0 ;;
    esac
  done
  return 1
}

# A file is a CITATION of a past deposit (not the current one) when it carries a
# Version DOI distinct from the deposit concept DOI — e.g. REPRODUCTION.md
# documents an archived v26.50.05 with its own version DOI 20777315.
has_distinct_version_doi() {
  grep -oiE 'Version DOI[^0-9]*10\.5281/zenodo\.[0-9]+' "$1" 2>/dev/null \
    | grep -oE '[0-9]+' | tail -1 | grep -qvE "^${CONCEPT_DOI}$" \
    && grep -qiE 'Version DOI' "$1" 2>/dev/null
}

# Stage 2 of classification: is any 26.N.N in this file in a VERSION-KEYED
# position (a declaration), versus an incidental occurrence (a test fixture, a
# dependency version, a date, a comment citing a past incident)? Discovery
# (the value sweep) cannot miss; this keyed-position test keeps the warning
# signal-clean. Only keyed occurrences are version declarations a human must
# see; incidental matches are not classified as version-bearing at all.
has_version_keyed_26() {
  grep -qE '("version"[[:space:]]*:[[:space:]]*"?26\.[0-9]|^version[[:space:]]*:[[:space:]]*"?26\.[0-9]|version[[:space:]]*=[[:space:]]*\{26\.[0-9]|Version[[:space:]]+26\.[0-9]|\*\*Version:\*\*[[:space:]]*v?26\.[0-9]|Version</span>&ensp;26\.[0-9]|version(&nbsp;)+[[:space:]]*=[[:space:]]*\{26\.[0-9]|DNS Tool v26\.[0-9]|Enforced values as of v26\.[0-9])' "$1" 2>/dev/null
}

MANIFEST_RE=$(printf '|%s' "${DEPOSIT_VERSION_FILES[@]}"); MANIFEST_RE="${MANIFEST_RE:1}"
WARN_FILES=()
while IFS= read -r f; do
  # value sweep: any tracked text file containing 26.N.N (discovery cannot miss)
  case "$f" in
    node_modules/*|*/tools/*|.claude/*|*/skills-lock.json|*/dependabot.yml|*/sqlc.yaml|*/registry.yaml|*/pyproject.toml|*/pipeline-config.json|*/uv.lock|package-lock.json|*/package-lock.json|package.json|*/package.json|*.pdf) continue ;;
  esac
  echo "$f" | grep -qE "^(${MANIFEST_RE})$" && continue   # manifest members handled above
  [ -f "$f" ] || continue
  grep -qE '26\.[0-9]+\.[0-9]+' "$f" 2>/dev/null || continue  # stage 1: the value sweep
  # classification
  has_distinct_version_doi "$f" && continue                 # CITATION of a past deposit
  is_record_exempt "$f" && continue                         # declared record-type
  has_version_keyed_26 "$f" || continue                     # incidental 26.N.N, not a declaration
  WARN_FILES+=("$f")
done < <(git ls-files)

if [ "${#WARN_FILES[@]}" -gt 0 ]; then
  echo -e "${YELLOW}WARN${NC} — files carrying a 26.x.y version NOT in the manifest and NOT exempt (a deposit file nobody declared, or a record-type file to declare in scripts/assert-version-strings.sh):"
  printf '       - %s\n' "${WARN_FILES[@]}"
fi

if [ "$FAILED" -eq 1 ]; then
  echo -e "${RED}FAIL${NC} — deposit version strings disagree. Fix the mismatches above."
  exit 1
fi
echo -e "${GREEN}PASS${NC} — all manifested version keys = ${EXPECTED}"
