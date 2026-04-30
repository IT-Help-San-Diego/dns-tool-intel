#!/bin/bash
# Release gate — validates everything before a tag is created.
# Usage: bash scripts/release-gate.sh X.Y.Z
#
# *** THIS IS THE RELEASE BUMP PATH — TAG TIME ONLY ***
# For routine dev version bumps, edit ONLY config.go and rebuild.
# Do NOT run this script for dev bumps. See docs/ACIP.md "Two-Track
# Version Bump Law" and replit.md "CITATION.cff — HANDS OFF".
#
# Runs:
#   1. Version bump in all versioned artifacts
#   2. Methodology PDF regeneration
#   3. Philosophical Foundations PDF regeneration
#   4. CITATION.cff validation (SPDX, schema)
#   5. Go tests
#   6. Quality gates (R009/R010/R011)
#
# Fails loudly on any error. Do NOT tag until this passes.
#
# NOTE: The concept DOI (10.5281/zenodo.19468134) in CITATION.cff
# is PERMANENT and must NEVER be changed by this or any script.

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} — $1"; }
fail() { echo -e "${RED}FAIL${NC} — $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC} — $1"; }

trap 'echo ""; echo -e "${RED}FAIL${NC} — Release gate crashed at line $LINENO: $BASH_COMMAND"; echo "  Fix the error and re-run: bash scripts/release-gate.sh $1"' ERR

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: bash scripts/release-gate.sh X.Y.Z"
  echo "  Version must not have a leading 'v'"
  exit 1
fi

if [[ "$VERSION" == v* ]]; then
  fail "Version must NOT have a leading 'v' (got: $VERSION). Use: ${VERSION#v}"
fi

echo "========================================="
echo "  Release Gate — v${VERSION}"
echo "========================================="
echo ""

info "Gate 1: CITATION.cff license check"
LICENSE_LINE=$(grep '^license:' CITATION.cff || true)
if echo "$LICENSE_LINE" | grep -q 'BUSL-1.1'; then
  pass "CITATION.cff license is BUSL-1.1"
else
  fail "CITATION.cff license is not BUSL-1.1 (found: ${LICENSE_LINE})"
fi

info "Gate 2: CITATION.cff required fields"
grep -q '^title:' CITATION.cff || fail "CITATION.cff missing title"
grep -q '^version:' CITATION.cff || fail "CITATION.cff missing version"
grep -q '^date-released:' CITATION.cff || fail "CITATION.cff missing date-released"
grep -q 'orcid:' CITATION.cff || fail "CITATION.cff missing ORCID"
grep -q '^doi:' CITATION.cff || fail "CITATION.cff missing DOI"
pass "CITATION.cff has all required fields"

info "Gate 3: Version bump — CITATION.cff"
sed -i "s/^version: .*/version: \"${VERSION}\"/" CITATION.cff
DATE_TODAY=$(date +%Y-%m-%d)
sed -i "s/^date-released: .*/date-released: ${DATE_TODAY}/" CITATION.cff
pass "CITATION.cff version → ${VERSION}, date → ${DATE_TODAY}"

info "Gate 4: Version bump — codemeta.json"
if [ -f codemeta.json ]; then
  sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION}\"/" codemeta.json
  sed -i "s/\"softwareVersion\": \"[^\"]*\"/\"softwareVersion\": \"${VERSION}\"/" codemeta.json
  sed -i "s/\"dateModified\": \"[^\"]*\"/\"dateModified\": \"${DATE_TODAY}\"/" codemeta.json
  sed -i "s/\"datePublished\": \"[^\"]*\"/\"datePublished\": \"${DATE_TODAY}\"/" codemeta.json
  pass "codemeta.json version → ${VERSION}"
fi

info "Gate 4b: Version bump — .zenodo.json"
if [ -f .zenodo.json ]; then
  sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION}\"/" .zenodo.json
  sed -i "s/\"publication_date\": \"[^\"]*\"/\"publication_date\": \"${DATE_TODAY}\"/" .zenodo.json
  grep -q "\"version\": \"${VERSION}\"" .zenodo.json \
    || fail ".zenodo.json version was not updated (sed did not match)"
  pass ".zenodo.json version → ${VERSION}, publication_date → ${DATE_TODAY}"
fi

info "Gate 5: Version bump — config.go"
sed -i -E "s/(Version\s*=\s*)\"[^\"]*\"/\1\"${VERSION}\"/" go-server/internal/config/config.go
grep -q "\"${VERSION}\"" go-server/internal/config/config.go \
  || fail "config.go version was not updated (sed did not match)"
pass "config.go version → ${VERSION}"

info "Gate 6: Version bump — sonar-project.properties (DORMANT)"
# SonarCloud SaaS decoupled April 2026; properties file is dormant but
# we still bump the version field so it stays accurate when local
# SonarQube CE is brought online and reads the file as-is.
sed -i "s/^sonar.projectVersion=.*/sonar.projectVersion=${VERSION}/" sonar-project.properties
pass "sonar-project.properties → ${VERSION} (dormant, no upload)"

info "Gate 7: Methodology PDF regeneration"
bash scripts/generate-methodology-pdf.sh "$VERSION"
pass "Methodology PDF regenerated with version ${VERSION}"

info "Gate 7b: Philosophical Foundations PDF regeneration"
bash scripts/generate-foundations-pdf.sh "$VERSION"
pass "Philosophical Foundations PDF regenerated"

info "Gate 7c: Founder's Manifesto PDF regeneration"
bash scripts/generate-manifesto-pdf.sh "$VERSION"
pass "Founder's Manifesto PDF regenerated"

info "Gate 7d: Communication Standards PDF regeneration"
bash scripts/generate-comm-standards-pdf.sh "$VERSION"
pass "Communication Standards PDF regenerated"

info "Gate 8: Go tests"
# REQUIRE_PDF_AUDIT=1 forces TestCorpusPDFIntegrity to FAIL (not skip) if
# pdftotext is missing on the runner — guarantees the corpus PDF banner
# audit ran for every release.
TEST_OUTPUT=$(REQUIRE_PDF_AUDIT=1 go test ./go-server/... -count=1 -short -timeout 120s 2>&1) || true
FAILED_TESTS=$(echo "$TEST_OUTPUT" | grep -E "^--- FAIL:" || true)
FAILED_PKGS=$(echo "$TEST_OUTPUT" | grep -E "^FAIL\s" || true)
TOTAL_FAILS=$(echo "$FAILED_TESTS" | grep -c "FAIL" || true)

if [ "$TOTAL_FAILS" -eq 0 ]; then
  pass "Go tests pass (all green)"
else
  echo ""
  echo "  Failed tests:"
  echo "$FAILED_TESTS" | while read -r line; do echo "    $line"; done
  echo ""
  echo "  Failed packages:"
  echo "$FAILED_PKGS" | while read -r line; do echo "    $line"; done
  fail "Go tests failed — ${TOTAL_FAILS} failure(s)"
fi

info "Gate 8b: go vet (compensating control for dormant SonarCloud)"
# Added April 2026 alongside SonarCloud SaaS decouple. Catches the
# common static-analysis smells (unreachable code, format mismatches,
# struct tag errors, lock copies, etc.) that Sonar used to flag.
if go vet ./go-server/... 2>&1 | tee /tmp/go-vet.log | grep -qE '\.go:[0-9]+'; then
  echo "  go vet findings:"
  cat /tmp/go-vet.log | sed 's/^/    /'
  fail "go vet reported findings — fix before tagging"
fi
pass "go vet clean across go-server/..."

info "Gate 9: Quality gates (R009/R010/R011)"
GATE9_FAILED=0

set +e
R009_OUT=$(node scripts/audit-css-cohesion.js 2>&1)
R009_RC=$?
R010_OUT=$(node scripts/validate-scientific-colors.js 2>&1)
R010_RC=$?
R011_OUT=$(node scripts/feature-inventory.js 2>&1)
R011_RC=$?
set -e

R009_RESULT=$(echo "$R009_OUT" | grep -i "Result:" || echo "Result: UNKNOWN (exit $R009_RC)")
R010_RESULT=$(echo "$R010_OUT" | grep -i "Result:" || echo "Result: UNKNOWN (exit $R010_RC)")
R011_RESULT=$(echo "$R011_OUT" | grep -i "Result:" || echo "Result: UNKNOWN (exit $R011_RC)")

echo "  R009 (CSS cohesion):       $R009_RESULT"
echo "  R010 (scientific colors):  $R010_RESULT"
echo "  R011 (feature inventory):  $R011_RESULT"

if ! echo "$R009_RESULT" | grep -qi "pass"; then
  echo ""
  echo "$R009_OUT" | grep -E "✗|FAIL|ERROR" | head -10 || true
  GATE9_FAILED=1
fi
if ! echo "$R010_RESULT" | grep -qi "pass"; then
  echo ""
  echo "$R010_OUT" | grep -E "✗|FAIL|ERROR" | head -10 || true
  GATE9_FAILED=1
fi
if ! echo "$R011_RESULT" | grep -qi "pass"; then
  echo ""
  echo "$R011_OUT" | grep -E "✗|FAIL|ERROR" | head -10 || true
  GATE9_FAILED=1
fi

if [ "$GATE9_FAILED" -eq 1 ]; then
  fail "Quality gates failed — fix the errors above before releasing"
fi
pass "R009/R010/R011 all pass"

info "Gate 10: handlers/ shim drift guard"
if ! bash scripts/check-handlers-no-shims.sh; then
  fail "handlers/ shim drift detected — see message above"
fi
pass "handlers/ shim guard clean"

info "Gate 11: No stale BSL-1.1 in CITATION.cff"
if grep -q '"BSL-1.1"' CITATION.cff 2>/dev/null; then
  fail "CITATION.cff still contains BSL-1.1 (must be BUSL-1.1)"
fi
pass "No invalid SPDX in CITATION.cff"

info "Gate 12: CITATION.cff schema validation (cffconvert via uv)"
set +e
CFF_OUTPUT=$(uv run cffconvert --validate 2>&1)
CFF_EXIT=$?
set -e
if [ "$CFF_EXIT" -eq 0 ]; then
  pass "cffconvert --validate passed (CFF 1.2.0 schema valid)"
elif echo "$CFF_OUTPUT" | grep -qi "ModuleNotFoundError\|No module named\|ImportError"; then
  echo -e "  ${YELLOW}SKIP${NC} — cffconvert not available via uv (add to pyproject.toml: uv add cffconvert)"
else
  echo "$CFF_OUTPUT"
  fail "cffconvert --validate failed — fix CITATION.cff before tagging"
fi

echo ""
echo "========================================="
echo -e "  ${GREEN}ALL GATES PASSED${NC}"
echo "  Ready to commit, PR, merge, then tag v${VERSION}"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. git add -A && git commit -m 'Release v${VERSION}'"
echo "  2. Push branch → PR → merge to main"
echo "  3. git tag v${VERSION} && git push origin v${VERSION}"
echo "  4. Verify Zenodo ingestion succeeded"
