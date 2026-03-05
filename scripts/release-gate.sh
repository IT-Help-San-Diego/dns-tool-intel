#!/bin/bash
# Release gate — validates everything before a tag is created.
# Usage: bash scripts/release-gate.sh X.Y.Z
#
# Runs:
#   1. Version bump in all versioned artifacts
#   2. Methodology PDF regeneration
#   3. CITATION.cff validation (SPDX, schema)
#   4. Go tests
#   5. Quality gates (R009/R010/R011)
#   6. Git status check (must be clean after all updates)
#
# Fails loudly on any error. Do NOT tag until this passes.

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} — $1"; }
fail() { echo -e "${RED}FAIL${NC} — $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC} — $1"; }

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

info "Gate 5: Version bump — config.go"
sed -i "s/AppVersion = \"[^\"]*\"/AppVersion = \"${VERSION}\"/" go-server/internal/config/config.go
pass "config.go version → ${VERSION}"

info "Gate 6: Version bump — sonar-project.properties"
sed -i "s/^sonar.projectVersion=.*/sonar.projectVersion=${VERSION}/" sonar-project.properties
pass "sonar-project.properties → ${VERSION}"

info "Gate 7: Methodology PDF regeneration"
bash scripts/generate-methodology-pdf.sh "$VERSION"
pass "Methodology PDF regenerated with version ${VERSION}"

info "Gate 8: Go tests"
if go test ./go-server/... -count=1 -short -timeout 120s > /dev/null 2>&1; then
  pass "Go tests pass"
else
  fail "Go tests failed"
fi

info "Gate 9: Quality gates (R009/R010/R011)"
R009=$(node scripts/audit-css-cohesion.js 2>&1 | tail -1)
R010=$(node scripts/validate-scientific-colors.js 2>&1 | tail -1)
R011=$(node scripts/feature-inventory.js 2>&1 | tail -1)
echo "$R009" | grep -qi "pass" || fail "R009 (CSS cohesion) failed"
echo "$R010" | grep -qi "pass" || fail "R010 (scientific colors) failed"
echo "$R011" | grep -qi "pass" || fail "R011 (feature inventory) failed"
pass "R009/R010/R011 all pass"

info "Gate 10: No stale BSL-1.1 in CITATION.cff"
if grep -q '"BSL-1.1"' CITATION.cff 2>/dev/null; then
  fail "CITATION.cff still contains BSL-1.1 (must be BUSL-1.1)"
fi
pass "No invalid SPDX in CITATION.cff"

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
