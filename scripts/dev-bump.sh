#!/bin/bash
# Dev version bump — routine development only.
# Usage: bash scripts/dev-bump.sh X.Y.Z
#
# Bumps config.go + sonar-project.properties, rebuilds binary, commits.
# Does NOT touch CITATION.cff, codemeta.json, or methodology docs.
# For full release bumps (tag time), use: bash scripts/release-gate.sh X.Y.Z
#
# See docs/ACIP.md "Two-Track Version Bump Law".

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: bash scripts/dev-bump.sh X.Y.Z"
  echo "Example: bash scripts/dev-bump.sh 26.34.31"
  exit 1
fi

if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Error: Version must be in X.Y.Z format (e.g., 26.34.31)"
  exit 1
fi

CURRENT=$(grep 'Version.*=' go-server/internal/config/config.go | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "Dev bump: ${CURRENT} → ${VERSION}"
echo ""

sed -i -E "s/(Version\s*=\s*)\"[^\"]*\"/\1\"${VERSION}\"/" go-server/internal/config/config.go
grep -q "\"${VERSION}\"" go-server/internal/config/config.go \
  || { echo "FAIL: config.go was not updated"; exit 1; }
echo "  config.go ✓"

sed -i "s/^sonar.projectVersion=.*/sonar.projectVersion=${VERSION}/" sonar-project.properties
grep -q "sonar.projectVersion=${VERSION}" sonar-project.properties \
  || { echo "FAIL: sonar-project.properties was not updated"; exit 1; }
echo "  sonar-project.properties ✓"

echo ""
echo "Building..."
bash build.sh

echo ""
echo "Committing..."
git add go-server/internal/config/config.go sonar-project.properties
git commit -m "dev-bump: v${VERSION}" --quiet
echo "  Committed: dev-bump: v${VERSION} ✓"

echo ""
echo "Protected (untouched):"
echo "  CITATION.cff ✓ (concept DOI safe)"
echo "  codemeta.json ✓"
echo "  methodology docs ✓"
echo ""
echo "Restarting app..."
pkill -f dns-tool-server 2>/dev/null || true
sleep 1
nohup ./dns-tool-server > /dev/null 2>&1 &
echo "  App restarted on v${VERSION} ✓"
echo ""
echo "Ready. Run: bash scripts/git-sync.sh"
