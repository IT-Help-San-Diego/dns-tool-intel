#!/bin/bash
# Dev version bump — routine development only.
# Usage: bash scripts/dev-bump.sh X.Y.Z
#
# Bumps ONLY config.go, rebuilds, and restarts.
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

sed -i -E "s/(Version\s*=\s*)\"[^\"]*\"/\1\"${VERSION}\"/" go-server/internal/config/config.go
grep -q "\"${VERSION}\"" go-server/internal/config/config.go \
  || { echo "FAIL: config.go was not updated"; exit 1; }

echo "config.go updated ✓"
echo ""
echo "Building..."
bash build.sh
echo ""
echo "CITATION.cff untouched ✓ (concept DOI safe)"
echo "codemeta.json untouched ✓"
echo ""
echo "Ready to publish. Restart the app to see v${VERSION}."
