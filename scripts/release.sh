#!/usr/bin/env bash
# One-command release: bumps versions, validates, commits, tags, pushes.
# Usage: ./scripts/release.sh X.Y.Z
#
# Prerequisites:
#   - Clean working tree (no uncommitted changes)
#   - On a branch ready to push (or main if unprotected)
#   - PAT with workflow scope if touching .github/workflows/
#
# What it does:
#   1. Runs release-gate.sh (bumps all 8 versioned artifacts, validates)
#   2. Commits the version bump
#   3. Tags vX.Y.Z
#   4. Pushes commit + tag
#   5. GitHub Actions creates the Release with SHA256SUMS
#   6. Zenodo auto-archives via GitHub integration

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 X.Y.Z"
  exit 1
fi

VER="$1"
TAG="v$VER"

if [[ "$VER" == v* ]]; then
  echo -e "${RED}ERROR${NC}: Version must NOT have a leading 'v' (got: $VER). Use: ${VER#v}"
  exit 1
fi

if [[ ! "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo -e "${RED}ERROR${NC}: Version must be X.Y.Z format (got: $VER)"
  exit 1
fi

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  echo -e "${RED}ERROR${NC}: Working tree is not clean. Commit or stash changes before releasing."
  git status --short
  exit 1
fi

echo ""
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo -e "${YELLOW}  Release Pipeline — ${TAG}${NC}"
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Step 1/5${NC}: Running release gate (version bump + validation)..."
bash scripts/release-gate.sh "$VER"

echo ""
echo -e "${YELLOW}Step 2/5${NC}: Staging all changes..."
git add -A
git status --short

echo ""
echo -e "${YELLOW}Step 3/5${NC}: Committing..."
git commit -m "Release ${TAG}"

echo ""
echo -e "${YELLOW}Step 4/5${NC}: Tagging ${TAG}..."
git tag -a "$TAG" -m "$TAG"

echo ""
echo -e "${YELLOW}Step 5/5${NC}: Pushing commit + tag..."
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git push origin "$BRANCH"
git push origin "$TAG"

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  Release ${TAG} complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""
echo "Next (automatic):"
echo "  1. GitHub Actions creates Release with SHA256SUMS"
echo "  2. Zenodo auto-archives the GitHub Release"
echo ""
echo "Verify:"
echo "  - GitHub: https://github.com/careyjames/dns-tool-web/releases/tag/${TAG}"
echo "  - Zenodo: https://zenodo.org/doi/10.5281/zenodo.18871596"
