#!/usr/bin/env bash
# One-command release: bumps versions, validates, commits, tags, pushes.
# Usage: ./scripts/release.sh X.Y.Z
#
# Prerequisites:
#   - Clean working tree (no uncommitted changes)
#   - GH_SYNC_TOKEN set with repo + workflow scope
#
# What it does:
#   1. Runs release-gate.sh (bumps all versioned artifacts, regenerates PDFs, validates)
#   2. Commits the release locally
#   3. Pushes to dns-tool-intel (canonical repo) via git-push.sh
#   4. Creates annotated tag vX.Y.Z
#   5. GitHub Actions creates the Release with SHA256SUMS (automatic)
#   6. Zenodo auto-archives via GitHub integration (automatic)
#   7. Verifies the Zenodo version record exists and matches the tag
#      (scripts/verify-zenodo-release.sh)
#
# Architecture:
#   Single-repo: IT-Help-San-Diego/dns-tool-intel (BUSL-1.1 licensed).
#   Build tags separate OSS stubs (_oss.go) from intel (_intel.go).
#   Zenodo watches this repo for releases.

set -euo pipefail
cd "$(dirname "$0")/.."

# Hermes/agent shells export PYTHONPATH pointing at their own venv (Python 3.11),
# which shadows this repo's .venv (Python 3.14) and breaks weasyprint's PIL import
# during PDF regeneration. Unset it so the repo's own toolchain is used.
unset PYTHONPATH

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

trap 'echo ""; echo -e "  ${RED}✗ Release pipeline failed at line $LINENO: $BASH_COMMAND${NC}"; echo "  Fix the error above and re-run: bash scripts/release.sh $1"' ERR

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 X.Y.Z"
  exit 1
fi

VER="$1"
TAG="v$VER"

if [[ "$VER" == v* ]]; then
  fail "Version must NOT have a leading 'v' (got: $VER). Use: ${VER#v}"
fi

if [[ ! "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "Version must be X.Y.Z format (got: $VER)"
fi

# Refuse to release from main/master: git-push.sh treats "already on main" as
# branch-only (PUSH_MAIN=0), so the release commit would land on an orphaned
# snapshot/ branch and the tag would go on main's OLD tip (files at the previous
# version). The correct flow is a release branch off origin/main, which git-push.sh
# ships to main via a squash PR before we tag.
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ "$CURRENT_BRANCH" = "main" ] || [ "$CURRENT_BRANCH" = "master" ]; then
  fail "Refusing to release from '$CURRENT_BRANCH'. Run from a release branch: git switch -c release/${TAG} origin/main"
fi

TOKEN="${GH_SYNC_TOKEN:-${ORG_PAT:-${GITHUB_MASTER_PAT:-}}}"
if [ -z "$TOKEN" ]; then
  fail "GH_SYNC_TOKEN (or ORG_PAT) not set. Cannot authenticate with GitHub."
fi

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is not clean. Commit or stash changes before releasing."
fi

REPO="IT-Help-San-Diego/dns-tool-intel"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Release Pipeline — ${TAG}${NC}"
echo -e "${YELLOW}  repo: ${REPO}${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Step 1/5${NC}: Running release gate (version bump + validation)..."
echo ""
bash scripts/release-gate.sh "$VER"

echo ""
echo -e "${YELLOW}Step 2/5${NC}: Committing release locally..."
git add -A
git status --short
git commit -m "Release ${TAG}"
pass "Committed: Release ${TAG}"

echo ""
echo -e "${YELLOW}Step 3/5${NC}: Syncing to ${REPO}..."
bash scripts/git-push.sh
pass "${REPO} synced"

echo ""
echo -e "${YELLOW}Step 4/5${NC}: Creating tag ${TAG} on origin/main's tip..."
# Version Law: the tag goes on origin/main's tip — NEVER local HEAD.
# The squash-merge flow means local HEAD is never on main's lineage, so a
# tag on local HEAD reads clean locally but is invisible to production.
git fetch origin main
git tag -a "${TAG}" origin/main -m "Release ${TAG}"
# Push via PAT-embedded URL — the workspace origin remote has no push
# credentials (same reason git-push.sh pushes this way).
git push "https://${TOKEN}@github.com/${REPO}.git" "${TAG}"
TAG_STATUS="unknown"
for attempt in 1 2; do
  TAG_STATUS=$(GH_TOKEN="${ALL_GH:-${GH_TOKEN:-$TOKEN}}" gh api "repos/${REPO}/compare/main...${TAG}" --jq '.status' 2>/dev/null || echo "unknown")
  case "$TAG_STATUS" in identical|behind) break ;; esac
  [ "$attempt" -eq 1 ] && sleep 5
done
case "$TAG_STATUS" in
  identical|behind)
    pass "Tag ${TAG} pushed — reachable from main (compare: ${TAG_STATUS})"
    ;;
  *)
    fail "Tag ${TAG} NOT confirmed reachable from main (compare: ${TAG_STATUS}). Verify manually before deleting: gh api repos/${REPO}/compare/main...${TAG} --jq .status — expect identical/behind. If truly mis-placed: git push origin :refs/tags/${TAG} && git tag -d ${TAG}, then re-tag origin/main."
    ;;
esac

echo ""
echo -e "${YELLOW}Step 5/5${NC}: Verifying Zenodo ingestion (async; polling up to ~15 min)..."
if bash scripts/verify-zenodo-release.sh "$VER" --wait; then
  pass "Zenodo version record verified for ${TAG}"
else
  echo -e "  ${YELLOW}▸${NC} Not confirmed — re-run later: bash scripts/verify-zenodo-release.sh ${VER} --wait"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release ${TAG} complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "What happened:"
echo "  1. All versioned artifacts bumped to ${VER}"
echo "  2. PDFs regenerated (methodology, foundations, manifesto, comm standards)"
echo "  3. CITATION.cff version + date updated"
echo "  4. Go tests + quality gates passed"
echo "  5. Committed locally + synced to ${REPO}"
echo "  6. Tag ${TAG} created"
echo ""
echo "Next (automatic — no action needed):"
echo "  1. GitHub Actions creates Release with SHA256SUMS"
echo "  2. Zenodo auto-archives the GitHub Release"
echo ""
echo "Verify:"
echo "  - GitHub: https://github.com/${REPO}/releases/tag/${TAG}"
echo "  - Zenodo: bash scripts/verify-zenodo-release.sh ${VER} --wait"
echo "            https://zenodo.org/doi/10.5281/zenodo.19468134"
echo ""
