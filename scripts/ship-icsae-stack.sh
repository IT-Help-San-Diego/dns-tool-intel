#!/usr/bin/env bash
#
# One-shot shipper for the unmerged ICSAE stack (S1-S3 + icae calibration fix).
# Pushes the current workspace branch to a FRESH remote branch, opens a PR to
# main, and arms rebase auto-merge (GitHub re-signs commits on merge and waits
# for required checks). Leaves the unrelated open PR #98 untouched.
#
# Usage:  bash scripts/ship-icsae-stack.sh
#
set -euo pipefail

REPO="IT-Help-San-Diego/dns-tool-intel"
BRANCH="ship/icsae-bridge-remediation-queue"
export GH_TOKEN="${GH_SYNC_TOKEN:?GH_SYNC_TOKEN is not set in this shell}"

echo "==============================================="
echo "  Shipping ICSAE stack -> main via fresh branch"
echo "==============================================="

echo "▸ [1/2] Pushing current HEAD to fresh branch: $BRANCH"
git push origin "HEAD:${BRANCH}"

echo "▸ [2/2] Branch is up. (The automation token cannot open PRs, so finish in the browser.)"
echo ""
echo "✓ Pushed. Open this link and click 'Create pull request', then 'Rebase and merge':"
echo ""
echo "    https://github.com/${REPO}/compare/main...${BRANCH}?expand=1"
echo ""
echo "  Base = main, compare = ${BRANCH}. After the required checks go green, use the"
echo "  'Rebase and merge' button (GitHub re-signs the commits, satisfying branch protection)."
echo ""
echo "PR #98 (the May 31 confidence_gap_lab.py) is independent and optional — its fix"
echo "already lives in go-server/internal/icae/priors.go. Merge or close it whenever."
