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

echo "▸ [1/3] Pushing current HEAD to fresh branch: $BRANCH"
git push origin "HEAD:${BRANCH}"

echo "▸ [2/3] Opening PR -> main (reusing existing PR if one already exists)"
PR_URL="$(gh pr create --repo "$REPO" --base main --head "$BRANCH" \
  --title "ICSAE bridge + reality-matched classifier + prioritized remediation queue (v26.49.01)" \
  --body "Ships the unmerged ICSAE Go bridge (S1-S3): weakness taxonomy refs, reality-matched classifier, prioritized remediation queue + ICD-203 confidence, plus the icae evidence-weighted /confidence calibration fix (priors.go). Local descends from the current main tip, so the diff is exactly the unshipped delta. Independent of PR #98." \
  2>/dev/null || gh pr view "$BRANCH" --repo "$REPO" --json url --jq .url)"
echo "    PR: $PR_URL"

echo "▸ [3/3] Arming rebase auto-merge (waits for required checks, then merges)"
if gh pr merge "$BRANCH" --repo "$REPO" --rebase --auto; then
  echo ""
  echo "✓ Done. Auto-merge is armed. The PR rebase-merges into main automatically"
  echo "  once the required checks (Build & Test, Code Quality, Off-site Backup,"
  echo "  CodeQL) pass. Nothing else for you to do."
else
  echo ""
  echo "⚠ Could not arm --auto (repo may not have auto-merge enabled)."
  echo "  Once the checks on the PR go green, finish it with:"
  echo "      gh pr merge \"$BRANCH\" --repo \"$REPO\" --rebase"
fi

echo ""
echo "PR #98 (the May 31 confidence_gap_lab.py) is left untouched and is optional."
echo "  Its fix already lives in go-server/internal/icae/priors.go. When you're"
echo "  ready, keep it:   gh pr review 98 --repo \"$REPO\" --approve && gh pr merge 98 --repo \"$REPO\" --rebase"
echo "  or close it:      gh pr close 98 --repo \"$REPO\" --comment \"Fix already in icae/priors.go; closing to free the replit-agent branch.\""
