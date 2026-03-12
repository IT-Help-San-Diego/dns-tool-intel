#!/bin/bash
# Git sync — push replit-agent commits to main via GitHub PR.
# Usage: bash scripts/git-sync.sh
#
# Pre-flight → push → create PR → merge → sync back.
# Preserves full commit history (merge commit, no squash).
# Uses GITHUB_MASTER_PAT for GitHub API authentication.
#
# Safe to run anytime. Fails loudly on any problem.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_OWNER="careyjames"
REPO_NAME="dns-tool-web"
BRANCH_SOURCE="replit-agent"
BRANCH_TARGET="main"
API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}▸${NC} $1"; }

TOKEN="${GITHUB_MASTER_PAT:-}"
if [ -z "$TOKEN" ]; then
  fail "GITHUB_MASTER_PAT not set. Cannot authenticate with GitHub."
fi
PAT_REMOTE="https://${TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.git"

VERSION=$(grep 'Version.*=' go-server/internal/config/config.go | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "═══════════════════════════════════════════"
echo "  Git Sync: ${BRANCH_SOURCE} → ${BRANCH_TARGET}"
echo "  App version: v${VERSION}"
echo "═══════════════════════════════════════════"
echo ""

info "Pre-flight checks"

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ "$CURRENT_BRANCH" != "$BRANCH_SOURCE" ]; then
  fail "Not on ${BRANCH_SOURCE} branch (on: ${CURRENT_BRANCH})"
fi
pass "On ${BRANCH_SOURCE} branch"

if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  fail "Working tree is dirty. Commit or stash changes first."
fi
pass "Working tree clean"

for LOCKFILE in .git/index.lock .git/shallow.lock .git/refs/heads/*.lock; do
  if [ -f "$LOCKFILE" ] 2>/dev/null; then
    LOCK_AGE=$(( $(date +%s) - $(stat -c %Y "$LOCKFILE" 2>/dev/null || stat -f %m "$LOCKFILE" 2>/dev/null || echo "0") ))
    if [ "$LOCK_AGE" -gt 30 ]; then
      echo -e "  ${YELLOW}⚠${NC} Removing stale lock: ${LOCKFILE} (${LOCK_AGE}s old)"
      rm -f "$LOCKFILE"
    else
      fail "Active lock file: ${LOCKFILE} (${LOCK_AGE}s old). Git operation in progress?"
    fi
  fi
done
pass "No git lock files"

info "Fetching latest from origin"
timeout 30 git fetch origin --prune 2>/dev/null || fail "git fetch timed out or failed"
pass "Fetched origin"

LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git rev-parse "origin/${BRANCH_SOURCE}" 2>/dev/null || echo "none")
if [ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]; then
  info "Local ${BRANCH_SOURCE} differs from origin — pushing"
  timeout 30 git push "${PAT_REMOTE}" "${BRANCH_SOURCE}" 2>&1 || fail "git push failed"
  pass "Pushed to origin/${BRANCH_SOURCE}"
else
  pass "Local and origin/${BRANCH_SOURCE} in sync"
fi

AHEAD=$(git rev-list --count "origin/${BRANCH_TARGET}..origin/${BRANCH_SOURCE}" 2>/dev/null || echo "0")
if [ "$AHEAD" -eq 0 ]; then
  pass "Nothing to merge — ${BRANCH_SOURCE} and ${BRANCH_TARGET} are in sync"
  echo ""
  echo "All good. Nothing to do."
  exit 0
fi
pass "${AHEAD} commit(s) ahead of ${BRANCH_TARGET}"

echo ""
info "Creating pull request"

EXISTING_PR=$(curl -sf -H "Authorization: token ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${API}/pulls?head=${REPO_OWNER}:${BRANCH_SOURCE}&base=${BRANCH_TARGET}&state=open" \
  2>/dev/null | python3 -c "import sys,json; prs=json.load(sys.stdin); print(prs[0]['number'] if prs else '')" 2>/dev/null || echo "")

if [ -n "$EXISTING_PR" ]; then
  PR_NUMBER="$EXISTING_PR"
  pass "Using existing PR #${PR_NUMBER}"
else
  PR_TITLE="Merge ${BRANCH_SOURCE}: v${VERSION} — ${AHEAD} commits"
  COMMITS=$(git log --oneline "origin/${BRANCH_TARGET}..origin/${BRANCH_SOURCE}" | head -20)

  TMPFILE=$(mktemp)
  trap "rm -f $TMPFILE" EXIT
  python3 -c "
import json, sys
title = sys.argv[1]
commits = sys.argv[2]
ahead = sys.argv[3]
branch_src = sys.argv[4]
branch_tgt = sys.argv[5]
version = sys.argv[6]
body = f'Automated sync from \`{branch_src}\` to \`{branch_tgt}\`.\n\n'
body += f'**Version**: v{version}\n**Commits**: {ahead}\n\n'
body += f'\`\`\`\n{commits}\n\`\`\`'
print(json.dumps({'title': title, 'head': branch_src, 'base': branch_tgt, 'body': body}))
" "$PR_TITLE" "$COMMITS" "$AHEAD" "$BRANCH_SOURCE" "$BRANCH_TARGET" "$VERSION" > "$TMPFILE"

  PR_RESPONSE=$(curl -sf -X POST \
    -H "Authorization: token ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${API}/pulls" \
    -d @"$TMPFILE" \
    2>/dev/null) || fail "Failed to create PR. Check token permissions."

  PR_NUMBER=$(echo "$PR_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['number'])" 2>/dev/null)
  if [ -z "$PR_NUMBER" ]; then
    echo "$PR_RESPONSE"
    fail "PR creation returned unexpected response"
  fi
  pass "Created PR #${PR_NUMBER}: ${PR_TITLE}"
fi

echo ""
info "Merging PR #${PR_NUMBER}"

sleep 2

MERGE_RESPONSE=$(curl -sf -X PUT \
  -H "Authorization: token ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${API}/pulls/${PR_NUMBER}/merge" \
  -d "{\"merge_method\": \"merge\", \"commit_title\": \"Merge pull request #${PR_NUMBER} from ${REPO_OWNER}/${BRANCH_SOURCE}\"}" \
  2>/dev/null) || fail "Merge failed. Check branch protection rules or merge conflicts."

MERGED=$(echo "$MERGE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('merged', False))" 2>/dev/null)
if [ "$MERGED" != "True" ]; then
  fail "Merge response did not confirm success"
fi
pass "PR #${PR_NUMBER} merged to ${BRANCH_TARGET}"

echo ""
info "Syncing ${BRANCH_TARGET} back to ${BRANCH_SOURCE}"

timeout 30 git fetch origin "${BRANCH_TARGET}" 2>/dev/null || fail "Failed to fetch updated ${BRANCH_TARGET}"
timeout 30 git merge --ff-only "origin/${BRANCH_TARGET}" 2>/dev/null || {
  echo -e "  ${YELLOW}⚠${NC} Fast-forward failed — pulling with merge"
  timeout 30 git pull origin "${BRANCH_TARGET}" --no-edit 2>/dev/null || fail "Reverse sync failed"
}
pass "Synced ${BRANCH_TARGET} → ${BRANCH_SOURCE}"

timeout 30 git push "${PAT_REMOTE}" "${BRANCH_SOURCE}" 2>/dev/null || echo -e "  ${YELLOW}⚠${NC} Push after sync skipped (may need manual push)"

echo ""
echo "═══════════════════════════════════════════"
echo -e "  ${GREEN}Done.${NC} v${VERSION} is on ${BRANCH_TARGET}."
echo "═══════════════════════════════════════════"
echo ""
