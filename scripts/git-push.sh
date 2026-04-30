#!/bin/bash
# Direct push to GitHub via PAT — the agent's method for pushing dns-tool
# Usage: bash scripts/git-push.sh
#
# The user can also push via the Git panel after running git-panel-reset.sh.
# NEVER push via GitHub API (createBlob/createTree/createCommit/updateRef).
# See SKILL.md "Repo Sync Law" for why.
#
# LOCK FILES: Smart classification — only push-blocking locks (index, HEAD,
# config, shallow) cause HARD STOP. Background locks (maintenance, refs/remotes)
# are logged as INFO and do NOT block the push.
#
# SYNC VERIFICATION uses git ls-remote (read-only) instead of git fetch,
# because the Replit platform blocks .git writes from the agent process tree.
# NOTE: .git/objects/maintenance.lock is EXPECTED to be present — it's
# Replit's background git maintenance, not a stale lock. It does NOT block push.

cd /home/runner/workspace

REPO="IT-Help-San-Diego/dns-tool-intel"
LOCAL_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "replit-agent")
REMOTE_BRANCH="$LOCAL_BRANCH"
SHIP_BRANCH="main"   # The branch that drives CI/SonarCloud/deployments
PUSH_MAIN=1          # Default ON: a successful push must also fast-forward main
GIT_PAT="${GH_SYNC_TOKEN:-${GITHUB_MASTER_PAT:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch) REMOTE_BRANCH="${2:-$LOCAL_BRANCH}"; shift 2 ;;
    --branch=*) REMOTE_BRANCH="${1#*=}"; shift ;;
    --no-main) PUSH_MAIN=0; shift ;;   # Escape hatch: agent-branch only, do NOT touch main
    *) shift ;;
  esac
done

# If user explicitly redirected to a non-default branch, do not also bump main.
if [ "$REMOTE_BRANCH" != "$LOCAL_BRANCH" ]; then
  PUSH_MAIN=0
fi
# If we're already pushing to main as the primary, no second push needed.
if [ "$REMOTE_BRANCH" = "$SHIP_BRANCH" ]; then
  PUSH_MAIN=0
fi

PAT_URL="https://${GIT_PAT}@github.com/${REPO}.git"

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export GIT_CONFIG_NOSYSTEM=1
export GIT_TRACE=0

if [ -z "$GIT_PAT" ]; then
  echo "ABORT: GH_SYNC_TOKEN secret not set"
  exit 1
fi

# ── Pre-flight: verify token is valid ──
echo "=== Token auth check ==="
AUTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${GIT_PAT}" https://api.github.com/user 2>/dev/null || echo "000")
if [ "$AUTH_CHECK" = "200" ]; then
  echo "  PASS — token authenticated"
  REPO_CHECK=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${GIT_PAT}" "https://api.github.com/repos/${REPO}" 2>/dev/null || echo "000")
  if [ "$REPO_CHECK" = "200" ]; then
    echo "  PASS — repo ${REPO} accessible"
  elif [ "$REPO_CHECK" = "000" ] || [ "${REPO_CHECK:0:1}" = "5" ]; then
    echo "  WARN — repo check returned HTTP ${REPO_CHECK} (transient/network issue, continuing)"
  else
    echo ""
    echo "  HARD STOP: Token cannot access ${REPO} (HTTP ${REPO_CHECK})."
    echo "  The token needs 'repo' and 'workflow' scopes for this repository."
    echo "  Generate a new PAT on GitHub and update GH_SYNC_TOKEN in Replit."
    exit 1
  fi
elif [ "$AUTH_CHECK" = "000" ] || [ "${AUTH_CHECK:0:1}" = "5" ]; then
  echo "  WARN — auth check returned HTTP ${AUTH_CHECK} (transient/network issue, continuing)"
else
  echo ""
  echo "  HARD STOP: GH_SYNC_TOKEN returns ${AUTH_CHECK} (authentication failed)."
  echo "  The token is expired, revoked, or invalid. Generate a new PAT on GitHub"
  echo "  and update the GH_SYNC_TOKEN secret in Replit."
  exit 1
fi

# ── GATE 1: Lock files — fail-closed allowlist ──
# Known harmless (allowlisted): maintenance.lock (Replit background), refs/remotes/* (tracking refs)
# Everything else: treated as push-blocking until proven otherwise
echo "=== GATE 1: Lock file check ==="
ALL_LOCKS=$(find .git -name "*.lock" -type f 2>/dev/null || true)
PUSH_BLOCKERS=""
HARMLESS=""

if [ -n "$ALL_LOCKS" ]; then
  while IFS= read -r lockfile; do
    case "$lockfile" in
      .git/objects/maintenance.lock|.git/refs/remotes/*)
        HARMLESS="${HARMLESS}${lockfile}\n"
        ;;
      *)
        PUSH_BLOCKERS="${PUSH_BLOCKERS}${lockfile}\n"
        ;;
    esac
  done <<< "$ALL_LOCKS"
fi

if [ -n "$PUSH_BLOCKERS" ]; then
  echo ""
  echo "  Push-blocking lock file(s) found:"
  echo -e "$PUSH_BLOCKERS" | sed '/^$/d' | sed 's/^/    /'
  echo ""
  echo "  Checking staleness..."
  REPAIR_OK=true
  STALE_COUNT=0
  while IFS= read -r lockfile; do
    if [ -n "$lockfile" ]; then
      LOCK_AGE=$(( $(date +%s) - $(stat -c %Y "$lockfile" 2>/dev/null || echo "$(date +%s)") ))
      LOCK_SIZE=$(stat -c %s "$lockfile" 2>/dev/null || echo "-1")
      if [ "$LOCK_AGE" -ge 30 ] && [ "$LOCK_SIZE" -le 0 ]; then
        if rm -f "$lockfile" 2>/dev/null; then
          echo "    Removed stale lock (${LOCK_AGE}s old, empty): $lockfile"
          STALE_COUNT=$((STALE_COUNT+1))
        else
          echo "    FAILED to remove: $lockfile"
          REPAIR_OK=false
        fi
      else
        echo "    Lock appears active (age: ${LOCK_AGE}s, size: ${LOCK_SIZE}B): $lockfile"
        REPAIR_OK=false
      fi
    fi
  done <<< "$(echo -e "$PUSH_BLOCKERS" | sed '/^$/d')"

  if [ "$REPAIR_OK" = false ]; then
    echo ""
    echo "  HARD STOP: Lock file(s) may be actively held."
    echo "  Wait a moment for any in-flight operation to finish, then run:"
    echo "    bash scripts/git-health-check.sh --repair"
    echo ""
    echo "  Then re-run this push script."
    exit 1
  fi
  echo "  Auto-repair succeeded (removed $STALE_COUNT stale lock(s)) — continuing push."
  echo ""
fi

if [ -n "$HARMLESS" ]; then
  echo "  INFO: Non-blocking lock file(s) present (safe to ignore for push):"
  echo -e "$HARMLESS" | sed '/^$/d' | sed 's/^/    /'
fi
echo "  PASS — no push-blocking locks"

# ── GATE 2: No interrupted rebase ──
echo "=== GATE 2: Rebase state check ==="
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  echo ""
  echo "  HARD STOP: Interrupted rebase detected."
  echo ""
  echo "  Run this in the Shell tab:"
  echo "    bash scripts/git-health-check.sh --repair"
  echo ""
  echo "  Then re-run this push script."
  exit 1
fi
echo "  PASS — no interrupted rebase"

# ── All gates passed ──
echo ""
echo "=== All safety gates passed ==="
echo ""

# ── Pre-push: check what GitHub has vs what we have ──
LOCAL_SHA=$(git rev-parse HEAD 2>/dev/null)
REMOTE_SHA=$(git ls-remote "$PAT_URL" refs/heads/${REMOTE_BRANCH} 2>/dev/null | awk '{print $1}')

if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
  echo "Already synced — local HEAD ($LOCAL_SHA) matches GitHub."
  mkdir -p .gitpanel 2>/dev/null
  echo "$LOCAL_SHA" > .gitpanel/last_pushed_sha 2>/dev/null
  if [ -f ".git/refs/remotes/origin/main.lock" ]; then
    echo ""
    echo "NOTE: Git panel tracking ref is locked. Panel may show stale counts."
    echo "  To fix: run 'bash scripts/git-panel-reset.sh' from the Shell tab."
  fi
  if [ -f "scripts/drift-cairn.sh" ]; then
    bash scripts/drift-cairn.sh snapshot 2>/dev/null || true
  fi
  echo ""
  echo "SYNC STATUS: VERIFIED MATCH"
  exit 0
fi

echo "Local HEAD:  ${LOCAL_SHA}"
echo "GitHub HEAD: ${REMOTE_SHA:-"(unable to read)"}"
echo ""

# ── Show commits to push ──
git log --oneline "${REMOTE_SHA}..HEAD" 2>/dev/null || git log --oneline -5

# ── Push via PAT (with retry for checkpoint race conditions) ──
echo ""
echo "Pushing to github.com/${REPO} ${LOCAL_BRANCH}:${REMOTE_BRANCH}..."
PUSH_OK=0
for ATTEMPT in 1 2; do
  if git push "${PAT_URL}" ${LOCAL_BRANCH}:${REMOTE_BRANCH} 2>&1; then
    PUSH_OK=1
    break
  fi
  if [ "$ATTEMPT" -eq 1 ]; then
    echo "  Push attempt 1 failed — retrying in 15s (checkpoint may be in flight)..."
    sleep 15
  fi
done

if [ "$PUSH_OK" -eq 0 ]; then
  echo ""
  echo "PUSH FAILED after 2 attempts. Troubleshoot:"
  echo "  1. Run 'bash scripts/git-health-check.sh' from Shell tab"
  echo "  2. Check if branches diverged (may need force push — see SKILL.md)"
  echo "  3. Verify PAT is valid: GH_SYNC_TOKEN"
  exit 1
fi

# ── Verify sync via ls-remote (read-only — no .git writes) ──
echo ""
echo "=== Verifying sync (read-only) ==="
POST_PUSH_REMOTE=$(git ls-remote "$PAT_URL" refs/heads/${REMOTE_BRANCH} 2>/dev/null | awk '{print $1}')

# Write marker file (non-.git) so staleness is always detectable
mkdir -p .gitpanel 2>/dev/null
echo "$LOCAL_SHA" > .gitpanel/last_pushed_sha 2>/dev/null

if [ "$LOCAL_SHA" = "$POST_PUSH_REMOTE" ]; then
  echo "  VERIFIED: Local HEAD matches GitHub HEAD."
  echo "  Local:  $LOCAL_SHA"
  echo "  GitHub: $POST_PUSH_REMOTE"
  echo ""
  echo "SYNC STATUS: FULLY SYNCED"
else
  echo "  NOTE: SHA mismatch — a checkpoint commit likely landed during push."
  echo "  Local:  $(git rev-parse HEAD 2>/dev/null)"
  echo "  GitHub: ${POST_PUSH_REMOTE:-"(unable to read)"}"
  echo "  Re-checking in 10s..."
  sleep 10
  NEW_LOCAL=$(git rev-parse HEAD 2>/dev/null)
  NEW_REMOTE=$(git ls-remote "$PAT_URL" refs/heads/${REMOTE_BRANCH} 2>/dev/null | awk '{print $1}')
  if [ "$NEW_LOCAL" != "$NEW_REMOTE" ]; then
    echo "  Still mismatched — pushing new checkpoint..."
    git push "${PAT_URL}" ${LOCAL_BRANCH}:${REMOTE_BRANCH} 2>&1 || true
    FINAL_REMOTE=$(git ls-remote "$PAT_URL" refs/heads/${REMOTE_BRANCH} 2>/dev/null | awk '{print $1}')
    FINAL_LOCAL=$(git rev-parse HEAD 2>/dev/null)
    if [ "$FINAL_LOCAL" = "$FINAL_REMOTE" ]; then
      echo "  VERIFIED after retry: Local matches GitHub."
      echo ""
      echo "SYNC STATUS: FULLY SYNCED (after retry)"
    else
      echo "  Local and GitHub still differ. A new checkpoint may keep landing."
      echo "  Run 'bash scripts/git-push.sh' again once activity settles."
      echo ""
      echo "SYNC STATUS: PENDING"
    fi
  else
    echo "  VERIFIED on recheck: Local matches GitHub."
    echo ""
    echo "SYNC STATUS: FULLY SYNCED"
  fi
fi
# ── Ship to main (the branch CI/SonarCloud/deployments actually use) ──
# Branch protection rule on main allows our bypass actor to fast-forward
# directly. Without this step the agent-branch advances but main lags,
# which is the exact bug that caused dev-bump v26.46.02 to be missed.
if [ "$PUSH_MAIN" -eq 1 ]; then
  echo ""
  echo "=== Shipping to ${SHIP_BRANCH} (CI/deployment branch) ==="
  SHIP_REMOTE_BEFORE=$(git ls-remote "$PAT_URL" refs/heads/${SHIP_BRANCH} 2>/dev/null | awk '{print $1}')
  SHIP_LOCAL=$(git rev-parse HEAD 2>/dev/null)

  if [ "$SHIP_LOCAL" = "$SHIP_REMOTE_BEFORE" ]; then
    echo "  Already at ${SHIP_BRANCH}: $SHIP_LOCAL"
    echo "SHIP STATUS: ALREADY CURRENT"
  else
    echo "  Local:        $SHIP_LOCAL"
    echo "  ${SHIP_BRANCH} before: ${SHIP_REMOTE_BEFORE:-"(unable to read)"}"
    SHIP_OK=0
    for ATTEMPT in 1 2; do
      if git push "${PAT_URL}" ${LOCAL_BRANCH}:${SHIP_BRANCH} 2>&1; then
        SHIP_OK=1
        break
      fi
      if [ "$ATTEMPT" -eq 1 ]; then
        echo "  Ship attempt 1 failed — retrying in 10s..."
        sleep 10
      fi
    done

    if [ "$SHIP_OK" -eq 0 ]; then
      echo ""
      echo "SHIP FAILED: agent-branch is on GitHub but ${SHIP_BRANCH} was NOT updated."
      echo "  Possible causes: non-fast-forward (someone else pushed), token bypass"
      echo "  expired, or branch protection changed. Recover with:"
      echo "    git push origin ${LOCAL_BRANCH}:${SHIP_BRANCH}"
      echo "  Or open a PR. Use --no-main on this script to skip this step."
      exit 1
    fi

    SHIP_REMOTE_AFTER=$(git ls-remote "$PAT_URL" refs/heads/${SHIP_BRANCH} 2>/dev/null | awk '{print $1}')
    if [ "$SHIP_LOCAL" = "$SHIP_REMOTE_AFTER" ]; then
      echo "  VERIFIED: ${SHIP_BRANCH} now at $SHIP_LOCAL"
      echo "SHIP STATUS: FULLY SYNCED"
    else
      echo "  WARNING: ${SHIP_BRANCH} did not advance to expected SHA."
      echo "  Local:  $SHIP_LOCAL"
      echo "  GitHub: ${SHIP_REMOTE_AFTER:-"(unable to read)"}"
      echo "SHIP STATUS: PENDING — re-run script."
      exit 1
    fi
  fi
else
  echo ""
  echo "=== Skipping ${SHIP_BRANCH} ship (--no-main or non-default --branch) ==="
fi

# ── Git panel staleness check ──
if [ -f ".git/refs/remotes/origin/main.lock" ]; then
  echo ""
  echo "NOTE: Git panel tracking ref is locked (.git/refs/remotes/origin/main.lock)"
  echo "  The Git panel may show stale 'X commits ahead' even though GitHub is current."
  echo "  To fix: run 'bash scripts/git-panel-reset.sh' from the Shell tab."
fi

# ── Drift Cairn snapshot (record current state after push) ──
if [ -f "scripts/drift-cairn.sh" ]; then
  bash scripts/drift-cairn.sh snapshot 2>/dev/null || true
fi

echo ""
echo "PUSH COMPLETE."
