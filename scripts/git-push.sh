#!/bin/bash
# Push to GitHub via PAT — seL4-grade PR-based ship flow.
# Usage:
#   bash scripts/git-push.sh           # push branch + open PR + auto-merge on green checks
#   bash scripts/git-push.sh --no-main # push branch only (no PR, no ship)
#   bash scripts/git-push.sh --branch X # push to a non-default remote branch (implies --no-main)
#
# THE LAW: NEVER push via GitHub API (createBlob/createTree/createCommit/
# updateRef/POST /merges) — only standard `git push` + `gh pr` commands.
# See .agents/skills/dns-tool/SKILL.md "Repo Sync Law" rule #3.
#
# Branch protection on `main` (enabled 2026-05-16) physically rejects direct
# pushes. The PR flow is the ONLY way to land changes on main.
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

# ════════════════════════════════════════════════════════════════════════════
# EPHEMERAL-BRANCH SHIP MODEL (2026-06-08) — the permanent fix for
# "! [rejected] ... (fetch first)" non-fast-forward push failures.
#
# OLD (broken): always pushed the workspace HEAD onto a PERSISTENT remote branch
#   (replit-agent). Because every merge to main is a SQUASH (a brand-new commit
#   the local branch never contains) while Replit keeps adding checkpoint commits
#   locally, the local branch and the persistent remote branch inevitably DIVERGE
#   -> non-fast-forward -> retries forever. A single stale orphan branch poisons
#   every future ship.
#
# NEW (durable): push the workspace HEAD to a FRESH, uniquely-named remote branch
#   each run. A brand-new branch has nothing to diverge from, so the push can
#   never be rejected non-fast-forward. The branch is then squash-merged into
#   main (GitHub signs the squash commit -> main stays verified) and auto-deleted.
#   No persistent feature branch, no divergence, ever.
#
# TOKENS: the git PUSH uses GH_SYNC_TOKEN (push scope). The PR lifecycle
#   (create + enable auto-merge) needs PR scope, which GH_SYNC_TOKEN lacks
#   ("createPullRequest: Resource not accessible"), so ALL_GH (owner token) is
#   used ONLY for the gh PR calls. These are repo/PR API operations, NOT git-ref
#   writes — compliant with the Repo Sync Law (no createCommit/updateRef/merges).
# ════════════════════════════════════════════════════════════════════════════

LOCAL_SHA=$(git rev-parse HEAD 2>/dev/null)
STAMP="$(date -u +%Y%m%d-%H%M%S)"
SHORT_SHA="$(git rev-parse --short=9 HEAD 2>/dev/null)"

# Decide the fresh remote branch name.
if [ "$REMOTE_BRANCH" != "$LOCAL_BRANCH" ]; then
  # User passed --branch X explicitly: honor it verbatim (advanced/manual use).
  TARGET_REMOTE_BRANCH="$REMOTE_BRANCH"
elif [ "$PUSH_MAIN" -eq 1 ]; then
  TARGET_REMOTE_BRANCH="ship/${STAMP}-${SHORT_SHA}"      # ships to main, auto-deleted on merge
else
  TARGET_REMOTE_BRANCH="snapshot/${STAMP}-${SHORT_SHA}"  # backup only (--no-main)
fi

# ── Idempotency guard: if an open PR already ships this EXACT HEAD, reuse it ──
# Without this, re-running after a SHIP TIMEOUT would open a duplicate ship/* PR
# every time. We match on headRefOid (the pushed commit), so a re-run for the same
# workspace state resumes the in-flight PR instead of cluttering the repo.
REUSE_PR=""
if [ "$PUSH_MAIN" -eq 1 ] && [ "$REMOTE_BRANCH" = "$LOCAL_BRANCH" ] && [ -n "${ALL_GH:-}" ] && command -v gh >/dev/null 2>&1; then
  REUSE_PR=$(GH_TOKEN="$ALL_GH" gh pr list -R "$REPO" --base "$SHIP_BRANCH" --state open \
    --json number,headRefOid --jq "map(select(.headRefOid==\"$LOCAL_SHA\"))|.[0].number" 2>/dev/null)
  [ "$REUSE_PR" = "null" ] && REUSE_PR=""
fi

# ── Empty-ship guard: refuse a redundant no-op PR when local already == main ──
# After a squash-merge, main gains a commit the local branch never receives, so
# SHA equality never holds again — but the content (git TREE) is identical. If
# local HEAD's tree == main's tip tree there is nothing new to ship. Re-running in
# that state previously opened back-to-back no-op PRs that still squash-merged
# (the duplicate ships #124/#125/#126). Tree SHAs are content-addressed, so this
# catches it regardless of divergent commit history. Best-effort: skipped silently
# if gh/token/API are unavailable so a legitimate ship is never blocked.
if [ "$PUSH_MAIN" -eq 1 ] && [ -z "$REUSE_PR" ] && command -v gh >/dev/null 2>&1; then
  LOCAL_TREE=$(git rev-parse "HEAD^{tree}" 2>/dev/null)
  MAIN_TREE=$(GH_TOKEN="${ALL_GH:-$GIT_PAT}" gh api "repos/${REPO}/commits/${SHIP_BRANCH}" --jq '.commit.tree.sha' 2>/dev/null)
  if [ -n "$LOCAL_TREE" ] && [ -n "$MAIN_TREE" ] && [ "$LOCAL_TREE" = "$MAIN_TREE" ]; then
    echo ""
    echo "=== Nothing to ship ==="
    echo "  Local working tree already matches origin/${SHIP_BRANCH} (identical content)."
    echo "  Opening a PR now would create a redundant no-op merge — aborting."
    echo ""
    echo "  If you expected local commits to land, your branch is behind main."
    echo "  Re-sync, then make your change:  bash scripts/sync-local-to-main.sh"
    exit 0
  fi
fi

echo "Workspace HEAD:      ${LOCAL_SHA}"
if [ -n "$REUSE_PR" ]; then
  echo "In-flight PR:        #${REUSE_PR} (already ships this exact HEAD — reusing, no new branch)"
else
  echo "Fresh remote branch: ${TARGET_REMOTE_BRANCH}"
fi
echo ""
git log --oneline -5 2>/dev/null

# ── Push to the fresh branch (skipped when reusing an in-flight PR) ──
if [ -z "$REUSE_PR" ]; then
  echo ""
  echo "Pushing ${LOCAL_BRANCH} → ${TARGET_REMOTE_BRANCH} ..."
  PUSH_OK=0
  for ATTEMPT in 1 2; do
    if git push "${PAT_URL}" "${LOCAL_BRANCH}:${TARGET_REMOTE_BRANCH}" 2>&1; then
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
    echo "  2. Verify PAT is valid: GH_SYNC_TOKEN"
    exit 1
  fi

  # ── Verify the branch landed (read-only ls-remote, no .git writes) ──
  mkdir -p .gitpanel 2>/dev/null
  echo "$LOCAL_SHA" > .gitpanel/last_pushed_sha 2>/dev/null
  POST_PUSH_REMOTE=$(git ls-remote "$PAT_URL" "refs/heads/${TARGET_REMOTE_BRANCH}" 2>/dev/null | awk '{print $1}')
  if [ "$LOCAL_SHA" = "$POST_PUSH_REMOTE" ]; then
    echo "  VERIFIED: ${TARGET_REMOTE_BRANCH} = ${LOCAL_SHA}"
  else
    echo "  NOTE: branch tip (${POST_PUSH_REMOTE:-unknown}) != local (${LOCAL_SHA}) —"
    echo "        a checkpoint likely landed during push; the PR will reflect the pushed tip."
  fi
fi

# ── Branch-only mode: stop here, print the compare link ──
if [ "$PUSH_MAIN" -ne 1 ]; then
  echo ""
  echo "=== Branch-only push complete (no PR) ==="
  echo "  Branch:  ${TARGET_REMOTE_BRANCH}"
  echo "  Compare: https://github.com/${REPO}/compare/${SHIP_BRANCH}...${TARGET_REMOTE_BRANCH}?expand=1"
  if [ -f "scripts/drift-cairn.sh" ]; then
    bash scripts/drift-cairn.sh snapshot 2>/dev/null || true
  fi
  echo ""
  echo "PUSH COMPLETE."
  exit 0
fi

# ── Ship to main via PR + SQUASH auto-merge ──
# Squash is the ONLY method that lands a GitHub-signed (verified) commit on main;
# rebase/merge carry Replit's unsigned commits and are rejected. Squash-only is
# enforced at the repo + ruleset level and guarded by scripts/check-merge-policy.sh.
GH_PR_TOKEN="${ALL_GH:-}"
if [ -z "$GH_PR_TOKEN" ]; then
  echo ""
  echo "Branch pushed, but ALL_GH (PR-capable token) is not set — cannot open/merge the PR."
  echo "  Open it manually (Squash and merge):"
  echo "  https://github.com/${REPO}/compare/${SHIP_BRANCH}...${TARGET_REMOTE_BRANCH}?expand=1"
  exit 1
fi
export GH_TOKEN="$GH_PR_TOKEN"
if ! command -v gh >/dev/null 2>&1; then
  echo ""
  echo "ABORT: gh CLI not found. Install: https://cli.github.com/"
  exit 1
fi

if [ -n "$REUSE_PR" ]; then
  PR_NUM="$REUSE_PR"
  echo ""
  echo "=== Resuming PR #${PR_NUM} → ${SHIP_BRANCH} (squash) ==="
else
  echo ""
  echo "=== Shipping ${TARGET_REMOTE_BRANCH} → ${SHIP_BRANCH} via PR (squash) ==="
  # Pin PR title/body to the SHA we actually pushed ($LOCAL_SHA), not HEAD — a
  # checkpoint may have landed locally after the push.
  PR_TITLE="$(git log -1 --pretty=%s "$LOCAL_SHA" 2>/dev/null)"
  PR_BODY="$(git log -10 --pretty='- %s' "$LOCAL_SHA" 2>/dev/null)"
  [ -z "$PR_TITLE" ] && PR_TITLE="ship: ${TARGET_REMOTE_BRANCH}"
  [ -z "$PR_BODY" ] && PR_BODY="(auto-opened by scripts/git-push.sh)"
  PR_URL=$(gh pr create -R "$REPO" --base "$SHIP_BRANCH" --head "$TARGET_REMOTE_BRANCH" \
    --title "$PR_TITLE" --body "$PR_BODY" 2>&1)
  PR_NUM=$(echo "$PR_URL" | grep -oE 'pull/[0-9]+' | head -1 | cut -d/ -f2)
  if [ -z "$PR_NUM" ]; then
    echo "  ERROR creating PR:"
    echo "  $PR_URL"
    echo ""
    echo "  Open it manually (Squash and merge):"
    echo "  https://github.com/${REPO}/compare/${SHIP_BRANCH}...${TARGET_REMOTE_BRANCH}?expand=1"
    exit 1
  fi
  echo "  PR #${PR_NUM}: $PR_URL"
fi

# ── Close SUPERSEDED ship PRs (the missing cleanup that made success look like
#    failure) ──────────────────────────────────────────────────────────────────
# The ephemeral-branch model means only the CURRENT ship PR is ever valid: each
# run pushes a brand-new ship/<ts>-<sha> branch. But a PRIOR run can leave an open
# PR behind — e.g. a first attempt opens PR #N, then main advances (another squash
# lands), so #N goes CONFLICTING/DIRTY and can never merge. The follow-up
# sync+reship opens PR #N+1 which merges cleanly — yet #N stays OPEN and
# CONFLICTING forever. The operator keeps looking at the dead #N and concludes
# "the ship failed / CI is broken" when it actually SUCCEEDED on #N+1.
# Fix: the moment we have our live PR (#PR_NUM), close every OTHER open ship/* PR
# on this base and delete its ephemeral branch. Exactly one live ship PR is ever
# visible, so a stale conflicting PR can no longer masquerade as a failure.
# (gh pr close is a PR-state API op and --delete-branch targets only the ephemeral
#  ship/* head ref — never main — so this stays within the established ship flow
#  and the Repo Sync Law, identical to the --delete-branch already used on merge.)
echo "  Closing any superseded ship PRs (ephemeral model — only #${PR_NUM} is live) ..."
SUPERSEDED=$(gh pr list -R "$REPO" --base "$SHIP_BRANCH" --state open \
  --json number,headRefName \
  --jq "map(select(.number!=${PR_NUM} and (.headRefName|startswith(\"ship/\"))))|.[].number" 2>/dev/null || true)
if [ -n "$SUPERSEDED" ]; then
  for OLD in $SUPERSEDED; do
    gh pr close -R "$REPO" "$OLD" --delete-branch \
      --comment "Superseded by #${PR_NUM} (ephemeral ship branch replaced by a fresh, conflict-free ship)." \
      >/dev/null 2>&1 && echo "    Closed superseded PR #${OLD} (+ deleted its branch)" \
      || echo "    NOTE: could not close stale PR #${OLD} (close it manually: gh pr close ${OLD})"
  done
else
  echo "    None — clean."
fi

echo "  Enabling auto-merge (squash — GitHub signs the commit on main) ..."
MERGE_OUT=$(gh pr merge -R "$REPO" "$PR_NUM" --auto --squash --delete-branch 2>&1) || true
[ -n "$MERGE_OUT" ] && echo "$MERGE_OUT" | sed 's/^/    /'
# Fail fast on NON-transient errors (bad token scope, conflicts, policy). Tolerate
# the benign cases: auto-merge already enabled, or PR already in a clean/queued state.
if echo "$MERGE_OUT" | grep -qiE 'not accessible|not authorized|forbidden|protected|conflict|not mergeable|cannot be merged'; then
  if ! echo "$MERGE_OUT" | grep -qiE 'already|clean status|set to be merged|enabled auto'; then
    echo ""
    echo "SHIP FAILED — auto-merge could not be armed (non-transient error above)."
    echo "  Inspect: gh pr view -R $REPO $PR_NUM --web"
    exit 1
  fi
fi

# ── Poll until merged, or a required check fails ──
echo ""
echo "  Waiting for required checks + auto-merge (max 15min)..."
MAX_WAIT=900
POLL=20
ELAPSED=0
MERGED=false
CONFLICT_SEEN=0
MISS=0
MISS_MAX=6
while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
  # Query merged + state + mergeable together. Breaking only on merged=="true" meant
  # a single transient/empty gh read left the loop polling to the full timeout even
  # though the PR had already merged (the 12-min hang). state=="MERGED" is a second,
  # independent merged signal; an empty read just falls through to the next poll.
  PR_STATE=$(gh pr view -R "$REPO" "$PR_NUM" --json merged,state,mergeable --jq '[.merged,.state,.mergeable]|@tsv' 2>/dev/null)
  # Transient GitHub/gh failure (empty read): a single miss is harmless, but do not
  # let a sustained API outage silently ride to the full 15-min timeout — that is the
  # other "stuck on git push" face. Bail after MISS_MAX consecutive empty reads (~2min)
  # with an honest "API transient" message rather than a fake merge-failure.
  if [ -z "$PR_STATE" ]; then
    MISS=$((MISS + 1))
    if [ "$MISS" -ge "$MISS_MAX" ]; then
      echo ""
      echo "SHIP UNCERTAIN — GitHub returned no PR status for ${MISS} consecutive polls (~$((MISS * POLL))s)."
      echo "  Almost certainly a transient gh/GitHub API problem, NOT a code or merge failure."
      echo "  Check manually: gh pr view -R $REPO $PR_NUM"
      echo "  Auto-merge stays armed; safe to re-run once GitHub recovers: bash scripts/git-push.sh"
      exit 1
    fi
    sleep "$POLL"; ELAPSED=$((ELAPSED + POLL)); printf "    waited %ds (api retry %d/%d) ...\r" "$ELAPSED" "$MISS" "$MISS_MAX"
    continue
  fi
  MISS=0
  MERGED=$(printf '%s' "$PR_STATE" | cut -f1)
  STATE=$(printf '%s' "$PR_STATE" | cut -f2)
  MERGEABLE=$(printf '%s' "$PR_STATE" | cut -f3)
  if [ "$MERGED" = "true" ] || [ "$STATE" = "MERGED" ]; then
    MERGED=true
    break
  fi
  # PR closed without merging (e.g. superseded/manually closed) — stop now instead
  # of sleeping to the timeout waiting for a merge that will never happen.
  if [ "$STATE" = "CLOSED" ]; then
    echo ""
    echo "SHIP HALTED — PR #${PR_NUM} was closed without merging."
    echo "  Inspect: gh pr view -R $REPO $PR_NUM --web"
    exit 1
  fi
  # PR has a merge conflict against the base — auto-merge can NEVER fire, so do not
  # burn the full 15-min timeout waiting for a merge that will never happen (this was
  # the stuck-on-push failure mode). mergeable=="CONFLICTING" is a settled state, but
  # require it twice consecutively (~40s) to ride out the brief UNKNOWN/null window
  # GitHub reports while it is still computing mergeability on a freshly-opened PR.
  if [ "$MERGEABLE" = "CONFLICTING" ]; then
    CONFLICT_SEEN=$((CONFLICT_SEEN + 1))
    if [ "$CONFLICT_SEEN" -ge 2 ]; then
      echo ""
      echo "SHIP HALTED — PR #${PR_NUM} has a merge conflict against ${SHIP_BRANCH}; auto-merge cannot fire."
      echo "  This is almost always the version-file conflict (config.go / sonar-project.properties)."
      echo "  Fix: bash scripts/sync-local-to-main.sh   # merges main into local, resolves version files"
      echo "  Then re-run: bash scripts/git-push.sh      # fresh branch, clean PR, supersedes #${PR_NUM}"
      echo "  Inspect: gh pr view -R $REPO $PR_NUM --web"
      exit 1
    fi
  else
    CONFLICT_SEEN=0
  fi
  FAILED=$(gh pr checks -R "$REPO" "$PR_NUM" --required 2>/dev/null | grep -iE '\bfail(ing|ed|ure)?\b' | head -3 || true)
  if [ -n "$FAILED" ]; then
    echo ""
    echo "SHIP FAILED — required check(s) failed:"
    echo "$FAILED"
    echo ""
    echo "  Inspect: gh pr view -R $REPO $PR_NUM --web"
    echo "  Fix, then re-run: bash scripts/git-push.sh (a new ship branch will be created)."
    exit 1
  fi
  sleep "$POLL"
  ELAPSED=$((ELAPSED + POLL))
  printf "    waited %ds ...\r" "$ELAPSED"
done

if [ "$MERGED" != "true" ]; then
  echo ""
  echo "SHIP TIMEOUT after ${MAX_WAIT}s. PR #${PR_NUM} not yet merged."
  echo "  Status: gh pr view -R $REPO $PR_NUM"
  echo "  Auto-merge stays armed — it will merge when checks pass. Safe to re-run."
  exit 1
fi

sleep 3  # allow GitHub to update the ref
SHIP_REMOTE_AFTER=$(git ls-remote "$PAT_URL" "refs/heads/${SHIP_BRANCH}" 2>/dev/null | awk '{print $1}')
echo ""
echo "  PR #${PR_NUM} MERGED ✓ (squash, GitHub-signed)"
echo "  ${SHIP_BRANCH} now: ${SHIP_REMOTE_AFTER}"
echo "SHIP STATUS: MERGED — ship branch deleted, main updated."

# ── Auto re-sync local onto the new main (closes the duplicate-ship loop) ──
# Skipping this manual step is what produced back-to-back duplicate ship PRs: local
# stayed behind main, so the next run re-shipped the same delta as a no-op merge.
# Running it here makes a clean ship leave a clean local. Best-effort and safe:
# sync hard-stops cleanly (and changes nothing) on a dirty tree, detached HEAD, or
# any non-version conflict — it can never corrupt the merge that already landed.
if [ -f "scripts/sync-local-to-main.sh" ]; then
  echo ""
  echo "=== Re-syncing local onto origin/${SHIP_BRANCH} (post-merge) ==="
  if bash scripts/sync-local-to-main.sh; then
    echo "  Local re-synced — the next ship will start clean."
  else
    echo "  NOTE: auto-sync did not complete (reason above). Run it manually before"
    echo "        the next ship:  bash scripts/sync-local-to-main.sh"
  fi
fi

# ── Drift Cairn snapshot (record current state after ship) ──
if [ -f "scripts/drift-cairn.sh" ]; then
  bash scripts/drift-cairn.sh snapshot 2>/dev/null || true
fi

echo ""
echo "PUSH COMPLETE."
