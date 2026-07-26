#!/bin/bash
# Sync the local branch with origin/main — the cure for the recurring
# version-line MERGE CONFLICT on the ship PR.
#
# WHY THIS EXISTS
#   Every release bumps the same Version line (go-server/internal/config/config.go).
#   Changes land on main as SQUASH commits that the
#   local branch never receives, so local and main share only an ancient ancestor.
#   A 3-way merge then sees that one line "changed on both sides" -> conflict on
#   EVERY ship. Making local descend from origin/main removes the divergence, so
#   the next ship branch merges cleanly.
#
# WHEN TO RUN
#   After a successful ship (PR merged to main), OR any time the ship PR shows a
#   conflict on config.go. Safe to run anytime.
#
# WHAT IT DOES (native git only — no API ref writes, Repo Sync Law compliant)
#   1. Refuses if the working tree is dirty (never risks uncommitted work).
#   2. Fetches origin/main (read into local tracking only).
#   3. If local already contains main -> nothing to do.
#   4. Otherwise merges main into local. The ONLY expected conflict is the two
#      monotonic version files, auto-resolved in favour of LOCAL (the freshly
#      bumped, higher version). ANY other conflict -> abort + hard stop.
#
# Usage:  bash scripts/sync-local-to-main.sh

cd /home/runner/workspace || exit 1
set -uo pipefail   # pipefail: a failing git fetch must not be masked by a downstream pipe

REPO="IT-Help-San-Diego/dns-tool-intel"
SHIP_BRANCH="main"
GIT_PAT="${GH_SYNC_TOKEN:-${GITHUB_MASTER_PAT:-}}"
VERSION_FILES="go-server/internal/config/config.go"

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=
export GIT_CONFIG_NOSYSTEM=1

if [ -z "$GIT_PAT" ]; then
  echo "ABORT: GH_SYNC_TOKEN secret not set."
  exit 1
fi
PAT_URL="https://${GIT_PAT}@github.com/${REPO}.git"

# ── GATE: must be on a real branch, not detached HEAD ──
if ! LOCAL_BRANCH=$(git symbolic-ref -q --short HEAD 2>/dev/null); then
  echo "  HARD STOP: HEAD is detached (not on a branch). Check out your branch first:"
  echo "    git checkout replit-agent"
  exit 1
fi

echo "=== Sync ${LOCAL_BRANCH} with origin/${SHIP_BRANCH} ==="

# ── GATE: no uncommitted changes to TRACKED files ──
# Untracked files (.local/, *.log, build junk) are deliberately ignored: a merge
# cannot clobber work that git is not tracking, and git itself refuses if a merge
# would overwrite an untracked file. The real danger is staged/unstaged edits to
# tracked files, which a merge could silently fold in — those still hard-stop.
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
  echo ""
  echo "  HARD STOP: tracked files have uncommitted changes."
  echo "  Let the Replit checkpoint commit them (or commit/stash), then re-run."
  git status --short --untracked-files=no 2>/dev/null | sed 's/^/    /'
  exit 1
fi
echo "  PASS — no uncommitted changes to tracked files"

# ── GATE: no interrupted merge/rebase ──
if [ -f ".git/MERGE_HEAD" ] || [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  echo ""
  echo "  HARD STOP: an in-progress merge/rebase was detected."
  echo "  Resolve or abort it first:  git merge --abort   (or)   git rebase --abort"
  exit 1
fi

# ── Fetch main (read-only w.r.t. the remote; writes only local tracking refs) ──
# Capture to a file and test git's OWN exit code directly — a pipe to sed would
# mask a fetch failure (sed exits 0), leaving a STALE FETCH_HEAD that merges the
# wrong commit and falsely reports success.
echo "  Fetching origin/${SHIP_BRANCH} ..."
if ! git fetch "$PAT_URL" "$SHIP_BRANCH" >/tmp/sync_fetch.out 2>&1; then
  sed 's/^/    /' /tmp/sync_fetch.out
  echo ""
  echo "  HARD STOP: fetch failed. Check network and GH_SYNC_TOKEN."
  exit 1
fi
sed 's/^/    /' /tmp/sync_fetch.out

MAIN_SHA=$(git rev-parse FETCH_HEAD 2>/dev/null)
echo "  origin/${SHIP_BRANCH} = ${MAIN_SHA}"

# ── Already up to date? ──
if git merge-base --is-ancestor FETCH_HEAD HEAD 2>/dev/null; then
  echo ""
  echo "  Local already contains origin/${SHIP_BRANCH} — nothing to sync."
  echo "SYNC COMPLETE (no-op)."
  exit 0
fi

# ── Merge main into local ──
echo "  Merging origin/${SHIP_BRANCH} into ${LOCAL_BRANCH} ..."
if git merge --no-edit --no-ff FETCH_HEAD >/tmp/sync_merge.out 2>&1; then
  sed 's/^/    /' /tmp/sync_merge.out
  echo ""
  echo "  Clean merge — local now descends from origin/${SHIP_BRANCH}."
  echo "SYNC COMPLETE."
  exit 0
fi

# Merge stopped with conflicts — only the version files are tolerated.
CONFLICTS="$(git diff --name-only --diff-filter=U 2>/dev/null)"
if [ -z "$CONFLICTS" ]; then
  echo ""
  echo "  HARD STOP: merge failed without listable conflicts. Output:"
  sed 's/^/    /' /tmp/sync_merge.out
  git merge --abort 2>/dev/null
  echo "  Merge aborted (no changes kept)."
  exit 1
fi

UNEXPECTED=""
for f in $CONFLICTS; do
  case " $VERSION_FILES " in
    *" $f "*) : ;;
    *) UNEXPECTED="$UNEXPECTED $f" ;;
  esac
done

if [ -n "$UNEXPECTED" ]; then
  echo ""
  echo "  HARD STOP: unexpected merge conflict(s) outside the version files:"
  echo "   $UNEXPECTED" | tr ' ' '\n' | sed '/^$/d' | sed 's/^/    /'
  git merge --abort 2>/dev/null
  echo "  Merge aborted (no changes kept). Resolve manually, then re-run."
  exit 1
fi

# Defense-in-depth: even within the version files, only tolerate conflicts whose
# conflicting lines are version-related. If a non-version line is in conflict
# (i.e. real upstream code changed the same region), `--ours` would silently drop
# it — so abort and force a manual merge instead.
#   Allowed conflicting content: blank, the Version= line,
#   or a bare semver. Anything else is "real" code -> abort.
for f in $CONFLICTS; do
  CONFLICT_LINES=$(awk '
    /^<<<<<<</ { inblk=1; next }
    /^\|\|\|\|\|\|\|/ { next }
    /^=======$/ { next }
    /^>>>>>>>/ { inblk=0; next }
    inblk { print }
  ' "$f")
  NONVERSION=$(printf '%s\n' "$CONFLICT_LINES" \
    | sed '/^[[:space:]]*$/d' \
    | grep -vE 'Version[[:space:]]*=|^[[:space:]]*"?[0-9]+\.[0-9]+\.[0-9]+' || true)
  if [ -n "$NONVERSION" ]; then
    echo ""
    echo "  HARD STOP: conflict in ${f} touches non-version lines:"
    printf '%s\n' "$NONVERSION" | sed 's/^/    /'
    git merge --abort 2>/dev/null
    echo "  Merge aborted (no changes kept). Resolve manually, then re-run."
    exit 1
  fi
done

# Auto-resolve the monotonic version files in favour of LOCAL (higher version).
echo "  Auto-resolving version-file conflict(s) in favour of local:"
for f in $CONFLICTS; do
  git checkout --ours "$f" 2>/dev/null && git add "$f" 2>/dev/null && echo "    kept local: $f"
done

if [ -n "$(git diff --name-only --diff-filter=U 2>/dev/null)" ]; then
  echo ""
  echo "  HARD STOP: conflicts remain after auto-resolve — aborting."
  git merge --abort 2>/dev/null
  exit 1
fi

if ! git commit --no-edit >/tmp/sync_commit.out 2>&1; then
  echo ""
  echo "  HARD STOP: merge commit failed:"
  sed 's/^/    /' /tmp/sync_commit.out
  git merge --abort 2>/dev/null
  exit 1
fi

LOCAL_VERSION=$(grep -oE 'Version[[:space:]]*=[[:space:]]*"[^"]+"' go-server/internal/config/config.go 2>/dev/null | head -1)
echo ""
echo "  Resolved version files to local; merge committed."
echo "  Local now descends from origin/${SHIP_BRANCH}.  ${LOCAL_VERSION}"
echo "SYNC COMPLETE — next ship will merge cleanly."
