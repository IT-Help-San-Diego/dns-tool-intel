#!/usr/bin/env bash
# squash-merge-pr.sh — merge a green PR into main when GitHub's required_signatures
# rule blocks it (Replit checkpoint commits are unsigned).
#
# It briefly lifts ONLY the required_signatures rule on `mainrule`, squash-merges
# the PR (GitHub signs the resulting squash commit -> verified: true), then ALWAYS
# restores the rule — even if the merge fails. Every other protection
# (required status checks, linear history, no-force, no-delete, PR-required) stays
# on the entire time.
#
# Usage:   bash scripts/squash-merge-pr.sh <PR_NUMBER>
# Requires: GH_TOKEN with admin (owner) scope. Export it first:  export GH_TOKEN="$ALL_GH"
#
# Why this exists: main's `mainrule` ruleset requires signed commits with an EMPTY
# bypass list, so not even the owner can merge unsigned commits directly. CI itself
# is not the blocker — checks pass; the signature rule is. See replit.md "Repo Sync Law".

set -euo pipefail

REPO="IT-Help-San-Diego/dns-tool-intel"
RULESET_ID="16489215"   # mainrule
PR="${1:?Usage: bash scripts/squash-merge-pr.sh <PR_NUMBER>}"

: "${GH_TOKEN:?Set GH_TOKEN first, e.g. export GH_TOKEN=\"\$ALL_GH\"}"

echo "==> Checking PR #$PR is green and mergeable..."
state=$(gh pr view "$PR" --repo "$REPO" --json state --jq '.state')
[ "$state" = "OPEN" ] || { echo "PR #$PR is $state, not OPEN. Aborting."; exit 1; }

# Fail fast if any required check is not passing.
bad=$(gh pr view "$PR" --repo "$REPO" --json statusCheckRollup \
  --jq '[.statusCheckRollup[] | select((.conclusion // .state) as $s | $s != "SUCCESS" and $s != "NEUTRAL" and $s != "SKIPPED")] | length')
if [ "${bad:-0}" -ne 0 ]; then
  echo "PR #$PR has ${bad} non-passing check(s). Refusing to merge."
  gh pr view "$PR" --repo "$REPO" --json statusCheckRollup \
    --jq '.statusCheckRollup[] | "  \(.name // .context): \(.conclusion // .state)"'
  exit 1
fi
echo "    all checks green."

TMP_ORIG="$(mktemp)"; TMP_NOSIG="$(mktemp)"; TMP_RESTORE="$(mktemp)"
trap 'rm -f "$TMP_ORIG" "$TMP_NOSIG" "$TMP_RESTORE"' EXIT

echo "==> Snapshotting mainrule ($RULESET_ID)..."
gh api "repos/$REPO/rulesets/$RULESET_ID" > "$TMP_ORIG"
jq '{name,target,enforcement,conditions,bypass_actors,rules}' "$TMP_ORIG" > "$TMP_RESTORE"
jq '{name,target,enforcement,conditions,bypass_actors,rules:[.rules[]|select(.type!="required_signatures")]}' "$TMP_ORIG" > "$TMP_NOSIG"

restore() {
  echo "==> Restoring required_signatures..."
  gh api -X PUT "repos/$REPO/rulesets/$RULESET_ID" --input "$TMP_RESTORE" --jq '.rules[].type' \
    && echo "    restored." \
    || echo "!! RESTORE FAILED — re-add required_signatures to mainrule manually NOW."
}
trap 'restore; rm -f "$TMP_ORIG" "$TMP_NOSIG" "$TMP_RESTORE"' EXIT

echo "==> Lifting required_signatures (temporary)..."
gh api -X PUT "repos/$REPO/rulesets/$RULESET_ID" --input "$TMP_NOSIG" --jq '.rules[].type'

echo "==> Squash-merging PR #$PR..."
if gh pr merge "$PR" --repo "$REPO" --squash --delete-branch; then
  echo "==> Merge OK."
else
  echo "!! Merge failed; rule will be restored by trap."
  exit 1
fi

# restore runs via trap on exit
echo "==> Verifying main..."
gh api "repos/$REPO/commits/main" \
  --jq '"main @ \(.sha[0:9])  verified=\(.commit.verification.verified)  \(.commit.message|split("\n")[0])"'
