#!/usr/bin/env bash
# check-merge-policy.sh — drift guard for main's merge policy.
#
# Verifies the PERMANENT CI/merge configuration is intact so PRs always flow:
#   - Repo: squash-only (merge & rebase OFF), auto-merge ON, delete-branch ON
#   - Ruleset "mainrule": pull_request (squash-only) + required_status_checks
#     (CodeQL, Build & Test, strict) + required_linear_history + non_fast_forward
#     + deletion; required_signatures ABSENT; bypass list EMPTY.
#   - Ruleset "main": pull_request squash-only.
#
# WHY: required_signatures is structurally incompatible with Replit's unsigned
# checkpoint commits — it silently blocks every PR. We rely instead on squash-only
# merges, which GitHub signs server-side (verified:true on main). If anyone re-adds
# required_signatures, re-enables merge/rebase, or grants a bypass, shipping breaks
# or posture regresses. Run this to catch that early.
#
# Usage:   export GH_TOKEN="$ALL_GH"; bash scripts/check-merge-policy.sh
# Exit 0 = policy intact; exit 1 = drift detected.

set -euo pipefail
REPO="IT-Help-San-Diego/dns-tool-intel"
MAINRULE=16489215
BASERULE=14300584
: "${GH_TOKEN:?Set GH_TOKEN first, e.g. export GH_TOKEN=\"\$ALL_GH\" (ruleset reads need admin scope)}"

fail=0
ok()   { echo "  OK   $1"; }
bad()  { echo "  DRIFT $1"; fail=1; }

echo "== Repo merge settings =="
repo=$(gh api "repos/$REPO" --jq '{m:.allow_merge_commit,s:.allow_squash_merge,r:.allow_rebase_merge,a:.allow_auto_merge,d:.delete_branch_on_merge}')
[ "$(jq -r .s <<<"$repo")" = "true" ]  && ok "squash merge enabled"            || bad "squash merge DISABLED"
[ "$(jq -r .m <<<"$repo")" = "false" ] && ok "merge-commit disabled"           || bad "merge-commit ENABLED (should be off)"
[ "$(jq -r .r <<<"$repo")" = "false" ] && ok "rebase merge disabled"           || bad "rebase merge ENABLED (should be off)"
[ "$(jq -r .a <<<"$repo")" = "true" ]  && ok "auto-merge enabled"              || bad "auto-merge DISABLED"
[ "$(jq -r .d <<<"$repo")" = "true" ]  && ok "delete-branch-on-merge enabled"  || bad "delete-branch-on-merge DISABLED"

echo "== Ruleset: mainrule ($MAINRULE) =="
mr=$(gh api "repos/$REPO/rulesets/$MAINRULE")
types=$(jq -r '[.rules[].type]|join(" ")' <<<"$mr")
grep -qw required_signatures <<<"$types" && bad "required_signatures present (re-blocks every PR)" || ok "required_signatures absent"
grep -qw pull_request        <<<"$types" && ok "pull_request required"        || bad "pull_request rule missing"
grep -qw required_status_checks <<<"$types" && ok "required_status_checks present" || bad "required_status_checks missing"
grep -qw required_linear_history <<<"$types" && ok "linear history required"  || bad "required_linear_history missing"
grep -qw non_fast_forward    <<<"$types" && ok "non-fast-forward (no force)"  || bad "non_fast_forward missing"
methods=$(jq -r '(.rules[]|select(.type=="pull_request").parameters.allowed_merge_methods)|join(",")' <<<"$mr")
[ "$methods" = "squash" ] && ok "mainrule merge method = squash-only" || bad "mainrule merge methods = [$methods] (want squash only)"
strict=$(jq -r '(.rules[]|select(.type=="required_status_checks").parameters.strict_required_status_checks_policy)' <<<"$mr")
# strict MUST be false: ship branches are squash-from-divergent-local and never
# contain main's squash tip, so strict=true would mark every PR "out of date" and
# deadlock auto-merge. (Solo sequential squash flow => no stale-green race anyway.)
[ "$strict" = "false" ] && ok "status checks non-strict (required for squash-from-divergent-local)" || bad "status checks strict=$strict (must be false or auto-merge deadlocks)"
checks=$(jq -r '[.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context]|join(",")' <<<"$mr")
grep -q "CodeQL" <<<"$checks" && grep -q "Build & Test" <<<"$checks" && ok "required checks: $checks" || bad "required checks incomplete: [$checks]"
nbypass=$(jq -r '.bypass_actors|length' <<<"$mr")
[ "$nbypass" = "0" ] && ok "mainrule bypass list empty (no one skips checks)" || bad "mainrule has $nbypass bypass actor(s)"
enf=$(jq -r '.enforcement' <<<"$mr")
[ "$enf" = "active" ] && ok "mainrule active" || bad "mainrule enforcement = $enf"

echo "== Ruleset: main ($BASERULE) =="
br=$(gh api "repos/$REPO/rulesets/$BASERULE")
bmethods=$(jq -r '(.rules[]|select(.type=="pull_request").parameters.allowed_merge_methods)//[]|join(",")' <<<"$br")
{ [ "$bmethods" = "squash" ] || [ -z "$bmethods" ]; } && ok "main ruleset merge method = squash-only (or n/a)" || bad "main ruleset merge methods = [$bmethods]"

echo ""
if [ "$fail" -eq 0 ]; then
  echo "MERGE POLICY: INTACT — PRs will flow (push → PR → auto-merge squash on green → signed main)."
else
  echo "MERGE POLICY: DRIFT DETECTED — fix the items marked DRIFT above. See scripts/check-merge-policy.sh header."
fi
exit "$fail"
