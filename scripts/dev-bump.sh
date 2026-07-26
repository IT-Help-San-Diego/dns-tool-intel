#!/usr/bin/env bash
# dev-bump.sh — DEPRECATED (retired 2026-06-20).
#
# The app version is now DERIVED FROM GIT (scripts/version.sh) and injected at
# build time via -ldflags. Routine development ships NO LONGER bump a version
# file at all — that hand-edit of the same Version line on every ship was the
# single cause of the chronic every-ship merge conflict on config.go. There is nothing to bump for a dev ship.
#
# WHAT TO DO NOW:
#   * Routine dev ship: just ship. The binary's version auto-advances from git
#     (e.g. "26.46.14-376-gfee43e982"). No bump, no file edit, no conflict.
#         bash scripts/quality-gate.sh
#         bash scripts/git-push.sh
#   * Cut a RELEASE: run the release gate, then create an annotated git tag —
#     the tag IS the version (git describe resolves to it exactly on the tag):
#         bash scripts/release-gate.sh X.Y.Z
#         git tag -a vX.Y.Z -m "Release vX.Y.Z"   (then push the tag)
#   * Pin a clean display version temporarily: export APP_VERSION=X.Y.Z and rebuild.
#
# This script intentionally no longer edits any file. It exits 0 so old muscle
# memory / automation can't accidentally reintroduce version-file churn.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "dev-bump.sh is DEPRECATED — version now comes from git, not a tracked file."
echo ""
echo "Current git-derived version: $(bash scripts/version.sh)"
echo ""
echo "Routine dev ship (no bump needed):"
echo "  bash scripts/quality-gate.sh"
echo "  bash scripts/git-push.sh"
echo ""
echo "Cut a release (tag IS the version):"
echo "  bash scripts/release-gate.sh X.Y.Z"
echo "  git tag -a vX.Y.Z -m 'Release vX.Y.Z'"
echo ""
echo "Pin a display version temporarily:  export APP_VERSION=X.Y.Z && bash build.sh"
exit 0
