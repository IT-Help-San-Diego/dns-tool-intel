#!/usr/bin/env bash
# version.sh — single source of truth for the app version.
#
# The version is DERIVED FROM GIT, never from a hand-edited file. This is the
# permanent cure for the chronic ship conflict: routine dev ships no longer edit
# a tracked Version line, so local + main can no longer "change the same line on
# both sides" and conflict on every PR.
#
# Resolution order:
#   1. $APP_VERSION env override (operator-controlled, e.g. to pin a clean label)
#   2. git describe --tags --always   (e.g. "26.46.14-376-gfee43e982"; on a tag
#      exactly "26.46.14") with any leading "v" stripped
#   3. "dev" fallback when git/.git is unavailable
#
# Consumed by build.sh (ldflags injection into config.Version) and the Node
# projection scripts (figma/miro/pipeline sync). One definition, no drift.

if [ -n "${APP_VERSION:-}" ]; then
  echo "$APP_VERSION"
  exit 0
fi

cd "$(dirname "$0")/.." 2>/dev/null || true

v=$(git describe --tags --always 2>/dev/null || true)
[ -z "$v" ] && v="dev"
echo "${v#v}"
