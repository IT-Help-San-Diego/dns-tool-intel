#!/bin/bash
# DEPRECATED — Intel Breadcrumbs Sync (retired in v26.48)
#
# This script was a holdover from the two-repo open-core era. It used to pull
# a hard-coded list of docs (PROJECT_CONTEXT.md, EVOLUTION.md,
# EVOLUTION_APPEND_*.md, STUB_AUDIT.md, ARCHITECTURE_CLASSIFIED.md,
# BUILD_TAG_STRATEGY.md, etc.) out of a separate private `dns-tool-intel`
# repository into `.intel/breadcrumbs/`.
#
# As of v26.48, the Intel repository was merged into the single public repo
# (`IT-Help-San-Diego/dns-tool-intel`, BUSL-1.1). All those documents now live
# directly in this repo under `docs/`, and several of the targeted files —
# `STUB_AUDIT.md`, `docs/ARCHITECTURE_CLASSIFIED.md`,
# `docs/BUILD_TAG_STRATEGY.md` — were consolidated into
# `docs/ARCHIVED_BUILD_TAG_HISTORY.md`.
#
# There is nothing to "sync" anymore: the breadcrumbs are part of the working
# tree. Pulling them through GitHub's contents API would just re-download
# files that already exist on disk, and would fail with `SKIP` lines for the
# entries that were intentionally consolidated away.
#
# See: docs/ARCHIVED_BUILD_TAG_HISTORY.md (consolidated successor)
#      .agents/skills/dns-tool/SKILL.md ("SINGLE PUBLIC REPO" entry under
#      "Documentation Hierarchy")
#
# This stub remains so that any stale invocation (muscle memory, cron, a
# forgotten alias) fails loudly with a clear pointer instead of silently
# chasing files that no longer exist.

set -euo pipefail

cat >&2 <<'EOF'
intel-breadcrumbs-sync.sh is DEPRECATED and was retired in v26.48.

The separate private `dns-tool-intel` repository no longer exists — the
project consolidated to a single public repo. The documents this script
used to fetch now live directly under `docs/` in this working tree, and
the intel-era specific files (STUB_AUDIT.md, ARCHITECTURE_CLASSIFIED.md,
BUILD_TAG_STRATEGY.md) were consolidated into:

    docs/ARCHIVED_BUILD_TAG_HISTORY.md

There is nothing to sync. Remove this invocation from whatever called it.
EOF

exit 1
