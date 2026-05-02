#!/bin/bash
# DEPRECATED — Filtered web-mirror sync (retired in v26.48 single-repo migration)
#
# This script was used during the two-repo open-core era to filter the
# private intel codebase down to a public `dns-tool-web` mirror. The
# 2026-03-30 single-repo migration consolidated everything into the now-public
# `IT-Help-San-Diego/dns-tool-intel` (BUSL-1.1), so there is nothing left to
# filter or sync.
#
# Originally this stub exited 0 to be a quiet no-op, but the 2026-05-01
# sync-script audit (Task #112) established a fail-loud convention for
# retired sync helpers — silent no-ops were exactly what masked
# `intel-breadcrumbs-sync.sh` failing on every run. Aligned to that
# convention so any stale invocation surfaces immediately.
#
# References:
# - docs/ARCHIVED_BUILD_TAG_HISTORY.md (Section 5 "Single-Repo Migration"
#   and Section 6 "Sync-Script Audit (2026-05-01)")
# - scripts/codeberg-intel-sync.mjs, scripts/codeberg-webapp-sync.mjs,
#   scripts/github-to-codeberg-sync.sh, scripts/intel-breadcrumbs-sync.sh
#   (sibling deprecation stubs)

set -euo pipefail

cat >&2 <<'EOF'
sync-to-web.sh is DEPRECATED and was retired in v26.48 (single-repo migration).

The two-repo open-core architecture is gone — `IT-Help-San-Diego/dns-tool-intel`
is now the single public repo (BUSL-1.1), so there is no filtered web mirror
to sync to. The legacy `IT-Help-San-Diego/dns-tool-web` repo was archived as
part of that migration.

Off-site backups now go through `.github/workflows/backup-offsite.yml`,
which mirrors to a dedicated `backup` git remote.

Remove this invocation from whatever called it.
EOF

exit 1
