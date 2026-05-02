#!/bin/bash
# DEPRECATED — GitHub → Codeberg bulk mirror (retired 2026-05-01)
#
# This script used to git-clone three GitHub source repos
# (`dns-tool-web`, `dns-tool-cli`, `dns-tool-intel`) and push them
# `--mirror` to matching Codeberg destinations under `careybalboa/`.
#
# As of the 2026-05-01 sync-script audit (Task #112), every leg of that
# pipeline is broken or obsolete:
#
#   * `IT-Help-San-Diego/dns-tool-cli` — never existed (GitHub returns 404).
#   * `IT-Help-San-Diego/dns-tool-web` — exists but is archived as part of the
#     single-repo migration (v26.48). It is no longer a meaningful mirror
#     source.
#   * `IT-Help-San-Diego/dns-tool-intel` — live, but the script's
#     intel-mirror step was already in the trailing "for dns-tool-intel
#     (private), run:" comment, not the active code path.
#   * `careybalboa/dns-tool-web`, `careybalboa/dns-tool-cli`,
#     `careybalboa/dns-tool-intel` — none exist on Codeberg (Forgejo
#     API returns 404 for all three).
#
# So every invocation of this script in the v26.48+ era either failed
# at the clone step (cli) or pushed to a 404 destination (web).
#
# Off-site backups are now handled by the GitHub Actions workflow
# `.github/workflows/backup-offsite.yml`, which pushes `main` plus
# timestamped snapshot branches to a dedicated `backup` git remote
# (not to Codeberg).
#
# References:
#   * docs/ARCHIVED_BUILD_TAG_HISTORY.md (sync-script audit appendix)
#   * .agents/skills/dns-tool/SKILL.md (Documentation Hierarchy — no longer
#     claims a Codeberg mirror)
#   * scripts/codeberg-intel-sync.mjs, scripts/codeberg-webapp-sync.mjs
#     (sibling deprecation stubs)
#
# This stub remains so any stale invocation (cron, alias, muscle memory)
# fails loudly with a clear pointer instead of pretending to back things up.

set -euo pipefail

cat >&2 <<'EOF'
github-to-codeberg-sync.sh is DEPRECATED and was retired on 2026-05-01.

  * `IT-Help-San-Diego/dns-tool-cli` does not exist on GitHub.
  * `IT-Help-San-Diego/dns-tool-web` is archived (single-repo migration).
  * `careybalboa/{dns-tool-web,dns-tool-cli,dns-tool-intel}` do not exist
    on Codeberg.

Off-site backups now go through `.github/workflows/backup-offsite.yml`,
which mirrors to a dedicated `backup` git remote.

Remove this invocation from whatever called it.
EOF

exit 1
