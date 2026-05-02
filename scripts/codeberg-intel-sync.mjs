#!/usr/bin/env node
// DEPRECATED — Codeberg Intel mirror sync (retired 2026-05-01)
//
// This script used to push files into a Codeberg "off-site backup" mirror at
// `careybalboa/dns-tool-intel` via the Forgejo contents API. As of the
// 2026-05-01 sync-script audit (Task #112), that destination repository does
// not exist on Codeberg (the Forgejo API returns HTTP 404 for both the repo
// and every related variant such as `careyjames/dns-tool-intel`). The
// `careybalboa` user account exists, but no `dns-tool-intel` repository was
// ever created underneath it.
//
// Anything calling this script in the v26.48+ single-repo era was therefore
// silently no-op'ing or quietly failing on the first API call.
//
// The actual off-site backup mechanism is `.github/workflows/backup-offsite.yml`,
// which mirrors `main` and snapshot branches to a separate `backup` git remote
// — not to Codeberg.
//
// References:
// - docs/ARCHIVED_BUILD_TAG_HISTORY.md (sync-script audit appendix)
// - .agents/skills/dns-tool/SKILL.md ("SINGLE PUBLIC REPO" entry under
//   Documentation Hierarchy — no longer claims a Codeberg mirror)
// - scripts/intel-breadcrumbs-sync.sh (sibling deprecation stub from v26.48)
//
// This stub remains so any stale invocation (cron, alias, muscle memory)
// fails loudly with a clear pointer instead of pretending to back things up.

process.stderr.write([
  'codeberg-intel-sync.mjs is DEPRECATED and was retired on 2026-05-01.',
  '',
  'The Codeberg destination `careybalboa/dns-tool-intel` does not exist',
  '(Forgejo API returns 404). Off-site backups now go through the',
  'GitHub Actions workflow `.github/workflows/backup-offsite.yml`, which',
  'mirrors to a dedicated `backup` git remote.',
  '',
  'Remove this invocation from whatever called it.',
  '',
].join('\n'));

process.exit(1);
