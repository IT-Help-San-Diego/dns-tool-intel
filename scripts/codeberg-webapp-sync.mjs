#!/usr/bin/env node
// DEPRECATED — Codeberg webapp mirror sync (retired 2026-05-01)
//
// This script used to push files into a Codeberg "off-site backup" mirror at
// `careybalboa/dns-tool-web` via the Forgejo contents API. As of the
// 2026-05-01 sync-script audit (Task #112), that destination repository does
// not exist on Codeberg (the Forgejo API returns HTTP 404). It is also
// architecturally obsolete: the two-repo era was retired by the
// single-repo migration (2026-03-30), and the GitHub `dns-tool-web` source
// repository was archived at the same time. There is no separate "webapp"
// repo to back up.
//
// The actual off-site backup mechanism is `.github/workflows/backup-offsite.yml`,
// which mirrors `main` and snapshot branches to a separate `backup` git remote
// — not to Codeberg.
//
// References:
// - docs/ARCHIVED_BUILD_TAG_HISTORY.md (sync-script audit appendix and
//   Section 5 "Single-Repo Migration")
// - .agents/skills/dns-tool/SKILL.md (Documentation Hierarchy — no longer
//   claims a Codeberg mirror)
// - scripts/sync-to-web.sh, scripts/intel-breadcrumbs-sync.sh
//   (sibling deprecation stubs from v26.40 and v26.48)
//
// This stub remains so any stale invocation (cron, alias, muscle memory)
// fails loudly with a clear pointer instead of pretending to back things up.

process.stderr.write([
  'codeberg-webapp-sync.mjs is DEPRECATED and was retired on 2026-05-01.',
  '',
  'The Codeberg destination `careybalboa/dns-tool-web` does not exist',
  '(Forgejo API returns 404), and the source `dns-tool-web` GitHub repo',
  'was archived during the single-repo migration in v26.48.',
  '',
  'Off-site backups now go through `.github/workflows/backup-offsite.yml`,',
  'which mirrors to a dedicated `backup` git remote.',
  '',
  'Remove this invocation from whatever called it.',
  '',
].join('\n'));

process.exit(1);
