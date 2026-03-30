# Single-Repo Migration — GitHub Instructions

**Date:** 2026-03-30
**Migration:** `dns-tool-intel` (was private → now public) is the single canonical repo. `dns-tool-web` (public mirror) → archived. `dns-tool` (original legacy repo) → left as-is (already archived).

All codebase changes are complete. This document covers the GitHub-side actions.

---

## Step 1: Make dns-tool-intel Public ✅ DONE

1. Go to **github.com/IT-Help-San-Diego/dns-tool-intel** → Settings → General
2. Scroll to "Danger Zone" → "Change repository visibility"
3. Change from **Private** to **Public**
4. Confirm by typing the repository name

> BUSL-1.1 license protects the IP. The latest shipping version is always commercially protected; each version converts to Apache 2.0 three years after release.

---

## Step 2: Archive dns-tool-web ✅ DONE

1. Go to **github.com/IT-Help-San-Diego/dns-tool-web** → Settings → General
2. Scroll to "Danger Zone" → "Archive this repository"
3. Click "Archive this repository"
4. Update repo description to: "Archived — consolidated into IT-Help-San-Diego/dns-tool-intel"

> This makes dns-tool-web read-only. Existing links still work.

---

## Step 3: SonarCloud Cleanup ✅ DONE

1. Go to **sonarcloud.io** → Organization: `ithelpsandiego`
2. Delete or archive these redundant projects:
   - `dns-tool-web` (the public mirror project — no longer needed)
   - `careyjames_dns-tool` (auto-imported duplicate)
   - `careyjames_dns-tool-intel` (auto-imported duplicate)
3. Keep `dns-tool-full` as the single canonical project
4. Update the `dns-tool-full` project settings:
   - Repository: `IT-Help-San-Diego/dns-tool-intel`
   - Project display name: "DNS Tool"

---

## Step 4: Push the Updated Codebase

From the Replit workspace, run:

```bash
bash scripts/git-sync.sh
```

This pushes all the migration changes (updated references, rewritten release.sh, deprecated mirror scripts) to the now-public `dns-tool-intel` repo.

---

## Step 5: Update Zenodo

1. Go to **zenodo.org** → Your uploads → DNS Tool record
2. Update the "Related identifiers" URL to `https://github.com/IT-Help-San-Diego/dns-tool-intel`
3. The DOI (10.5281/zenodo.18854899) remains valid — it points to the Zenodo record, not the GitHub URL directly
4. Future releases via `scripts/release.sh` will create tags on `dns-tool-intel` (Zenodo webhook may need re-linking)

---

## Step 6: Verify

After completing all steps:

- [x] `github.com/IT-Help-San-Diego/dns-tool-intel` is public and has all code
- [x] `github.com/IT-Help-San-Diego/dns-tool-web` is archived
- [ ] `github.com/IT-Help-San-Diego/dns-tool` left as-is (original legacy archive)
- [ ] SonarCloud shows only `dns-tool-full` project
- [ ] GitHub Actions CI runs on `dns-tool-intel`
- [ ] Security advisories link to `dns-tool-intel`
- [ ] `dnstool.it-help.tech` still serves correctly (deployment is independent of repo name)

---

## Why Not Rename to `dns-tool`?

The original migration plan proposed renaming `dns-tool-intel` to `dns-tool`. This was revised because:

1. `IT-Help-San-Diego/dns-tool` already exists as an archived legacy repo
2. GitHub does not allow renaming to a name that's already taken without deleting/renaming the existing repo first
3. The `-intel` suffix is harmless — the repo is public and is the only active one
4. Renaming would require updating all CI, metadata, DOIs, and Zenodo integrations again
5. The simpler path: keep the name, make it public, archive the others

---

## What Changed in the Codebase

All these changes are already committed and ready to push:

1. **Metadata files** (README, LICENSE refs, CITATION.cff, codemeta.json, NOTICE, CONTRIBUTING.md, BUILD.md, LICENSING.md) — all point to `dns-tool-intel`
2. **SonarCloud config** — single project key `dns-tool-full`, name "DNS Tool"
3. **Go source** — all `_oss.go` stubs reference build tags instead of repo names; boundary tests verify build-tag gating instead of asserting file absence
4. **Templates** — footer, privacy, architecture, security pages all link to `dns-tool-intel`
5. **Documentation** — all docs updated; architecture diagrams reference single-repo model
6. **Release pipeline** — `release.sh` rewritten for single-repo (no more two-repo push/filter logic)
7. **Mirror artifacts deprecated** — `sync-to-web.sh`, `fix-sonar-web.py`, `public-excludes.txt` contain deprecation notices
8. **GitHub config** — issue templates, security redirect workflow, `.zenodo.json` all reference `dns-tool-intel`
9. **Scripts** — `git-sync.sh`, `git-push.sh`, `git-health-check.sh` all target `dns-tool-intel`

---

## Rollback Plan

If something goes wrong:

1. Change `dns-tool-intel` visibility back to Private
2. Un-archive `dns-tool-web`
3. The mirror workflow files are deprecated but the scripts still exist — they would need to be restored from git history if needed
