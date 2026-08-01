# Replit Import Brief — dnstool.it-help.tech (paste-ready for the Replit agent)

Import from GitHub `main`. This import carries the deposit republication (four documents at 26.46.15) plus the PSL tri-state, UD classification, SMTP coverage restore, and the deposit-version build gate. Read every guard below BEFORE importing — several log lines and configurations look like errors and are not.

## CRITICAL — the production database

- **Never drop, rebuild, or re-initialise the production database.** It holds months of `scan_phase_telemetry` rows with no other copy. The migration system upgrades it in place on next start; rebuilding is unnecessary, not "now safe."
- **Migration 017 aborting with a row-count message is the guard WORKING, not a failure.** It measures row counts at run time and aborts if tables are non-empty before dropping/recreating. Do not "fix" this by forcing the migration.
- **The schema-adoption / "goose: no migrations to run" or version-table log line is WARNING-LEVEL and NORMAL.** It is exactly the shape an agent tries to "fix" by re-initialising. Leave it.
- **`config.go:68` `DATABASE_URL_OVERRIDE` silently beats `DATABASE_URL`.** If a stale override is set in deployment secrets, the server reroutes to the wrong DB with no error. Verify it is unset or points at production BEFORE import.

## Five deliberate configurations — do NOT "fix" these

1. **`REPLIT_DEV_BANNER`** — an env var, intentionally set per environment. Do not delete it globally; but verify it is NOT set to `1` in the *published deployment* (the startup guard `assertDeploymentEnvironment` fails the boot if it is, because it widens script-src/connect-src/frame-src with the dev-banner wildcard in production).
2. **A security header that is deliberately absent** — intentional, documented. Do not add it.
3. **The pinned Go toolchain** (`GOTOOLCHAIN=go1.25.12` in `build.sh`) — pinned for three CVEs (GO-2026-4340/-4337 TLS, GO-2026-4341 net/url). Do not bump or downgrade; it must match every workflow `go-version:` in lockstep.
4. **Two OPPOSITE build-cache paths** — workspace-relative caches in the default build (persistence), `/tmp` in the `--deploy` branch only (8 GiB image cap). Never unify them; the difference is deliberate.
5. **A header-keyed CSP directive** — keyed on `X-Forwarded-Proto=https` (edge sets it, local doesn't). Do not hardcode it.

## NEW this import — startup ordering

**`config.Load()` runs AFTER the early listener binds.** `main.go` binds the early listener first (`waitForListener` + "Early listener started"), THEN calls `config.Load()`. Until config succeeds, the early listener serves `/healthz` with **HTTP 200 `{"status":"starting"}`**. So a misconfigured deployment answers healthchecks 200 OK in the moments before `config.Load()` fails and `os.Exit(1)` fires — **a crash-loop that reads healthy**, not a clean refusal. If the deployment crash-loops after import, do not assume "healthcheck passed so config is fine" — check the log for the `config.Load` error.

**Before importing, check these in the deployment's secrets:**
- `REPLIT_DEV_BANNER` — must NOT be `1` in the published deployment.
- `BASE_URL` — must be the real public base URL, not an ephemeral/dev URL.
- `DATABASE_URL_OVERRIDE` — unset, or pointing at the production DB.

## Post-019 imports — expected migration log lines (verified vs migrate.go:164/168/186/263)

When a pending migration exists, the healthy boot prints **exactly**:
`migrate: applying pending migrations from_version=N to_version=N+1` → `OK <file>` → `migrate: schema upgraded version=N+1 applied=1`.

Two lines are **stop-and-report signals**, not successes:
- `migrate: version ledger table exists but has no rows` (the adoption WARN) — after the first adoption, this means the ledger was emptied again. Stop and report; do NOT re-initialise.
- `migrate: schema up to date` when a migration was expected to apply — means it did NOT run. Stop and report.

After migration 019 (app_version TEXT everywhere), confirm recording resumed: `SELECT MAX(created_at) FROM icuae_scan_scores` should postdate the deploy once the first scan completes. If not, something other than column width is blocking those inserts — stop and report.

## What "done" looks like

- Server boots, passes migration (existing DB upgraded in place), serves https://dnstool.it-help.tech.
- The four deposit documents (methodology, philosophical-foundations, founders-manifesto, communication-standards) all serve at version **26.46.15**, and their PDFs match.
- No database tables dropped or recreated. `scan_phase_telemetry` row count is unchanged (or only appended).
