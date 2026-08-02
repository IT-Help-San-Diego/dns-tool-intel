# AWS deploy — EC2 app box

The AWS successor to `.replit [deployment]` (`build.sh --deploy` then run
`./dns-tool-server` from repo root). Full migration record:
`docs/research/AWS-MIGRATION-DECISION-BRIEF.md` (PR #261).

## The rules, each one a measured failure mode

| Rule | Why (verified 2026-08-01) |
|---|---|
| Build with `GOOS=linux GOARCH=arm64 bash build.sh --deploy`, never plain `go build` | An un-ldflagged binary stamps literal `dev` into `app_version` on three DB tables (silent lineage corruption) and freezes the `?v=` asset cache key + service-worker version |
| Build from a full clone with tags fetched | `scripts/version.sh` silently degrades to a bare SHA or `dev` — the build does not fail, the damage is downstream |
| Ship the bundle, not the binary | `static/`, solver layouts, `CITATION.cff` degrade silently when missing; `/stats` reads the literal path `static/data/integrity_stats.json`. (Templates are binary-embedded since the embed PR — they cannot be missing, from any cwd) |
| `WorkingDirectory=/opt/dnstool` in the unit | static/, solver layouts, CITATION.cff, and the /stats data resolve relative to cwd — and with templates embedded, a wrong cwd no longer crash-loops: it serves a silently broken site (404 assets, no SRI, empty /stats). The unit pins it precisely BECAUSE the failure went quiet; verify a static asset returns 200 after any deploy change |
| Stage OUTSIDE the live dir (`/opt/dnstool-stage`), swap stopped, restart after | SRI hashes are boot-computed (changed bytes under a live server are refused by Firefox/Safari with no server-side error), and a staging dir INSIDE the rsync destination gets deleted by its own `--delete` mid-swap — reproduced: exit 23, service left stopped, tree corrupted |
| Provision first: `provision-ec2.sh` as root, once | Service user, `/opt/dnstool{,-stage,/logs}`, `/etc/dnstool/env`, sudoers, and the unit — four distinct fresh-box failures when left implicit (226/NAMESPACE on missing logs/, 217/USER on missing user, required EnvironmentFile absent, sudo hanging in the ssh block) |
| Verify ON THE BOX: `--version` then localhost `/healthz` body `"status":"ok"` | The public domain answers from the OLD platform until Route53 flips — a public-URL check reports READY for a dead box during the exact cutover run. `--version` self-reports "Built without version injection" on a bad build |

## /etc/dnstool/env

```
DATABASE_URL=postgres://…           # RDS endpoint (private subnet)
SESSION_SECRET=…
PORT=5000
CLOUD_DEPLOYMENT=1                  # the cloud→local lever: privacy banner,
                                    # cloud nav badge, no /history flipper,
                                    # Wayback archival ON. Without it the
                                    # public site impersonates a local build.
BASE_URL=https://dnstool.it-help.tech   # optional; canonical is the default
# TRUSTED_PROXIES=…                 # phase 2 (CloudFront/ALB): comma-separated
                                    # CIDRs of the origin-facing hop. Unset =
                                    # loopback only, correct for direct serving
                                    # and for an on-box TLS proxy.
```

`CLOUD_DEPLOYMENT` OR the legacy `REPLIT_DEPLOYMENT` both flip the lever
(`config.IsCloudDeploymentEnv`), so a rollback deploy onto Replit needs no
env change — and HSTS self-gates there too (`middleware.EmitHSTS`): behind
Replit's edge the app yields emission to the edge, so the rollback carries
no duplicate-header cost.

## Phase order (agreed 2026-08-01)

1. Direct cutover: `provision-ec2.sh` (root, once) → fill `/etc/dnstool/env`
   → `deploy-aws.sh` → Elastic IP, TLS on the box, Route53 A record. HSTS is
   now app-emitted off-Replit (restored in the pre-cutover PR; static assets
   and the early listener's starting/degraded responses included).
2. CloudFront after stable, with the verified behavior spec (cache key must
   include the query string; strip Set-Cookie on cached behaviors; MinTTL 0;
   origin timeout ≥60s; forward an https proto signal). Set TRUSTED_PROXIES
   in the same change or client IPs collapse onto the edge.
3. ~~Template embedding~~ LANDED: templates are compiled into the binary
   (`go-server/templates/embed.go`), deleting the fatal-cwd failure mode.
   Dev loop: `scripts/dev-watch.sh` auto-rebuilds+restarts on template/Go/
   static edits (the rebuild also re-computes SRI, so it fixes the
   blank-canvas-after-JS-edit trap at the same time).
