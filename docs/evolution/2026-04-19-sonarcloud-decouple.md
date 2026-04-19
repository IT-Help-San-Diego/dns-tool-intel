# SonarCloud Decouple — April 2026

## Decision

Decouple the project from SonarCloud (paid SaaS) effective April 19, 2026.
Codebase has grown past 100K LOC, putting it above the SonarCloud free
tier; the paid plan cost (hundreds/month) is not viable for a solo author.
SonarQube Community Edition (free, self-hosted) is owned and will be
brought online later as a replacement.

## What Changed

| Surface | Action | Reason |
|---|---|---|
| `.github/workflows/sonarcloud.yml` | Renamed → `.disabled`; `on:` reduced to `workflow_dispatch` placeholder. Job-level `if:` still requires push/PR events, so even a manual dispatch from the Actions UI is a no-op while dormant (intentional double-lock). | Stops billing immediately; preserves config for revival; defends against accidental rename |
| `sonar-project.properties` | Header comment added marking dormant; otherwise preserved verbatim | Curated 400-line config is institutional knowledge |
| `scripts/fix-sonar-web.py` | Deleted | Already a deprecated no-op stub |
| `go-server/cmd/server/main.go` | Removed `GET /proxy/sonar-badge/:key` route registration | Eliminates outbound calls to sonarcloud.io |
| `go-server/internal/handlers/proxy.go` | `SonarBadge` handler reduced to `410 Gone` stub; `sonarBadgeURLs` map preserved | Symbol kept for tests + future revival; no network plumbing |
| `go-server/templates/approach.html` | Quality-gate + AI-assurance badges wrapped in `{{/* ... */}}` template comments | Hides badges; restoration is uncomment |
| `scripts/release-gate.sh` Gate 6 | Marked DORMANT; still bumps `sonar.projectVersion` for accuracy | No-op for now; correct when CE comes online |
| `scripts/release-gate.sh` Gate 8b (NEW) | `go vet ./go-server/...` enforced as compensating control | Catches static-analysis smells Sonar used to flag |

## Compensating Controls In Effect

The release gate now relies entirely on in-repo tooling:

- **Gate 8** — `go test ./go-server/... -short -timeout 120s` (full unit suite)
- **Gate 8b** — `go vet ./go-server/...` (static analysis)
- **Gate 9** — R009/R010/R011 internal quality rules
- **Gate 10** — handlers/ shim drift guard
- **TestNoHardcodedMethodologyStrings** — methodology consistency
- **TestCorpusPDFIntegrity** — published PDF banner audit (added April 19, 2026)
- Boundary integrity tests — open-core repo separation
- `dependency-audit.yml` workflow — unchanged, still active

## What Did NOT Change

- The `SONAR_TOKEN` GitHub secret (left in place, dormant — user can rotate or delete via GitHub UI on their own schedule)
- The `sonarBadgeURLs` map and `SonarBadge` symbol (preserved for test references and future revival)
- Any documentation in `docs/`, `README.md`, `CITATIONS.md`, or `ROADMAP.md` referring to SonarCloud — those describe the historical and intended use, which is still true and may be true again

## Revival Path (when SonarQube CE is online)

1. Rename `.github/workflows/sonarcloud.yml.disabled` → `.yml`; restore the
   `push` and `pull_request` triggers in the `on:` block.
2. Update `sonar.host.url` in `sonar-project.properties` to point at the
   local CE instance.
3. Replace `SONAR_TOKEN` with the CE token in repo secrets (or update the
   workflow to use whatever credential CE expects).
4. Re-register the badge route in `main.go`:
   `d.Router.GET("/proxy/sonar-badge/:key", proxy.SonarBadge)`.
5. Restore the original fetch implementation in `SonarBadge` from git
   history (`git log --all -- go-server/internal/handlers/proxy.go`).
6. Uncomment the badge `<div>` in `go-server/templates/approach.html`.

## Two-Track Impact

Track 1 only — operational/cost decision, no scientific content touched.
Zenodo concept DOIs (`10.5281/zenodo.19468134`,
`10.5281/zenodo.19473698`) and PDF bytes unaffected.
