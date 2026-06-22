# DNS Tool — Domain Security Audit

## Overview
OSINT platform for RFC-compliant domain security analysis (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA). Generates ICD 203 technical and executive reports. See `.agents/skills/dns-tool/SKILL.md` for the full architecture, philosophy, and connected-ecosystem inventory.

## User Preferences

### Hard rules — never violate
- **CITATION.cff / codemeta.json — HANDS OFF**: ORCID-linked Zenodo artifacts. Never modify automatically. License must remain `BUSL-1.1`. Concept DOI `10.5281/zenodo.18854899` NEVER changes. CI guard `.github/workflows/guard_citation.yml` blocks regressions.
- **Version Law — version comes from git, not a hand-edited file** (changed 2026-06-20; replaces the old Two-Track dev-bump file churn that conflicted on every ship):
  - **Routine dev ship**: NO version bump. The app version is derived from git (`git describe --tags`, via `scripts/version.sh`) and injected at build time with `-ldflags` into `config.Version` (alongside `GitCommit`/`BuildTime`). Dev builds auto-advance, e.g. `26.46.14-376-gfee43e982`. Nothing is hand-edited, so there is no version line for the ship PR to conflict on. `scripts/dev-bump.sh` is DEPRECATED — it edits nothing and just prints guidance.
  - **Customer-facing display = `YEAR.MILESTONE.BUILD`** (added 2026-06-20): `config.Version` stays the full git-describe string, but the `displayVersion` template fn (`go-server/internal/templates/funcs.go`) renders the public label (footer, nav, ede/architecture/brand/owl pages) as e.g. `26.50.161`. **YEAR.MILESTONE** = first two components of the most recent tag; **BUILD** = git commit-count since that tag (the `-<N>-g<sha>` field). So the BUILD digit ticks up on EVERY ship automatically (visible in dev testing + to customers on every deploy) and resets to 0 when a new milestone tag is cut. The tag's THIRD component (legacy patch / release-tag `.0`) is intentionally ignored — BUILD takes that slot. This is why tags stay clean 3-part semver (`vX.Y.Z`) for Zenodo/CITATION while the app shows live movement; the milestone is bumped by bumping the MINOR at release time (`release-gate.sh`). PDF routes use raw `.AppVersion`, NOT `displayVersion` — do not couple them.
  - **Release** (tag time only, when Carey is ready): Run `bash scripts/release-gate.sh X.Y.Z` (bumps Zenodo/CITATION artifacts + PDFs), then tag **`origin/main`'s tip — NOT local HEAD**: `git fetch origin main && git tag -a vX.Y.Z origin/main -m "Release vX.Y.Z" && git push origin vX.Y.Z`. The tag IS the version. The squash-merge flow means local HEAD is never on main's lineage, so a tag on local HEAD reads clean locally but is invisible to production. Verify reachable: `gh api repos/<org>/<repo>/compare/main...vX.Y.Z --jq '.status'` → `identical`/`behind` (not `diverged`). Fix a mis-placed tag: `git push origin :refs/tags/vX.Y.Z` + `git tag -d vX.Y.Z`, then re-tag `origin/main`.
  - `config.go` `Version = "dev"` is a build-without-ldflags FALLBACK only — NEVER hand-edit it to bump. `export APP_VERSION=…` overrides the raw version for one build, but note the display maps it to YEAR.MILESTONE.BUILD: a plain `APP_VERSION=X.Y.Z` (no commit suffix) renders as `X.Y.0` (the patch slot is the BUILD counter). To pin an exact displayed build, use the git-describe shape, e.g. `export APP_VERSION=26.51-7-glocal` → displays `26.51.7`.

- **THE THREE-COMMAND PLANS** (canonical sequences — copy to notes):

  **A. Ship a dev bump to `origin/main`** (post-branch-protection 2026-05-16):
  ```
  1. # routine dev ship: NO version bump — version is git-derived at build time (see Version Law above)
  2. bash scripts/quality-gate.sh     # R009 + R010 + R011 + go vet + core tests + RFC attacks
  3. bash scripts/git-push.sh         # push to a FRESH ship/<ts> branch → open PR → auto-merge --squash on green → branch auto-deleted → auto-runs step 4 on success
  4. bash scripts/sync-local-to-main.sh   # now AUTO-RUN by step 3 after a successful merge; run manually ONLY if that auto-sync aborted (dirty tree / detached HEAD / conflict)
  ```
  `git-push.sh` handles the whole PR lifecycle (no direct push to main, no API ref-writes) and self-guards: hard-stops "Nothing to ship" when local tree == `origin/main`; its merge-wait loop bails fast — instead of burning the 15-min timeout — on `MERGED`/`CLOSED`, on `mergeable==CONFLICTING` (2 consecutive reads ~40s; auto-merge can never fire on a conflict, prints the `sync-local-to-main.sh` remedy), and on repeated transient/empty `gh` reads. Design pillars (NEVER regress):
  - **Sync after every ship (step 4)**: squash-merges land on `main` as commits local never receives. `sync-local-to-main.sh` fetches+merges `main` into local (native git, no API ref-writes), auto-resolves ONLY the version files (`config.go`, `sonar-project.properties`) in favour of local, and HARD-STOPS on any other conflict or a dirty tree. No-op when already in sync. (Git-derived versioning should end version-line conflicts, but this remains the canonical reconcile.)
  - **Ephemeral ship branches**: each run pushes workspace HEAD to a fresh `ship/<ts>-<sha>` branch (never the persistent `replit-agent` branch), so a push can never be non-fast-forward. Squash-merged into `main`, then auto-deleted. `--no-main` pushes a `snapshot/<ts>-<sha>` backup and stops (no PR).
  - **Squash-only, GitHub-signed main**: merge-commit & rebase disabled at repo + ruleset level; GitHub signs server-side squash commits so `main` stays `verified` without contributors signing. NEVER switch to `--rebase`/`--merge` (unsigned commits → rejected by base-branch policy).
  - **Tokens**: git push uses `GH_SYNC_TOKEN` (push scope); PR create + auto-merge use `ALL_GH` (PR scope — `GH_SYNC_TOKEN` cannot create PRs). Both are API ops, not git-ref writes.
  - **Required checks on `main`**: `CodeQL` + `Build & Test`, **non-strict** (strict deadlocks — local never contains main's squash tip). Force-push blocked, linear history required, bypass empty. Audit drift: `export GH_TOKEN="$ALL_GH"; bash scripts/check-merge-policy.sh`.

  **B. Do science / verify analyzer changes**:
  ```
  1. bash scripts/test-all.sh         # go vet + full Go test matrix (core + per-tag handler passes + RFC attacks)
  2. bash scripts/quality-gate.sh     # R009 + R010 + R011 + core gates (advisory: csso freshness, Lighthouse readiness)
  3. npx lighthouse http://localhost:5000 --only-categories=performance,accessibility,best-practices,seo --quiet   # standing gate 100/100/100/100
  ```
  Observatory 145+ is a manual check at https://developer.mozilla.org/en-US/observatory (against `https://dnstool.it-help.tech` for prod, dev preview not reachable). SonarCloud A/A/A is CI-only — surfaced by the `Code Quality: Push on main` check in step A.3.
- **Zero Fabrication Rule**: NEVER invent real-world facts (addresses, names, dates, stats, credentials). Verify from authoritative source or leave empty / ask.
- **Claims**: Every claim must be backed by implemented code. Roadmap items say "on the roadmap." Use "evidence-weighted confidence scoring inspired by Bayesian reasoning" not "Bayesian calibration"; "tamper-evident snapshots" not "append-only proof"; "inspired by" not "modelled on."
- **Marketing Voice**: Never position against competitors. Position against the complexity of DNS and the consequence of getting it wrong. Lead with capability, not comparison.
- **EDE entries are immutable**: Amendments only on FACTUAL_ERROR or DIGNITY_OF_EXPRESSION grounds, must be declared explicitly. See SKILL.md § EDE enforcement checklist.
- **MAINTENANCE_NOTE env var**: User-controlled operational control. Never remove without explicit approval.
- **Repo Sync Law — agent never writes git refs via API** (reaffirms SKILL.md § "Repo Sync Law" rule #3): changes land on `origin/main` ONLY via — agent edits workspace files → Replit checkpoint (or user) commits to local `.git` → user runs `bash scripts/git-push.sh` → `gh pr create` + `gh pr merge --squash --auto`. The agent is FORBIDDEN from creating remote-only commits/refs via the GitHub Git Data API (`createBlob`/`createTree`/`createCommit`/`updateRef`/`POST /repos/.../merges`) — they corrupt ancestry, cause non-fast-forward push storms, and have destroyed history before. If a change must land on `main` and the user is unavailable, the agent STOPS and waits. Read-only `gh api` (commits, file content, CI runs, PR status) is permitted; non-git-object repo-settings APIs (branch protection, Dependabot, secrets) need explicit user approval. Branch protection on `main` makes API ref-writes physically impossible — defense-in-depth on top of this rule.

### Process & quality gates
- **Development Process**: Research best-practices first (cite RFCs). Design before implementing. Write tests first. Check quality gates during development.
- **Dual-Environment Quality**: Verify every quality-affecting change in BOTH dev (localhost:5000) AND production (dnstool.it-help.tech). Use `npx lighthouse` against both. Dev preview runs in cross-site iframe — any new security header or cookie attribute MUST use `IsDevEnvironment` / `CookieSameSite(c)` pattern (strict prod, relaxed dev).
- **Standing Gates** (verify before EVERY phase transition): Lighthouse 100/100/100/100, Observatory 145+ (A+), SonarCloud A/A/A, Confidence Bridge, all 9 protocol analyzer test suites. Tracked in Goals & Benchmarks Notion DB.
- **After ANY Go change**: `go test ./go-server/... -count=1`
- **After CSS change**: `npx csso static/css/custom.min.css`
- **Always before delivering**: `node scripts/audit-css-cohesion.js` (R009), `node scripts/feature-inventory.js` (R011), `node scripts/validate-scientific-colors.js` (R010). All quality gates are HARD STOPS per ACIP v2.0 — see `docs/ACIP.md`.
- **Release Cross-System Checklist**: After `bash scripts/release-gate.sh X.Y.Z` + tagging, also update Notion Architecture Overview (`31c950b70b158108a5a5dc46eceae328`) and Phase 3 Version Range (`31c950b70b158196a670d758ad77f399`). Routine dev ships need NO version/Notion update — the version is git-derived. DO NOT touch CITATION.cff / codemeta.json / methodology docs outside release-gate.
- **Mermaid diagrams**: In Replit use `bash scripts/render-diagrams-remote.sh` (mermaid.ink API). Locally with mmdc: `bash scripts/render-diagrams.sh`. Always re-render after `.mmd` changes.
- **Connected Ecosystem Pre-Flight**: Before any task, check the API/secret/integration inventory in SKILL.md § "Step 0". Connect data across every system that knows about it.

### Code conventions
- **Test Build Tags (CRITICAL)**: Default `go test ./internal/handlers/` runs ~33K core test lines. Extended suites are opt-in:
  - `-tags coverage` — coverage/sprint batch tests (also on 6 analyzer files)
  - `-tags dbtest` — DB-dependent tests (require live PostgreSQL)
  - `-tags scientific` — scientific methodology tests
  - `-tags integration` — integration tests (also on analyzer `live_integration_test.go`)
  - Shared mock types live in `mock_stores_test.go` (always compiled). NEVER move mocks into build-tagged files.
  - Compile a test binary: `go test -c ./internal/handlers/ -o /tmp/ht_bin` then `/tmp/ht_bin -test.run TestFoo -test.v`
- **Implementation Files**: `_impl.go` files contain canonical implementations for analyzer subsystems.
- **Science vs Design tagging**: `[SCIENCE]` = analyzer/, ai_surface/, confidence/, rfc_citations.go, methodology docs, integrity_stats.json, llms.txt. `[DESIGN]` = templates/, css/, js/, copy. Tags follow the DATA: template logic rendering RFC-derived data is `[SCIENCE]`. `[SCIENCE]` changes require RFC citation verification + protocol test passes BEFORE changing. See SKILL.md § "Science & Research Tag Boundaries".
- **Capitalization**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.
- **Print-only elements**: ALL print-only elements MUST have `display: none !important` in the screen stylesheet.
- **Mobile input policy**: ALL domain/IP input fields MUST have `autocapitalize="none" spellcheck="false" autocomplete="off"`. Applies to index/investigate/zone/badge_embed/dossier/history.html and any future domain inputs.
- **Safari scan navigation**: NEVER use `location.href` to start a scan that shows a timer overlay — WebKit kills running JS on navigation, freezing it. Use `fetch()` + `document.write()` + `history.replaceState()` instead. Always call `showOverlay()` (double-rAF) before fetching. After `document.close()`, call `globalThis.scrollTo(0, 0)`. Pattern: main.js, results.html, history.html, dossier.html.
- **Naming — Modes**: "Covert Recon Mode" = overarching dark theme name. Navbar tooltip: "Covert Recon Mode." Engineer's Report button: "Recon Mode." Recon Report exit: "Exit Covert Mode." Recon Report title: "Recon Report" (`<h1>`).

### Security
No inline `onclick` / `onchange` / `style=""`. Use `addEventListener` in nonce'd script blocks. All CSS/JS use SRI (SHA-384) computed at server startup via `InitSRI()` in `go-server/internal/templates/funcs.go`; `staticSRI` template fn returns `template.HTMLAttr`. Static URLs include content-hash cache-bust (`&h=...`) via `staticVersionURL()` — rebuild binary after any static asset change to recompute. Service worker (`static/sw.js`) self-destructs on any host other than `dnstool.it-help.tech`; `main.js` also unregisters SWs on non-prod as defense-in-depth. All Referer redirects validated (path starts `/`, no `//`). Nmap targets validated via `isValidNmapTarget()` regex. BIMI proxy has SSRF protection (HTTPS-only, private IP block, redirect validation, size limits). Cookies always Secure + HttpOnly + SameSite (prod: Strict for CSRF/flash, Lax for auth/OAuth; dev: Lax for all via `CookieSameSite(c)`). HSTS production-only. crypto/rand only in security paths. All SQL parameterized (sqlc).

### LLM-facing documentation
`static/llms.txt` and `llms-full.txt` include "Implementation Verification" (file paths, line counts, test counts, standards) and "Why This Level of Rigor Exists." Maturity tier names must match code: Development → Verified → Consistent → Gold → Gold Master. Hash references say SHA-3-512 (not SHA-256). Reveal structure, counts, standards — protect scoring formulas, weighting models, decision heuristics. Disclose AI-assisted development without naming specific tools.

### RFC posture
Findings cite RFC requirement level (MUST/SHOULD/MAY), acknowledge Informational vs Standards Track, then explain operational consequence. CVEs cited inline (CVE-2024-7208, -7209, -49040). Results pages have collapsible "RFC & Security Context" panels. DMARCbis tracked with forward-looking notes. In `results.html`, Analysis Confidence (ICD 203) and Intelligence Currency are collapsible (default closed) so DNS records appear first. IDs: `confidencePanel`, `currencyPanel`. Same pattern for Suggested Scanner Configuration.

### Notion + Founder's Voice
- **Project Phases**: `31c950b7-0b15-81ca-bc65-f731940b5442`
- **Goals & Benchmarks**: `257950b7-0b15-80cf-b77f-f607547cb77e`
- **Founder's Voice**: `31d950b7-0b15-817e-879b-e33aaa95950f` (linked view: `d3160e92-df4c-4930-88bd-d0e10812cf06`)
- **Retrieval protocol**: query DB → read page bodies for transcription blocks → cite evidence and stop. Never substitute from memory. See SKILL.md § "Founder's Voice Retrieval Protocol."
- **Editorial policy**: Light grammar/spelling/punctuation only. Never change a word that alters meaning.

### Triage & hygiene
- **GitHub Issues triage** (priority order): (1) Research Mission Critical (RFC/methodology/confidence-logic errors) — fix immediately. (2) Cosmetic UX/UI — normal cadence. (3) Security/Vulnerability — forward to non-public forum, never discuss in public issues.
- **Storage hygiene**: Periodically prune operational attachments (one-time uploads, non-auth zone results). Intelligence vault and historical data are preserved. Flag growth proactively.

### Subsystem reference
- Subsystem one-liners (Owl Semaphore, Black Site, EDE pipeline, Confidence Scores, Production Seed, Dev DB seeding, ICuAE, Feature Tiers, Golden Logic, ICSAE, MIME hardening, Video SEO, Internal video assets, WebMCP/origin-trial) live in `.agents/skills/dns-tool/SKILL.md` § "Subsystem Reference Index". Read it before touching any of these subsystems.

## System Architecture
- **Backend**: Go + Gin. PostgreSQL primary store (sqlc-generated queries).
- **Auth**: Google OAuth 2.0 with PKCE (S256). Three-tier entitlements (Open / Registered / Premium).
- **Analytics**: Privacy-preserving HyperLogLog++ for unique visitor counts.
- **Theming**: "Covert Mode" dark theme, four-layer color tokens, Emblem Gold + Accent Red, glass-styled SVG badges.
- **PWA**: Service worker (prod-host only), Apple splash, dynamic theme-color, Focus Mode.
- **SEO**: Schema.org JSON-LD, Open Graph, Twitter Cards.
- **Visualization**: Canvas 2D inside SVG foreignObject for the scan topology globe; orthographic projection with NASA Blue Marble texture.
- **Probing**: Multi-probe SMTP/DANE/Nmap; subdomain discovery via CT logs, DNS brute-force, external tools, SecurityTrails.
- **Engines**: ICIE, ICAE, ICuAE, ICSAE + CalibrationEngine + DimensionCharts (ICD 203 confidence + currency).
- **Logging**: Hybrid multi-sink structured logging with sensitive-data redaction.
- **Pipeline Observatory**: `/ops/pipeline` real-time pipeline view.
- **Handlers package layout**: split into `contentpkg`, `agentpkg`, `adminpkg`, `authpkg`, `badgepkg`.

## External Dependencies
PostgreSQL · Google OAuth 2.0 · SecurityTrails · `codeberg.org/miekg/dns` · Observe Probe Fleet (Kali VPS) · Nmap · Subfinder · Amass · HackerTarget · Dnsx · Testssl.sh · Httpx · Nuclei · Whois · `gonum.org/v1/gonum` · KaTeX (self-hosted) · Internet Archive (Wayback) · Moltbook · librsvg (`rsvg-convert`) · `github.com/kettek/apng`.
