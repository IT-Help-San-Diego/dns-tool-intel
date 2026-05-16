# DNS Tool — Domain Security Audit

## Overview
OSINT platform for RFC-compliant domain security analysis (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, BIMI, MTA-STS, TLS-RPT, CAA). Generates ICD 203 technical and executive reports. See `.agents/skills/dns-tool/SKILL.md` for the full architecture, philosophy, and connected-ecosystem inventory.

## User Preferences

### Hard rules — never violate
- **CITATION.cff / codemeta.json — HANDS OFF**: ORCID-linked Zenodo artifacts. Never modify automatically. License must remain `BUSL-1.1`. Concept DOI `10.5281/zenodo.18854899` NEVER changes. CI guard `.github/workflows/guard_citation.yml` blocks regressions.
- **Two-Track Version Bump Law**:
  - **Dev bump** (routine): Edit ONLY `go-server/internal/config/config.go` → `Version = "X.Y.Z"`, then `bash build.sh` and publish. Nothing else changes.
  - **Release bump** (tag time only): Run `scripts/release-gate.sh X.Y.Z` — bumps all versioned artifacts. Only when Carey is ready to tag.
- **Zero Fabrication Rule**: NEVER invent real-world facts (addresses, names, dates, stats, credentials). Verify from authoritative source or leave empty / ask.
- **Claims**: Every claim must be backed by implemented code. Roadmap items say "on the roadmap." Use "evidence-weighted confidence scoring inspired by Bayesian reasoning" not "Bayesian calibration"; "tamper-evident snapshots" not "append-only proof"; "inspired by" not "modelled on."
- **Marketing Voice**: Never position against competitors. Position against the complexity of DNS and the consequence of getting it wrong. Lead with capability, not comparison.
- **EDE entries are immutable**: Amendments only on FACTUAL_ERROR or DIGNITY_OF_EXPRESSION grounds, must be declared explicitly. See SKILL.md § EDE enforcement checklist.
- **MAINTENANCE_NOTE env var**: User-controlled operational control. Never remove without explicit approval.
- **Replit checkpoint ≠ GitHub push**: Replit auto-checkpoints push to `gitsafe-backup`, NOT to GitHub `origin`. The sandbox blocks `git push`. To land changes on `origin/main` (IT-Help-San-Diego/dns-tool-intel), the agent MUST push explicitly via the GitHub Git Data API (`gh api repos/.../git/blobs|trees|commits|refs/heads/main`). Always verify the post-push origin state with `gh api repos/$REPO/contents/<file>` before claiming a change has landed.

### Process & quality gates
- **Development Process**: Research best-practices first (cite RFCs). Design before implementing. Write tests first. Check quality gates during development.
- **Dual-Environment Quality**: Verify every quality-affecting change in BOTH dev (localhost:5000) AND production (dnstool.it-help.tech). Use `npx lighthouse` against both. Dev preview runs in cross-site iframe — any new security header or cookie attribute MUST use `IsDevEnvironment` / `CookieSameSite(c)` pattern (strict prod, relaxed dev).
- **Standing Gates** (verify before EVERY phase transition): Lighthouse 100/100/100/100, Observatory 145+ (A+), SonarCloud A/A/A, Confidence Bridge, all 9 protocol analyzer test suites. Tracked in Goals & Benchmarks Notion DB.
- **After ANY Go change**: `go test ./go-server/... -count=1`
- **After CSS change**: `npx csso static/css/custom.min.css`
- **Always before delivering**: `node scripts/audit-css-cohesion.js` (R009), `node scripts/feature-inventory.js` (R011), `node scripts/validate-scientific-colors.js` (R010). All quality gates are HARD STOPS per ACIP v2.0 — see `docs/ACIP.md`.
- **Dev-Bump Cross-System Checklist**: After `bash scripts/dev-bump.sh X.Y.Z`, also update Notion Architecture Overview (`31c950b70b158108a5a5dc46eceae328`) and Phase 3 Version Range (`31c950b70b158196a670d758ad77f399`). DO NOT touch CITATION.cff / codemeta.json / methodology docs.
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

### Subsystem reference (one-liners — see code/docs for detail)
- **Owl Semaphore**: Three-state iconographic system (NORMATIVE / NON-NORMATIVE / CRITICAL) using O(2) transforms on Owl of Athena. Spec: `static/exports/dead-owl-icon/EXPORT-KIT.md`.
- **Black Site bug tracking** (Migration 010): `findings` / `observations` / `finding_events` tables. Severity S0–S4. Status machine: DETAINED→VERIFIED→UNDER_INTERROGATION→CONTAINED→RENDERED→REGRESSED→EXTRADITED→DISMISSED. Handler `internal/handlers/blacksite.go`, template `templates/black_site.html`, queries `db/queries/findings.sql`.
- **EDE pipeline** (Migration 011): `ede_events` + `ede_amendments` tables, JSON fallback (`static/data/integrity_stats.json`). Per-event SHA-3-512 hashes. Handler `internal/handlers/ede.go`. EDE dates must match verifiable git commits.
- **Confidence Scores** (Migration 012): `confidence_scores` table; per-scan/per-protocol; supports trending.
- **Production Seed** (Migration 013): `013_seed_findings_and_ede.sql` — idempotent (ON CONFLICT DO NOTHING), runs at startup via `internal/db/seed.go:RunSeedMigrations()`.
- **Dev DB seeding**: `psql "$DATABASE_URL" -f scripts/seed-dev-db.sql`. Never seed fake maturity progression.
- **ICuAE Expand/Contract**: `record_types_evaluated` (INTEGER count) + `record_types_list TEXT[]` co-exist; Go writes both.
- **Feature Tiers**: Open / Registered / Premium. Implementation in `internal/entitlements/`; `RequireFeature()` middleware in `internal/middleware/auth.go`. Plan ≠ role (RBAC). Design doc: `docs/plans/feature-tiers.md`.
- **Golden Logic** (drift detection): Registry at `docs/logic/registry.yaml` (git = source of truth, Notion + TheBrain = projections). Rule IDs like `LR-SPF-HARDFAIL-v1`, SHA-3-512 hashed, code/test refs. Detects logic / code / test / orphan / foundation / semantic drift. Design doc: `docs/plans/2026-03-08-golden-logic-design.md`.
- **ICSAE** (`dns-eval/`): Python standards engine. Schema v8 with 16 controls, ICD-203 confidence, ICIE Tier 1–8 sources, Chicago bibliography. Run: `cd dns-eval && python3 Mappings/normalize_input.py … && python3 Mappings/evaluate.py`. SPF ~all + DMARC p=reject is ACCEPTABLE; DNSSEC "inherited" with AD=true is VALID.
- **MIME Type Hardening**: All MIME types pre-registered via `mime.AddExtensionType()` in `init()` of `go-server/cmd/server/main.go` (Nix `/etc/mime.types` is broken in prod). Add new types there.
- **Video SEO** (BSI-2026-0017 fix): `/approach` and `/video/forgotten-domain` have VideoObject JSON-LD + WebVTT captions + posters.
- **Internal video assets** (brand voice): Rick Roll `https://youtu.be/ZzUsKizhb8o`, Shiiiiiaaat Roll (Clay Davis) `https://youtu.fm/7zUJ-dx2xXw` (used for ROE decliners in main.js).

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
