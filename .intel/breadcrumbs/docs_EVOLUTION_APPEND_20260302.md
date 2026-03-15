# Evolution Log — v26.28.45 → v26.28.51

**Date Range:** 2026-02-28 → 2026-03-02  
**Sessions:** Performance, OPSEC, Responsive Design, Development Infrastructure

---

## v26.28.45 — Performance Optimization (2026-02-28)

- **Gzip compression**: Changed from BestSpeed to DefaultCompression. HTML drops from ~35KB to ~30KB, CSS from ~38KB to ~29KB transferred.
- **Owl image right-sizing**: Nav owl (80px display) now serves `owl-of-athena-160.webp` (22KB) instead of full 512px PNG (157KB). Footer owl (120px display) serves `owl-of-athena-240.webp` (42KB). Total savings: ~250KB per page load.
- **Preload hints**: Added `<link rel="preload">` for critical font (Inter) and CSS files to reduce render-blocking latency.
- **Public TTFB ~400ms**: Investigated and confirmed this is Replit's reverse proxy overhead, not fixable in application code.

## v26.28.46 — Video Styling + Test Coverage (2026-02-28)

- **Approach page video**: Restyled from full-width dark slab to contained presentation — `max-width: 560px` wrapper, poster image (`og-forgotten-domain.png`), "Case Study" label, descriptive caption below.
- **Test expansion**: Added `exports_ice_test.go` (30+ Export* wrapper functions), `coverage_boost14_test.go` (handler helpers), `main_test.go` (isStaticAsset, dir finders).
- **Coverage**: Analyzer 70.9%, Config 100%, Middleware 85.7%, cmd/server 6.1%.

## v26.28.47 — Probe OPSEC Cleanup + Repo Audit (2026-03-01)

- **Probe identifier scrub**: Removed ALL specific probe identifiers from public-facing content:
  - `llms.txt`, `llms-full.txt`: "Probe-01 (Boston)" → "geographically distributed verification nodes"
  - `roe.html`: "Our Probe-02 uses Nmap" → "Our probe infrastructure uses Nmap"
  - `ROADMAP.md`: "probe-02, Kali" → "Probe Network Expansion" with generic language
  - `SYSTEM_ARCHITECTURE.md`: "probe-us-01", "probe-kali-01" → "Anchor Node 1", "Anchor Node 2"
  - `TOOLS.md`: "probe-us-01 (SMTP)" → "SMTP Probe"
- **Internal code preserved**: `config.go`, `admin_probes.go`, and test files retain probe identifiers (required for functionality, never served publicly).
- **Full repo audit**: Security/IP/publicity scan — no credential leaks, no admin routes exposed, boundary matrix clean.
- **ROADMAP.md**: Updated to reflect v26.28.46.

## v26.28.48 — Navbar Single-Row Fix (2026-03-02)

- **Root cause**: Three-layer CSS cascade conflict. Foundation CSS had `.navbar > .container { flex-wrap: inherit }` inheriting `wrap` from `.navbar { flex-wrap: wrap }`. Critical inline CSS set `nowrap` but was overridden by foundation.min.css loading after.
- **Fix applied at all three layers**:
  - Critical CSS (`_head.html`): `.navbar>.container{display:flex;flex-wrap:nowrap}` + `.navbar-brand{flex-shrink:1;min-width:0}` + `.u-nav-controls{flex-shrink:0}`
  - Foundation CSS: Changed `flex-wrap: inherit` to `flex-wrap: nowrap`
  - Custom CSS: Reinforced with `min-width: 0` on brand

## v26.28.49 — Apple Device Responsive Refinement (2026-03-02)

- **Base-level flex properties**: Moved `flex-shrink: 1; min-width: 0; overflow: hidden` to ALL screen sizes (not just mobile media query).
- **iPhone SE breakpoint**: New `@media (max-width: 390px)` — brand font 0.9rem, tighter badge/tag sizing, reduced controls gap.
- **Touch target refinement**: Hamburger toggler min-width/height reduced from 48px to 44px (still meets Apple HIG 44pt minimum). Navbar buttons exempted from general `.btn` min-height rule.
- **Tested and passing**: iPhone SE (375px), iPhone Air (393px), iPhone 17 Pro Max (430px), iPad mini (768px), narrow desktop (600px), desktop (1024px) — across homepage, history, and sources pages.

## v26.28.50 — Development Database Seeding (2026-03-02)

- **Problem identified**: Development environment had 20 database tables, all empty (0 rows). All UI testing against empty state — never saw real-world layout behavior.
- **Root cause**: Replit provisions a separate PostgreSQL for development. Production uses Neon-backed PostgreSQL at `dnstool.it-help.tech`. Dev database had schema but no data, and nothing in the workflow populated it.
- **Solution**: Created `scripts/seed-dev-db.sql` — idempotent seed script (ON CONFLICT DO NOTHING) with:
  - 12 domain analyses spanning strong (cloudflare.com, google.com, cisa.gov), weak (evilhacker.com, purpleflock.com), mixed (github.com, stanford.edu), international (kisa.org.cy), no-mail (parked-domain.example), and layout stress test (subdomain.really-long-organization-name.co.uk)
  - 7 days of analysis_stats and site_analytics
  - ICE test run with 12 representative results across SPF/DMARC/DKIM/DNSSEC/DANE/MTA-STS/BIMI/CAA
  - 18 ice_maturity entries at various maturity levels (development through gold)
- **Zero PII, zero production data, zero secrets** — safe to commit to version control.
- **Run anytime**: `psql "$DATABASE_URL" -f scripts/seed-dev-db.sql`

## v26.28.51 — Intel Repo Sync + Process Fix (2026-03-02)

- **Intel sync gap identified**: Six versions (v26.28.45–50) developed with zero evolution logging in the Intel repo. Last Intel commit was March 1 (IP audit doc), last evolution entry was Feb 24.
- **Root cause**: Replit auto-pushes to origin (public repo) via checkpoints. Intel repo requires manual `node scripts/github-intel-sync.mjs push` calls — nobody was running them.
- **Synced this session**: EVOLUTION append, llms.txt, llms-full.txt, ROADMAP.md.

---

## Process Observations

- **Development-against-empty-tables anti-pattern**: Identified and fixed. The dev database seed script ensures we always see realistic data during development. Layout bugs hiding behind "No Analysis History" empty states are no longer possible.
- **Intel repo drift**: The manual sync process creates a silent divergence risk. When sessions focus on rapid iteration, Intel syncing gets deprioritized. Consider adding a pre-push checklist or session-end sync step.
- **CSS cascade debugging**: Foundation CSS's `flex-wrap: inherit` pattern is a Bootstrap convention that causes silent wrapping when the parent navbar has `flex-wrap: wrap`. Direct `nowrap` values are safer than `inherit` for any element that must never wrap.
