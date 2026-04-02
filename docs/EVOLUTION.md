# DNS Tool — Evolution Log (Breadcrumbs)

This file is the project's permanent breadcrumb trail — every session's decisions, changes, lessons learned, and rationale. It serves as a backup for `replit.md` (which may be reset by the platform) and as the canonical history of the project's evolution. If anything goes wrong, this is where you trace back what happened and why.

**Rules for the AI agent**:
1. At the start of every session, read this file AND `replit.md`.
2. At the end of every session, append new entries here with dates.
3. If `replit.md` has been reset/truncated, restore its content from this file.
4. **MANDATORY**: After ANY Go code changes, run `go test ./go-server/... -count=1` before finishing. This runs the boundary integrity tests that prevent intelligence leaks, duplicate symbols, stub contract breakage, and architecture violations.

---


## Session: March 18, 2026 (Scientific Accuracy Audit — Overclaim Correction, Documentation Reconciliation)

### Deep Architect Audit: Publication-Readiness Assessment
A comprehensive scientific accuracy audit was conducted across all public-facing documentation, LLM-facing files, user-visible templates, and methodology documents. The audit compared every claim against the actual codebase implementation.

### Findings & Corrections

#### 1. "Tamper-Proof" → "Tamper-Evident" (OVERCLAIM — Production-Visible)
- **Where**: `results.html` (2 instances), `llms.txt`, `llms-full.txt`
- **Problem**: DNSSEC and Wayback Machine descriptions used "tamper-proof" — the system is tamper-evident (makes unauthorized modification detectable), not tamper-proof (physically impossible to modify). The EDE page (`ede.html`) already used the correct terminology.
- **Fix**: All instances changed to "tamper-evident" with accurate supporting language.

#### 2. ICAE Maturity Taxonomy Mismatch (INACCURATE — Methodology Doc)
- **Where**: `docs/dns-tool-methodology.md` Section 4.1
- **Problem**: Listed maturity levels as "Verified/Assessed/Adequate/Development" — the actual code uses "Development/Verified/Consistent/Gold/Gold Master" with specific threshold requirements (consecutive passes + elapsed days).
- **Fix**: Replaced with the actual five-tier taxonomy from `go-server/internal/icae/icae.go` with correct thresholds.

#### 3. Confidence Factor Model Mismatch (INACCURATE — Methodology Doc)
- **Where**: `docs/dns-tool-methodology.md` Sections 4.2–4.3
- **Problem**: Described a five-factor model (evidence completeness, cross-resolver consistency, RFC compliance, temporal stability, dependency satisfaction) and weighted aggregation. Actual implementation uses a reliability-weighted shrinkage estimator based on resolver agreement ratio with protocol-specific priors.
- **Fix**: Replaced with accurate description of the calibration formula, explicitly noting it is a shrinkage estimator (not Bayesian posterior, per EDE-006).

#### 4. ICAE Overclaim on Approach Page (OVERCLAIM — Production-Visible)
- **Where**: `go-server/templates/approach.html`
- **Problem**: Claimed ICAE "validates every scoring decision against RFC-defined behavior." ICAE validates deterministic test-case coverage, not literally every runtime decision.
- **Fix**: Changed to "129 deterministic test cases verifying scoring logic against RFC-defined behavior."

#### 5. Discord Webhook Threshold (INACCURATE — replit.md)
- **Where**: `replit.md` line 52
- **Problem**: Described Discord sink as "WARN+" — actual code restricts Discord to ERROR+ or security-category events only.
- **Fix**: Corrected to "ERROR+ or security-category events only."

#### 6. Intelligence Vault Auto-Ingestion Overclaim (OVERCLAIM — MISSION.md)
- **Where**: `docs/MISSION.md` lines 52, 106
- **Problem**: Implied every public scan automatically feeds into the intelligence vault. Golden fixtures are curated test assets, not auto-populated by runtime scans. The Confidence Bridge operates at build time via build-tag gating.
- **Fix**: Clarified that golden fixtures are curated and that the bridge validates structural consistency between mock and golden fixture data.

### Items Confirmed Accurate
- ICAE = 129 test cases (45+42+27+15), ICuAE = 29 test cases / 5 dimensions, 9 protocols — all verified against code
- NIST SP 800-53 SI-7 citations — correct (SI-18 was already corrected in a prior session, documented in integrity_stats.json)
- Structured logging architecture description in replit.md — accurate (except Discord threshold, now fixed)
- Calibration metrics (Brier ~0.0018, ECE ~0.031) — reproducible via `go test`

### Task #8 & #10 History (March 8–18)
- **Task #8** (Scan Phase Telemetry): Progress callbacks with phase lifecycle events, Gantt timeline visualization, trend chart, analysis_id linkage, XSS hardening
- **Task #10** (Hybrid Structured Logging): Multi-sink architecture — stdout+JSONL (all levels), PostgreSQL ring buffer (WARN+), Discord (ERROR+/security only). Redaction engine, DB sink with atomic.Bool close guard, bounded channel worker, admin log dashboard with time-range filtering and JSONL export.

### Companion Document (Philosophical Foundations) — Audited
The companion paper (`docs/philosophical-foundations.md`) was reviewed for scientific accuracy. Result: **CLEAN** — no overclaims, no inaccurate technical assertions. The document correctly defers all ICAE/confidence/calibration claims to the primary methodology document and stays within its philosophical lane. Only its version stamp (26.35.40) was updated to 26.37.26 for consistency. The HTML version of the methodology doc (`docs/dns-tool-methodology.html`) was also updated with the corrected maturity taxonomy and calibration description.

### Methodology Version Note
Both `docs/dns-tool-methodology.md` and `docs/philosophical-foundations.md` have been updated to Version 26.37.26. Both PDFs and the Zenodo deposit will need regeneration for the next publication release.

---


## Session: March 7, 2026 (EDE-009 — Human Error Attribution, Accountability Architecture)

### EDE-009: Founder Lost Analytical Perspective During High-Pressure Debugging Session
- **Date**: March 4–6, 2026 (documented March 7, 2026)
- **Attribution**: Human Error
- **Category**: governance_correction
- **Severity**: significant
- **What happened**: During the highest-volume session in project history (431 commits across March 4–6 (132 + 138 + 161)), the founder departed from the research-first, design-first methodology. Repetitive directive cycles replaced structured problem decomposition. The scientific discipline that underpins the project's credibility was temporarily suspended by the scientist who established it.
- **Resolution**: All blocking issues resolved without checkpoint reversion — the project has zero Replit checkpoint reversions across its entire history. Anti-Circle Rules formalized. MEASURE → CHANGE → MEASURE → COMMIT established as mandatory process.
- **Why this EDE exists**: The founder demanded honest accountability from the system and from himself. The attribution is Human Error because the deviation from methodology was a human decision. Forward-only error correction through the problem, not around it.
### EDE-009 Date Correction (Same Session, March 7)
- **Corrected from**: February 21, 2026 (197 commits) — this was a different high-volume day
- **Corrected to**: March 4–6, 2026 (431 commits: 132 + 138 + 161) — the actual multi-day session where the founder sent repetitive messages and departed from structured methodology
- **Why corrected**: The founder identified the wrong date. The actual incident was within the last few days, not five weeks ago. Git commit history confirms March 4–6 as the highest sustained volume in project history (431 commits over 3 days vs 197 in a single day on Feb 21).
- **This correction is itself an integrity signal**: When the data was wrong, it was corrected immediately, with full audit trail.


- **Prevention Rule**: Before sending repetitive directives: state the goal in one sentence. Check quality gates. Write down expected changes. Check EVOLUTION.md for prior attempts. If you cannot decompose the problem, stop and decompose.

### EDE-006 Bayesian Note Correction
- **Changed**: Removed "marketing instinct (human) favored strong language" — the overclaim language appeared organically across sessions. Neither party specifically directed the use of "validates" over "analyzes." Root cause was absence of a language audit process, not a deliberate marketing decision by either party.
- **Why corrected**: The original language was cited as a direct quote from the founder, which was inaccurate. The founder never directed marketing language to override technical accuracy. The AI agent authored that root-cause analysis in EVOLUTION.md and it was presented as if it were a human directive.

### Attribution Model Status
EDE Register now has all four attribution types represented:
- **AI Error** (red): EDE-004, 005, 008 — the AI got these wrong
- **Human Error** (orange): EDE-009 — the founder got this wrong
- **Both** (purple): EDE-006, 007 — both contributed
- **Process Gap** (blue): EDE-001, 002, 003 — no individual fault, tooling gaps

### Lesson Learned
Public accountability is not weakness. Zero reversions across the project's entire history is a data point. The /ede page with full attribution badges is a credibility asset, not a liability. A scientist who records his own errors and shows exactly how he corrected them demonstrates the rarest kind of intellectual honesty.

---

## Session: February 20–21, 2026 (v26.21.43–v26.21.55 — SHA-3-512 Migration, Download Verification, ICAE Visual Overhaul, Audit Log)

### v26.21.43–v26.21.44 — Cryptographic Hash Migration: SHA-256 → SHA-3-512

#### Changes
- **`integrity_hash.go`**: `ReportIntegrityHash()` migrated from `crypto/sha256` (`sha256.Sum256`) to `golang.org/x/crypto/sha3` (`sha3.Sum512`). Output now 128-char hex (512-bit) instead of 64-char (256-bit).
- **`posture_hash.go`**: `CanonicalPostureHash()` now uses `sha3.Sum512`. New `CanonicalPostureHashLegacySHA256()` function added for backward compatibility with existing records.
- **`posture_hash_test.go`**: All golden-rule test expectations updated to SHA-3-512 hashes.
- **Backward compat**: ICAE hash audit detects hash length (64 chars = legacy SHA-256, 128 chars = SHA-3-512) and uses the appropriate recomputation function.

#### Rationale
SHA-3 (Keccak) is NIST FIPS 202. Provides defense-in-depth against future SHA-2 weaknesses. All new analyses produce SHA-3-512 hashes; legacy records remain verifiable via the backward-compatible path.

### v26.21.45 — ICAE Hash Integrity Audit Engine

#### New Files
- **`go-server/internal/icae/hash_audit.go`**: `HashAuditResult` struct + `AuditHashIntegrity()` function. Queries recent hashed analyses, recomputes posture hashes from stored JSON, compares against stored values. Calculates integrity percentage. Logs warnings for mismatches.
- **`go-server/internal/icae/icae.go`**: Added `HashAudit *HashAuditResult` to `ReportMetrics` struct.

#### Confidence Page
- New "Hash Integrity Audit" card on `/confidence` page showing: Audited, Verified (green), Mismatched (red if >0), Integrity %. Uses new `.icae-hash-stat` CSS component.

### v26.21.46 — Accountability Log

#### New Files
- **`go-server/internal/handlers/audit_log.go`**: Route `/confidence/audit-log` with pagination (50 entries/page). Shows every hashed analysis with domain, timestamp (UTC), and SHA-3-512 posture hash.
- **`go-server/templates/audit_log.html`**: Dark-themed table, pagination controls, footer explaining deterministic canonical serialization.

### v26.21.47–v26.21.48 — ICAE Two-Layer Visual Distinction

#### Changes
- **Collection layer**: `#4dd0e1` (muted cyan) → `#00e5ff` (vivid cyan) with `font-weight: 700`
- **Analysis layer**: `#ce93d8` (muted purple) → `#ea80fc` (vivid magenta) with `font-weight: 700`
- 10 new per-tier fill gradient rules for each layer (collection + analysis × 5 maturity tiers)
- Color-matched progress needles with matching glow effects
- Layer-specific track backgrounds with colored borders
- `confidence.html`: Only the layer name word gets the color class, not the arrow/target text

### v26.21.49–v26.21.50 — Download & Verify Intelligence (Kali-Style)

#### New Feature
- **`analysis.go`**: Refactored `APIAnalysis()` into `buildAnalysisJSON()` + `loadAnalysisForAPI()` helpers. Deterministic JSON serialization with `sha3.Sum512` over exact bytes. `X-SHA3-512` response header on downloads.
- **New endpoint**: `/api/analysis/{id}/checksum` — JSON format (default) or `.sha3` sidecar file (with `?format=sha3`).
- **Kali-style sidecar** (`.sha3` file): Contains hacker poem Easter egg + RFC 1392 "hacker" definition + algorithm ID + verify command + standard checksum line. Compatible with `sha3sum --check`.

#### Easter Egg: Hacker Poem
```
# Cause I'm a hacker, baby, I'm gonna pwn you good,
# Diff your zone to the spec like you knew I would.
# Cite those RFCs, baby, so my argument stood,
# Standards over swagger — that's understood.
#
# — DNS Tool / If it's not in RFC 1034, it ain't understood.
```
Plus RFC 1392 disclaimer: "'Hacker' per RFC 1392 (IETF Internet Users' Glossary, 1993): 'A person who delights in having an intimate understanding of the internal workings of a system, computers and computer networks in particular.' That's us. That's always been us."

#### Results Template
- New "Download & Verify Intelligence" card with SHA-3-512 badge, two exposed buttons (Download Raw Intelligence + Download Checksum), expandable verification commands (OpenSSL + Sidecar, Python 3, sha3sum)
- "Show verification commands" clickable hint below download buttons
- `cd ~/Downloads` tip for non-technical users

### v26.21.51–v26.21.52 — Reproduce the Evidence Card + Posture Drift UX

#### Changes
- **Card rename**: "Verify It Yourself" → "Reproduce the Evidence" — differentiates from download integrity verification. Card 1 is file integrity (did the download arrive intact?). Card 2 is data transparency (can you reproduce our findings independently?).
- **Updated description**: "Every finding in this report is backed by DNS queries you can run yourself. These vetted one-liners reproduce the exact checks used to build this report for **{domain}**."
- **Posture drift**: Added human-readable explanation when hash changes without specific protocol status diffs: "The posture hash changed due to differences in DNS record values, ordering, or TTLs..."
- **Public suffix guard**: Test Send Recommendation now gated by `{{if and .DomainExists (not .IsPublicSuffix)}}` — prevents recommending test sends for TLDs.

### v26.21.53 — OpenSSL + Sidecar Combo Command

#### Changes
- First verification command changed from standalone `openssl dgst -sha3-512` to combined `cat .sha3 && echo '---' && openssl dgst -sha3-512` — shows hacker poem + expected hash + separator + computed hash in one terminal session. Users see both outputs for visual comparison.

### v26.21.54 — Expand Affordance UX

#### Changes
- "Download & Verify Intelligence" card: Added explicit "Show verification commands ▾" clickable text below download buttons with red terminal icon
- "Reproduce the Evidence" card: Simplified chevron-in-header (no competing buttons)

### v26.21.55 — Placeholder Fix + RFC Consistency Audit

#### Changes
- Homepage placeholder: `example.com or .com` → `example.com or com` (no leading dot; users enter TLDs without the dot)
- RFC consistency audit confirmed: "DNS, same way since 1983" (RFC 882/883 origin) and "If it's not in RFC 1034, it ain't understood" (canonical spec) are complementary, not contradictory. Heritage vs. authority — both factually correct.

#### Hacker Poem Appearances
The poem now appears in three places:
1. `index.html` HTML comment (view-source Easter egg)
2. `.sha3` sidecar file (download verification)
3. `analysis.go` (server-side generation of sidecar)

---

## Session: February 20, 2026 (v26.21.42 — Chrome Scroll Fix, SW Cache Hardening, Mobile Regression Prevention)

### v26.21.42 — Chrome Scroll Belt-and-Suspenders + SW Network-First

#### Changes
- **Explicit `overflow-y: auto`** on body and html — eliminates ambiguity in Chrome's overflow computation when `overflow-x: hidden` is set
- **Changed `overscroll-behavior: none` → `overscroll-behavior-x: none`** — only prevent horizontal overscroll, explicitly leave vertical scroll untouched
- **Service worker: network-first for versioned assets** — changed from stale-while-revalidate (cache || network) to network-first (network with cache fallback). Ensures fresh CSS/JS always wins when online. Old SW cached stale CSS containing the `pointer-events: none` bug, causing users to see the scroll-blocking version even after the fix was deployed.
- **CSS minification directive strengthened** — added explicit warning that server loads minified file only; forgetting `npx csso` means changes don't appear on the live site.

#### Root Cause (Scroll Bug Persistence)
The v26.21.40 CSS fix was correct, but users' service workers cached the OLD CSS (with `pointer-events: none` on body). The SW's stale-while-revalidate strategy served cached CSS before checking the network. Since the CSS URL included `?v=` version parameter, the old URL matched the old cache. The new SW (with new version) would eventually install and clear old caches, but there was a window where stale CSS persisted.

### v26.21.41 — Mobile Button Wrapping Fix + Regression Prevention Framework

#### Changes
- Added `white-space: nowrap` to action buttons preventing label wrapping on iPhone (375px)
- Added DOD.md "Mobile UI Verification" checklist (8 mandatory checks, 4 known failure patterns)
- Added anti-patterns #15-16 to SKILL.md
- Added Gotcha #5 to EVOLUTION.md
- Added Critical Rule #13 to replit.md

---

## Session: February 20, 2026 (v26.21.39 — Authoritative Sources Registry & Codebase Accuracy Audit)

### v26.21.39 — Authoritative Sources, Gotchas Framework, Codebase Accuracy Audit

#### Authoritative Sources Registry (AUTHORITIES.md)

Created `AUTHORITIES.md` — the canonical reference of every standards body, RFC, regulatory authority, and data source this project relies on. Every claim in code, templates, documentation, and UI copy must trace back to an entry here.

**Organized by:**
1. Standards bodies (IETF, NIST, CISA, FIRST, CA/Browser Forum, BIMI Group)
2. IETF RFCs by functional area (email auth, DNS infrastructure, web/AI governance, misc)
3. Quality gate authorities (Lighthouse, Observatory, SonarCloud)
4. Data sources (Team Cymru, OpenPhish, SecurityTrails, crt.sh, RDAP, ip-api.com)
5. Non-standard/proprietary directives we track (Content-Usage, Content-Signal, llms.txt, security.txt)
6. Verification checklist — 5-point check before citing any source
7. Update protocol — when and how to maintain the registry

**Key rule**: Before implementing any feature that references a standard, verify its current status at the authoritative URL. Drafts change, RFCs get obsoleted, assumptions rot.

#### robots.txt — Content-Usage Removed (Lighthouse Fix)

**Problem**: Content-Usage directives (`ai=allow`, `ai-training=allow`, `ai-inference=allow`) in our robots.txt caused Lighthouse to flag "Unknown directive" errors, tanking SEO score.

**Root cause**: Content-Usage is an active IETF working group draft (draft-ietf-aipref-attach), NOT a ratified standard. Lighthouse only recognizes RFC 9309 directives. Using an unratified directive in production violated our own quality gates.

**Fix**: Removed all Content-Usage directives from our robots.txt. Added detailed comment explaining our position: we permit AI crawling but refuse to use unratified directives that break quality gates. Our AI Surface Scanner still detects Content-Usage on scanned domains — that's intelligence gathering, not endorsement.

**Result**: robots.txt now contains only RFC 9309-compliant directives. 25 lines → 30 lines (added explanatory comments).

#### Deep Codebase Accuracy Audit — Findings & Fixes

Systematic audit of all templates, docs, and code for overstated claims:

1. **llms.txt "Proposed Standard" → "Community Convention"**: `results.html` tooltip said "llms.txt Proposed Standard" with an RFC 8615 link. RFC 8615 defines .well-known/ mechanics, not llms.txt. llmstxt.org is a community convention, not an IETF standard. Fixed tooltip and removed false RFC 8615 association.

---

## Session: March 11, 2026 (v26.36.02 — SonarCloud Deep Audit & Cross-System Sync)

### v26.36.02 — SonarCloud Deep Audit, UI/UX Safari Compatibility

#### SonarCloud Audit
- **91 suppression rules** in `sonar-project.properties` individually audited — unjustified suppressions removed, justified ones retained with inline code comments explaining rationale
- **34 coverage_boost test files** (~19,800 lines, 973 test functions) audited for test quality — tests with genuine assertions kept, pure coverage padding refactored or removed
- Security hotspots reviewed with documented rationale: TLS skip verify in `smtp_transport.go` and probe are intentional for opportunistic TLS/security scanning
- `go vet ./go-server/...` clean, build succeeds for both OSS and intel tags

#### Safari / Mobile Compatibility Fixes
- **DKIM selector inputs** (`index.html`): Added `autocapitalize="none"` and `spellcheck="false"` — iOS was auto-capitalizing DKIM selector names
- **SecurityTrails API key inputs** (`index.html`, `investigate.html`, `results.html`): Added `autocapitalize="none"` — iOS auto-caps on password fields varies by context
- **IPinfo token input** (`investigate.html`): Added `autocapitalize="none"`
- Verified: Scan overlay uses `fetch()` + `DOMParser` pattern (not `location.href`) — Safari-safe
- Verified: Fullscreen API has both standard and `webkit` prefixed fallbacks (`webkitRequestFullscreen`, `webkitExitFullscreen`, `webkitfullscreenchange`)
- Verified: Focus Mode button hidden when Fullscreen API unavailable
- Verified: `theme-color` meta tag dynamically updates for covert mode environments

#### Icon System
- Project uses inline SVG registry (`go-server/internal/icons/icons.go`) auto-generated from Font Awesome Free 6.x — NOT CSS subset + WOFF2 font. Icons cannot go missing due to CSS subset gaps.
- `audit_icons.py` script references obsolete `fontawesome-subset.min.css` path — flagged for update

#### Cross-System Sync
- EVOLUTION.md updated with this breadcrumb entry (pushed via `github-intel-sync.mjs`)
- Notion Session Journal: Session 37 entry created with all extended fields
- Notion Phases: Phase 3 version range updated to `v26.36.02`
- Notion Roadmap: All SonarCloud-related items confirmed "Done"
- Notion EDE Register: No new epistemic corrections required from this audit
- TheBrain: No MCP integration available — requires manual update

---

## Session 38 — Topology Redesign & Release Cleanup (2026-03-18)

### Scan Topology Node Redesign (Glass Circles with Concentric Rings)
- **Replaced** all 9 filled solid rectangular `<rect>` nodes in `_scan_topology.html` with uniform glass/transparent `<circle>` elements
- **Three concentric layers per node**: outer dashed halo ring (r=38, `.topo-halo`), status indicator ring (r=34, `.topo-ring`), glass body (r=28, `.topo-node`)
- **Glass body**: radial gradient fill (`node-glass`) with highlight overlay (`node-highlight`) — stays transparent at all times, never fills solid
- **Status communicated via outer rings only**: running phases pulse the status ring with phase color, completed phases light up ring + halo with glow filter
- **`<g>` group wrappers**: Each node wrapped in `<g data-phase="..." data-pkey="...">` — CSS child selectors (`.phase-done-dns .topo-ring`) handle styling
- **No JavaScript changes needed**: existing `querySelector('[data-phase]')` finds the group, CSS descendant selectors do the rest
- **Labels split to two lines** for readability inside circles (e.g., "DNS" / "Records", "DNSSEC" / "DANE")
- **Connector lines updated** to use circle center coordinates
- **Scientific data uniformity**: matches resolver dots on the globe — uniform circles with ring-based indicators

### Previous Session Changes Documented
- **Covert badge contradiction fixed**: `covertSummaryLines()` now requires `vectors <= 2 && vulnerable <= 1` for "mostly locked down" text
- **Empty history/compare/dossier badges**: Added `{{else}}` neutral fallback badges for unknown/empty SPF/DMARC/DKIM status
- **Web3 node added to detailed badge SVG topology**: Positioned at `{558,178}` with edge connecting Web3 to CAA

### Release Cleanup
- CSS audit: verified potentially unused classes (arch-standard-card, exec-finding-row, etc.) are in fact used in templates
- Template CSP audit: signature_raw.html inline styles confirmed correct (email signature requires inline CSS)
- Admin telemetry inline styles moved to CSS classes
- Documentation sweep: replit.md, EVOLUTION.md, llms.txt updated
- Quality gate verification: badge tests passing, build succeeds
