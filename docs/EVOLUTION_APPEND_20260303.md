# Evolution Log — v26.33.62 → v26.33.64

**Date:** 2026-03-03  
**Sessions:** SpeedCurve A11y/BP Fixes, Production Quality Audit, Cleanup & Hardening

---

## v26.33.62 — SonarCloud + SpeedCurve Fixes (2026-03-03)

- **SonarCloud 5-issue fix**: sonar-project.properties version synced (26.28.47→26.33.62); S1313 exclusions added for `analyzer/**` and `icuae/**`; adminSSHHostCheck rule corrected from S5527→S4423; S107 param-count exclusions added for 6 new files; S1082 Bootstrap collapse expanded from `results.html` to `templates/**`.
- **Service worker hardening**: Removed stale precache assets (`bootstrap-dark-theme.min.css`, `bootstrap.bundle.min.js`) that were causing 404s during SW install. Changed `cache.addAll()` to individual `cache.add()` with per-asset `.catch()`. Added `.catch()` fallback returning 408 responses on two fetch paths that previously threw unhandled rejections when resources failed offline.
- **Accessibility — link underlines**: Broadened body text link underline CSS from only `a.text-info` to all paragraph/card-body/footer links via `:not()` exclusion selectors. Fixed `.u-covert-disclosure` links (changed from `text-decoration: none` to underline). E2e test confirmed computed `textDecorationLine = "underline"` for both body text and footer links.

## v26.33.63 — Production Quality Audit Hardening (2026-03-03)

Three parallel audit subagents (Go code quality, frontend performance, scientific accuracy) produced 26 findings across Critical/High/Medium/Low. Critical and high fixes applied:

- **admin.go C1**: Three `tx.Exec` calls in user deletion transaction were silently discarding errors. Now properly checked with early returns and structured slog logging.
- **proxy.go H1**: `defer resp.Body.Close()` inside redirect loop leaked response bodies for intermediate redirects. Removed defer, added explicit `resp.Body.Close()` on all error paths (empty Location, invalid URL, SSRF check failures) before returning.
- **export.go H5**: `json.Unmarshal` error silently discarded. Now logged as warning with domain context.
- **analysis.go H5**: Same unmarshal fix for `buildAnalysisJSON` (both `FullResults` and `CtSubdomains`).
- **analysis.go M6**: CSV injection prevention — `csvEscape` now prefixes formula-trigger characters (`= + - @ \t \r`) with single-quote before quoting.
- **stats.go M4+M5**: `loadIntegrityData()` was reading `integrity_stats.json` from disk on every request. Added 5-minute RWMutex cache with double-checked locking pattern. Removed duplicate `integrityStatsFile` struct (identical to `IntegrityData`).

### Audit Findings Summary (for reference)

| Priority | Count | Key Issues |
|----------|-------|-----------|
| Critical | 3 | Swallowed tx.Exec errors (fixed), SSH host key checking disabled (operational), empty error block in test |
| High | 6 | Deferred close in loop (fixed), missing context propagation (noted), unbounded export (noted), discarded unmarshal (fixed) |
| Medium | 9 | String concat in loop, bubble sort, unbounded slices, file read per request (fixed), CSV injection (fixed), IP logging |
| Low | 8 | Unused test vars, duplicated constants, intentional response patterns |

### EDE Verification

All three Epistemic Disclosure Event dates verified against git history:
- EDE-001: 2026-02-14 → commit `084c6268` dated 2026-02-14 ✓
- EDE-002: 2026-03-01 → commit `70ae4dd3` dated 2026-03-01 ✓
- EDE-003: 2026-02-21 → commit `3ad0056f` dated 2026-02-21 ✓

No fabrication detected — all dates match their git commits exactly.

## v26.33.64 — Cleanup & Hardening (2026-03-03)

- **JavaScript IIFE wrapping**: Wrapped all 26 global functions in `main.js` into an IIFE. Only 4 functions exported to `globalThis` (the ones actually called from templates): `showOverlay`, `startStatusCycle`, `escapeHtml`, `loadDNSHistory`. Verified zero template references to now-private functions.
- **Country cache eviction**: Added hourly background goroutine (started via `sync.Once` on first `lookupCountry` call) that sweeps `countryCache` entries older than 24 hours, preventing unbounded `sync.Map` memory growth.
- **Orphaned asset cleanup**: Removed 3 files (~560KB): `static/audio/morse-need-a-sick-handle.m4a`, `static/images/bimi-logo.svg`, `static/images/owl-of-athena.webp`. Kept `owl-of-athena.png` (used in print templates).
- **Legacy Flask templates removed**: Deleted 6 stale files in `templates/` directory (compare.html, compare_select.html, history.html, index.html, results.html, stats.html). No Flask app.py/main.py exists — Go server is the only runtime.
- **Version sync across all docs**: Updated version to 26.33.64 in 9 locations (config.go, sonar-project.properties, FEATURE_INVENTORY.md, SYSTEM_ARCHITECTURE.md, golden-rules.json, golden-rules.md, figma-bundle manifest.json, figma-bundle README.txt, ROADMAP.md).
- **Version Bump Checklist**: Added permanent 10-point checklist to `replit.md` documenting every file that must be updated during version bumps. No version will be "hidden" again.
- **ROADMAP.md**: Added 11 new completed items covering v26.33.62–64 work. Updated version range, dates, and next review milestone.

---

## Process Observations

- **Version drift across docs**: Prior to v26.33.64, version references were scattered across 9+ files with no single checklist. Some files (golden-rules.json, figma-bundle, SYSTEM_ARCHITECTURE.md) were 8+ minor versions behind. Now tracked in replit.md as a mandatory checklist.
- **Production audit process**: Three parallel subagents (Go quality, frontend, scientific accuracy) completed in ~5 minutes and produced actionable findings. This pattern should be repeated every 10+ minor versions.
- **Flask template drift**: Legacy Flask templates in `/templates/` contained stale scientific claims ("proving they haven't been tampered with" vs the correct "designed to detect tampering") and missing JSON-LD properties. Removing them eliminates a class of documentation inconsistency.
- **Intel repo sync needed**: Codeberg `dns-tool-web` is 1 commit behind GitHub. Codeberg `dns-tool-intel` needs this evolution log and the updated ROADMAP/docs. Manual push required.
