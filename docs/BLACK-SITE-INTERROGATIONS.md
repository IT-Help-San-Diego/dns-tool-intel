# Black Site Interrogations

> *Repetitive, evil, disgusting bugs that we rendition, track, trace, and eliminate.*
> *When we get a hold of them, it looks like we sent them to a black site.*

**Created**: 2026-03-18
**Status**: ACTIVE — Full UX/UI/Performance/Accessibility Audit
**Audit Standard**: UX/UI Conference Scrutiny — "Scientists who claim to have really paid attention"
**Audit Agents**: 5 parallel (SquirrelScan Technical, Engineer Report UX, Navigation/Pages UX, CSS/Design System, Architect Strategic)

---

## Severity Classification

| Level | Meaning |
|-------|---------|
| **RENDITION** | Existential — will embarrass us at a conference. Fix before publish. |
| **INTERROGATION** | Serious UX/functional bug. Fix in current sprint. |
| **SURVEILLANCE** | Design debt or inconsistency. Track and fix systematically. |
| **WATCH LIST** | Minor polish. Address when touching related code. |

---

## RENDITION — Fix Before Publish

### BSI-001: Covert Mode Is Page Navigation, Not Toggle
- **Source**: T002 (Engineer Report UX), T005 (Architect)
- **Location**: `src/js/main.js:593-606`
- **Issue**: On Engineer's Report, pressing the covert button navigates to `/analysis/{id}/view/C` (full page load). Pressing it again navigates back to `/view/E`. Users lose scroll position. On non-results pages, it's a client-side class toggle. Behavior is inconsistent.
- **User Report**: "When you press the red button it works. But then if you hit it again, nothing happens."
- **Impact**: Core interaction feels broken. Conference demo killer.
- **Status**: OPEN

### BSI-002: Glass Treatment Only on Posture Cards — Confidence/Currency Cards Dead
- **Source**: T002, T004 (CSS Audit)
- **Location**: `src/css/custom.css:1087-1135`, `go-server/templates/results.html:519,560`
- **Issue**: Only cards with exact class combo `card.border-{status}.bg-{status}.bg-opacity-10` get glassmorphism. Confidence card uses `card border-{color} bg-dark` — no glass. Currency card uses `card bg-dark border-accent-gold-muted` — no glass. Domain Summary uses `bg-primary bg-opacity-10` — doesn't match the CSS selectors.
- **Impact**: Inconsistent visual language. Some cards hover-lift, some are dead slabs.
- **Status**: OPEN

### BSI-003: Golden Ratio / Fibonacci Claims Not Evidenced in Layout
- **Source**: T005 (Architect)
- **Issue**: Typography/spacing scales are ad hoc (`0.75`, `0.8`, `0.85`, `1.1`, `3.5`, `2.5`, etc.) rather than a coherent modular ratio. Only the scan topology SVG has a documented golden ratio (320/198 ≈ φ). The claim "Fibonacci math" has no systematic backing in the CSS type scale, spacing, or card proportions.
- **Impact**: If someone at a conference checks the math, we get exposed. The claim is the topology, not the layout system.
- **Status**: OPEN — needs either implementation or honest scoping of the claim

### BSI-004: No `prefers-reduced-motion` in CSS
- **Source**: T004 (CSS Audit), T005 (Architect)
- **Location**: Entire `src/css/custom.css` — absent
- **Issue**: Users who set "Reduce Motion" in OS settings still see all transitions, transforms, animations, and the covert toggle animation. WCAG 2.1 SC 2.3.3 requires this. JS handles it for the topology SVG SMIL animation, but CSS transitions are completely unprotected.
- **Impact**: WCAG compliance failure. Accessibility conference would flag immediately.
- **Status**: OPEN

### BSI-005: Stats Metric Label Fails WCAG Contrast (2.1:1)
- **Source**: T003 (Navigation UX)
- **Location**: `go-server/templates/stats.html:158-159`
- **Issue**: `.stats-confidence-metric-label { color: #484f58; }` on `#0d1117` background has ~2.1:1 contrast ratio. WCAG AA requires 4.5:1 for small text.
- **Impact**: Hard accessibility violation. Screen readers aside, humans literally can't read it.
- **Status**: OPEN

### BSI-006: Compare Select Rows Not Keyboard Accessible
- **Source**: T003 (Navigation UX)
- **Location**: `go-server/templates/compare_select.html:170-219`
- **Issue**: Compare rows use click handlers on `<tr>` elements with no `tabindex="0"` or `role="button"`. Keyboard-only users cannot select comparison domains.
- **Impact**: Accessibility violation. Any keyboard user is locked out.
- **Status**: OPEN

### BSI-007: Broken Internal Links — 404 SVGs on Architecture Page
- **Source**: T001 (SquirrelScan)
- **Location**: `/architecture` page
- **Issue**: `/static/images/diagrams/drift-notification-pipeline.svg` and `/static/images/diagrams/github-issues-triage.svg` return 404.
- **Impact**: Broken content on a page that shows our engineering rigor. Ironic.
- **Status**: OPEN

### BSI-008: Copy Buttons Invisible to Keyboard Users
- **Source**: T002 (Engineer Report UX)
- **Location**: `src/css/custom.css:1030`
- **Issue**: `.copy-btn` has `opacity: 0` by default, only visible on hover. Keyboard-only users cannot see or reach these buttons.
- **Impact**: Keyboard accessibility violation. Copy functionality inaccessible.
- **Status**: OPEN

---

## INTERROGATION — Current Sprint

### BSI-009: Anchor Link Scroll Conflicts with Bootstrap Collapse
- **Source**: T002 (Engineer Report UX)
- **Location**: `src/js/main.js:944-955`
- **Issue**: Generic smooth-scroll handler on ALL `a[href^="#"]` links calls `e.preventDefault()`, which can prevent Bootstrap collapse triggers that use `href="#target"` instead of `data-bs-target`.
- **Impact**: Some collapsible sections may silently fail to toggle.
- **Status**: OPEN

### BSI-010: `white-space-nowrap` Typo in Template
- **Source**: T002 (Engineer Report UX)
- **Location**: `go-server/templates/results.html:579`
- **Issue**: Uses class `white-space-nowrap` which doesn't exist. Should be Bootstrap's `text-nowrap`.
- **Impact**: Buttons may wrap unexpectedly on mobile.
- **Status**: OPEN

### BSI-011: `border-accent-gold-muted` Class Doesn't Exist
- **Source**: T002 (Engineer Report UX)
- **Location**: `go-server/templates/results.html:560`
- **Issue**: Currency card uses `border-accent-gold-muted` — no CSS rule exists for this class. Border falls back to default, making the card look generic.
- **Impact**: Visual inconsistency on every analysis page.
- **Status**: OPEN

### BSI-012: DNS Hosting Column Missing `text-truncate`
- **Source**: T002 (Engineer Report UX)
- **Location**: `go-server/templates/results.html:1226`
- **Issue**: DNS Hosting column doesn't have `text-truncate` while Registrar, Email, and Web Hosting columns do. Long hosting names overflow on mobile.
- **Status**: OPEN

### BSI-013: Chevron Icons Don't Rotate on Collapse
- **Source**: T002 (Engineer Report UX), T003 (Navigation UX)
- **Location**: Multiple collapse panels in `results.html`, `index.html`
- **Issue**: Chevron-down icons remain pointing down when sections are expanded. No rotation animation or icon swap. `allFixesCollapse` handler (main.js:982) does swap, but individual panels don't.
- **Impact**: Visual feedback gap — users can't tell if panel is expanded/collapsed from the icon.
- **Status**: OPEN

### BSI-014: Tooltips Not Initialized on Non-Results Pages
- **Source**: T002 (Engineer Report UX)
- **Location**: `src/js/main.js` (no tooltip init), `go-server/templates/results.html:6834-6838` (results-only init)
- **Issue**: Bootstrap tooltips initialized only in results.html inline script. Any tooltips on comparison, history, or other pages won't work.
- **Status**: OPEN

### BSI-015: Navbar Collapse No Max-Height / Scroll
- **Source**: T003 (Navigation UX)
- **Location**: `src/css/custom.css:1362-1417`
- **Issue**: Navbar collapse dropdown is `position: absolute` with no `max-height` or `overflow-y: auto`. With 11+ nav items, menu extends below viewport on shorter screens with no way to scroll.
- **Status**: OPEN

### BSI-016: Footer Links Dense Paragraph at 375px
- **Source**: T003 (Navigation UX)
- **Location**: `go-server/templates/_footer.html:32`
- **Issue**: 10+ footer links in a single `<p>` tag separated by `&middot;`. At 375px, becomes a wall of text. No column layout or grouping.
- **Status**: OPEN

### BSI-017: Video Score F (57/100)
- **Source**: T001 (SquirrelScan)
- **Issue**: Video category scored 57/100 (F). Likely missing VideoObject schema, accessibility attributes, or poster images.
- **Status**: OPEN — needs investigation

### BSI-018: Leaked Secrets in Page Source
- **Source**: T001 (SquirrelScan)
- **Location**: `/auth/login`, `/analysis/6141/view`
- **Issue**: Google OAuth Client ID exposed in inline script. Sanity Token exposed in analysis HTML.
- **Impact**: Security scanner flagged. OAuth client IDs are semi-public but shouldn't be in raw HTML. Sanity tokens are more concerning.
- **Status**: OPEN — needs investigation to confirm scope

### BSI-019: CSP script-src Allows Wildcard
- **Source**: T001 (SquirrelScan)
- **Issue**: Content-Security-Policy `script-src` uses wildcard `*`, allowing scripts from any origin. Should be restricted to specific trusted domains.
- **Impact**: Security posture contradiction — we audit DNS security but have a wide-open CSP.
- **Status**: OPEN

---

## SURVEILLANCE — Design Debt

### BSI-020: 908 `!important` Declarations in custom.css
- **Source**: T004 (CSS Audit)
- **Issue**: ~450 in covert mode alone. Architecturally inevitable without CSS `@layer`, creating specificity ceiling.
- **Recommendation**: Adopt CSS `@layer` (supported since March 2022) for `base < dark-theme < covert` cascade.
- **Status**: TRACKING

### BSI-021: 50+ Hardcoded Hex Colors Outside CSS Variables
- **Source**: T004 (CSS Audit)
- **Location**: `#8b949e` (5 locations), `#e6edf3` (6 locations), `#1a1a2e`, etc.
- **Recommendation**: Migrate to CSS custom property references.
- **Status**: TRACKING

### BSI-022: Inconsistent Backdrop-Filter Blur Radius
- **Source**: T004 (CSS Audit)
- **Issue**: 4 different blur values (12px/8px/6px/4px) with no documented rationale. Should be design tokens.
- **Status**: TRACKING

### BSI-023: Inconsistent Transition Timing (5+ Values)
- **Source**: T004 (CSS Audit)
- **Issue**: `0.15s`, `0.2s`, `0.25s`, `0.3s`, `0.35s` — should be standardized to 2-3 named durations via CSS custom properties.
- **Status**: TRACKING

### BSI-024: `transition: all` Performance Anti-Pattern
- **Source**: T004 (CSS Audit)
- **Location**: Lines 1750, 2289, 2301, 2314, 2326, 2338
- **Issue**: Animates all properties including width/height. Should specify exact transition properties.
- **Status**: TRACKING

### BSI-025: Inconsistent Breakpoint Syntax
- **Source**: T004 (CSS Audit)
- **Issue**: Mixes `767px`, `767.98px`, and `768px` for the same breakpoint. Bootstrap convention is `767.98px`.
- **Status**: TRACKING

### BSI-026: Print CSS Fragmented Across 4 Locations
- **Source**: T004 (CSS Audit)
- **Issue**: `print.css` + 3 `@media print` blocks in `custom.css` + inline in `results_executive.html`.
- **Status**: TRACKING

### BSI-027: Missing Covert Mode Overrides for .u-code-block and .icae-card
- **Source**: T004 (CSS Audit)
- **Issue**: `.code-block` has covert overrides but `.u-code-block` doesn't. ICAE card with gold gradient has no covert override — visually pops against dimmed background.
- **Status**: TRACKING

### BSI-028: Font Size Unit Inconsistency (rem/px/pt Mixed)
- **Source**: T004 (CSS Audit)
- **Issue**: Non-print CSS should standardize on `rem`. Currently mixes `rem`, `px`, and `pt`.
- **Status**: TRACKING

### BSI-029: Duplicate Code Block Implementations
- **Source**: T004 (CSS Audit)
- **Issue**: `.code-block` (line 999) and `.u-code-block` (line 5299) — two implementations, one has copy button and covert overrides, the other doesn't.
- **Status**: TRACKING

### BSI-030: Missing Canonical URLs on 66+ Pages
- **Source**: T001 (SquirrelScan)
- **Issue**: `/topology`, `/compare`, and 66+ dynamic pages missing `<link rel="canonical">`.
- **Status**: TRACKING

### BSI-031: Charset Not First Element in Head
- **Source**: T001 (SquirrelScan)
- **Issue**: `<meta charset="UTF-8">` should be the first child of `<head>` on all pages. Currently it's not.
- **Status**: TRACKING

### BSI-032: Broken External Links (DTIC, IANA, DNI)
- **Source**: T001 (SquirrelScan)
- **Issue**: 4 external links returning 403/404 on homepage and approach page (DTIC military docs, IANA RDAP, DNI ICD 203 PDF).
- **Status**: TRACKING

### BSI-033: Duplicate Page Titles (15 Duplicates Across 43 Pages)
- **Source**: T001 (SquirrelScan)
- **Issue**: History pagination pages share identical titles. Analysis/view and analyze pages share titles.
- **Status**: TRACKING

---

## WATCH LIST — Minor Polish

### BSI-034: Domain Input Missing `required` Attribute
- **Source**: T003
- **Location**: `go-server/templates/index.html:405-413`
- **Status**: TRACKING

### BSI-035: Input Hint Not Linked via `aria-describedby`
- **Source**: T003
- **Location**: `go-server/templates/index.html:423-426`
- **Status**: TRACKING

### BSI-036: Recon Mode Button Hidden Text on Mobile (Icon Only)
- **Source**: T002
- **Location**: `go-server/templates/results.html:278`
- **Status**: TRACKING

### BSI-037: ROE Nmap Script Tags Look Clickable But Aren't
- **Source**: T003
- **Location**: `go-server/templates/roe.html:178-183`
- **Status**: TRACKING

### BSI-038: TLP Dropdown Items Use href="#" Without role
- **Source**: T002
- **Location**: `go-server/templates/results.html:268-272`
- **Status**: TRACKING

### BSI-039: No Active Nav State on Analysis Pages
- **Source**: T003
- **Location**: `go-server/templates/_nav.html:25-73`
- **Status**: TRACKING

### BSI-040: Mobile Header Actions (7 Buttons) Compression at 375px
- **Source**: T002
- **Location**: `go-server/templates/results.html:250-290`
- **Status**: TRACKING

### BSI-041: Accordion Focus Styles Insufficient on Dark Background
- **Source**: T003
- **Location**: `go-server/templates/index.html:740-1000`
- **Status**: TRACKING

### BSI-042: Skip Link Uses :focus Instead of :focus-visible
- **Source**: T004
- **Location**: `src/css/custom.css:127-140`
- **Status**: TRACKING

### BSI-043: No @supports Fallback for backdrop-filter
- **Source**: T004
- **Issue**: Browsers without `backdrop-filter` support get semi-transparent backgrounds with no blur — readability risk.
- **Status**: TRACKING

### BSI-044: TTL Tuner Promo Card Overflow at 375px
- **Source**: T003
- **Location**: `go-server/templates/index.html:558-582`
- **Status**: TRACKING

### BSI-045: Sign-Out Button Touch Target Too Small on Mobile
- **Source**: T003
- **Location**: `go-server/templates/_nav.html:94`
- **Status**: TRACKING

---

## Audit Scores Summary

| Source | Score | Grade |
|--------|-------|-------|
| SquirrelScan Overall | 72 | C |
| SquirrelScan Performance | 83 | B |
| SquirrelScan Accessibility | 95 | A |
| SquirrelScan Security | 91 | A |
| SquirrelScan Core SEO | 97 | A |
| SquirrelScan Video | 57 | F |
| CSS Color Architecture | — | A |
| CSS Glassmorphism | — | A- |
| CSS Print Stylesheet | — | A |
| CSS Covert Mode | — | A- |
| CSS Responsive Design | — | B+ |
| CSS Accessibility | — | B- |
| CSS Hover/Transitions | — | B |

**Total Issues Found**: 45
- RENDITION (fix before publish): 8
- INTERROGATION (current sprint): 11
- SURVEILLANCE (design debt): 14
- WATCH LIST (minor polish): 12

---

*This document is a living registry. Every issue gets a BSI number. Issues move from OPEN → IN PROGRESS → RENDITIONED (resolved). Resolved issues stay in the document with their resolution date and commit hash — we don't forget what we killed.*
