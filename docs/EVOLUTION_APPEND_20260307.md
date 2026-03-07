# Evolution Log — 2026-03-07

## Session 29: EDE Page UX + Integrity Hash Containment + Methodology PDF Scoping

### Changes
- **SHA-3-512 hash overflow fix**: Replaced inline styles with dedicated CSS classes (`.ede-integrity-box`, `.ede-integrity-hash`, `.ede-integrity-label`, `.ede-integrity-verify`, `.ede-integrity-note`). Hash now wraps properly via `word-break: break-all` + `overflow-wrap: break-word` + `max-width: 100%`. Parent container enforces `overflow: hidden` + `box-sizing: border-box`.
- **Collapsible disclosure log**: 9 event cards now show only 3 most recent by default. Semantic `<button>` toggle with `aria-expanded`/`aria-controls` reveals all entries. JS runs from nonced `<script>` block (CSP-clean — no inline event handlers).
- **Accessibility improvements**: Toggle is a real `<button>` (not `<div>`), has `focus-visible` outline, manages `aria-expanded` state on click.
- **Notion synced**: 5 new EDE entries created (EDE-004 through EDE-008). Session journal entry 29 and decision log entry added.

### Architect Review Findings
- Caught dead `onclick="toggleAllEdeEvents()"` inline handler — CSP violation under `script-src 'nonce-...'`. Removed.
- Toggle changed from `<div>` to `<button>` with ARIA attributes.
- Methodology PDF decision: EDE integrity verification is methodologically relevant (not just governance). Architect recommends:
  - Section 7 (Reproducibility): Add "Epistemic Correction and Integrity Verification" subsection
  - Section 4 (Confidence Scoring): Add paragraph noting confidence-model corrections disclosed via EDE
  - Full policy prose stays in supplementary docs (EDE page), not in the paper

### Lessons
- **Inline styles on monospace hash text are unreliable for overflow containment** — CSS classes with explicit `word-break` + `overflow-wrap` on a `<div>` (not `<code>`) are more reliable across browsers.
- **CSP nonce does NOT authorize inline event attributes** — only `<script nonce="...">` blocks. `onclick="..."` is blocked.
- **Scientific methodology papers should reference epistemic controls** when the system includes model-correction disclosure mechanisms.
