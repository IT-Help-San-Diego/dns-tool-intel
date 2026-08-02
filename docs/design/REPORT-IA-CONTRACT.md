# Engineer's Report — Information Architecture Contract v0

**Status: DRAFT for ratification.** One contract, two renderers: the screen report (results.html successor) and the minted PDF (`/analysis/:id/pdf`). Blessed sequencing (Carey, 2026-08-01): this contract lands before either renderer is built. Full rationale, research grounding, and measured baselines live in `docs/research/SCIENTIFIC-PDF-MINT-BRIEF-DRAFT.md` (rev 3); this file is the operative spec both renderers consume and CI checks against.

Ratification needed on: §2 canonical assignments (Science + Carey), §6 per-protocol governing sentences (Science), visual system (design lane — out of scope here).

---

## 1. Anchor registry

One stable identifier per group and per card — **the same string** in the HTML anchor, the PDF cross-reference label, and the producer's results-map key mapping. No renderer invents its own.

| Kind | Anchor id |
|---|---|
| Group | `email-security`, `domain-security`, `transport-security`, `brand-trust`, `infrastructure-intel` |
| Protocol card | `spf`, `dmarc`, `dkim`, `dnssec`, `dane`, `mta-sts`, `tls-rpt`, `bimi`, `caa` |
| Infra card | `registrar`, `email-provider`, `web-hosting`, `dns-hosting`, `asn`, `ct-log`, `subdomains`, `rdap` |

Binding rule: an automated check must be able to walk artifact → anchor → producer field. An anchor that appears in one renderer and not the other fails the build.

## 2. Groups and canonical assignment (PROPOSED — resolves the wireframe's double-slotting)

Each verdict renders **exactly once**, at its canonical card; every other appearance is a cross-reference to that anchor. (Science's citability rule 1: duplication is provenance ambiguity — one measurement shown twice is indistinguishable from two that agree.)

| Group | Canonical cards | Cross-references shown |
|---|---|---|
| Email Security | `spf`, `dmarc`, `dkim` | → `mta-sts`, `tls-rpt`, `bimi` |
| Domain Security | `dnssec`, `dane`, `caa` | — |
| Transport Security | `mta-sts`, `tls-rpt` (+ SMTP/STARTTLS transport findings) | → `dane` |
| Brand & Trust | `bimi` (+ VMC/CT brand findings) | → `caa`, `dmarc` |
| Infrastructure Intelligence | `registrar`, `email-provider`, `web-hosting`, `dns-hosting`, `asn`, `ct-log`, `subdomains`, `rdap` | — |

Cross-references are typed links ("MTA-STS: see §Transport / Appendix B.4"), never restated verdicts.

## 3. Status vocabulary

`configured` · `not-configured` · `warning` · `critical` · `provider-limited` · **`not-measured`** · `error`

- `not-measured` (check didn't run) and `error` (check ran and failed) are **visibly distinct from every negative verdict** — a card with no producer verdict must not look like a card with a bad one. This is the owl-mark rule at card level, and the sentinel rule at UI level.
- Verdicts against draft specifications (BIMI) carry a **`draft-spec` marker rendered distinctly** from RFC-numbered normative references.
- Severity color stays within the amber/green/red budget with redundant non-color encoding (shape/label), per the corpus's ≤4-code and no-color-alone rules.

## 4. Disclosure gradient

`L0 dashboard → L1 section summaries → L2 evidence → L3 appendix/raw`

- **L0 (first viewport / PDF page 1):** posture card, all nine protocol chips, verdict tiles, infrastructure grid, owl + TLP + provenance header.
- **L1:** per-group summary — group verdict, canonical cards with one-line findings, the group's **Big Picture Question and guidance asides**.
- **L2:** per-card evidence — records, parsed fields, RFC citations with governing sentence.
- **L3:** verification commands, full enumerations, raw records.

**Invariant (mechanically checked): descending never changes a claim, only adds support.** Every L0/L1 claim resolves to ≥1 L2/L3 record; no L3 record carries a verdict absent upstream. Screen renders the gradient as progressive disclosure (collapse/expand); print renders it as **document order** (summaries → labeled appendices with cross-references). Collapse in HTML becomes an expanded block or a cross-reference in PDF — **never absence**.

## 5. Content classes and slots (the parity ratchet)

Every class present in today's report maps to a named gradient level. A class with no slot fails the build.

| Content class | Slot |
|---|---|
| Posture/risk verdicts, verdict tiles | L0 |
| Protocol status chips | L0 |
| Infrastructure detections | L0 grid (canonical), L2 detail |
| Owl epistemic mark, TLP, provenance fields | L0 header (outside gradient semantics — see §7) |
| **Big Picture Questions + guidance asides** | L1, positioned with their group (homepage-promised differentiator — never dropped) |
| Per-protocol findings and one-line summaries | L1 |
| Records and parsed evidence | L2 |
| RFC deep-links with governing sentence | L2 (at the claim), quoted in print citation |
| CVE references | L2 |
| Verification commands | L3, copy-to-clipboard on screen, listed in print appendix |
| Subdomain / CT enumerations | L3 — **always with count; any bound stated with pointer to full set** (silent truncation = contract violation; 20k rows is a feature) |
| Telemetry / timing | L2-L3 |

## 6. Normative citation contract

- Every normative claim links its RFC **section** with a `:~:text=` fragment highlighting the **strongest governing sentence** — which must be **normative language (MUST/SHALL/REQUIRED clauses)**, not a title or definitional line (Science's rule; several current fragments target the protocol's name line, which resolves and proves nothing).
- Science owns per-protocol which sentence governs. The sentence choice is an editorial claim with an owner, not a template accident.
- **Two-level ratchet** (census 2026-08-01: results.html has 80 rfc-editor links — 72 fragmented, 4 bare, 4 wrong-form; repo-wide 197 across 39 RFCs; a real page renders ~17 of the 80 through 874 conditional blocks):
  1. CI validates **all authored links** against cached RFC text — any can render for some domain; sampling a page leaves ~63 unchecked.
  2. The per-artifact check runs **at mint time** against what actually rendered: a rendered claim without its citation fails; an unrendered link is correct behavior.
- Print translation: the citation renders the quoted governing sentence (appendix/footnote) and carries the fragment URL for digital readers.

## 7. Provenance header (outside the gradient)

Six fields, each with its **schema-verified sentinel** (empty-string-under-NOT-NULL is invisible to type-level checks — test the sentinel the schema actually uses):

1. `app_version` verbatim; `''` → renders "not recorded" (019_domain_analyses_app_version.sql:30-31; 001_base_schema.sql:120/:234)
2. Analysis id + permalink
3. Measurement time, distinct from mint time
4. Resolver and vantage
5. Per-claim producer identity
6. Evidence reachable per verdict (the gradient is the mechanism)

The owl mark is producer-derived epistemic status (real owl assets from `static/images/owl-*`), never a template default; a mint request that cannot resolve one fails loudly.

## 8. What CI checks (summary of the ratchets)

1. Anchor parity across both renderers and producer keys (§1)
2. Single canonical rendering per verdict (§2)
3. Gradient invariant: claims resolve downward, no orphan verdicts upward (§4)
4. Content-class parity census (§5)
5. Citation fragments resolve against cached RFC text; per-artifact citation completeness at mint time (§6)
6. Provenance fields present with sentinel-aware rendering; owl mark resolvable (§7)
7. Golden-PDF renders of the fixture corpus: page count, text extraction (no truncated columns), required-elements presence, perceptual diff against blessed renders
