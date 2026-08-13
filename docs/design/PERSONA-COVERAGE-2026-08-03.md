# Persona coverage check — the "watch my back for normal DNS guys" report

Requested by Carey 2026-08-03 (walkthrough standing directive). Two independent
passes: five practitioner personas reasoned against the report's content
inventory (practice-grounded: bounce-triage runbooks, BOD 18-01 logic, RFC 9116,
MSP/SOC convention — **not** attributed to the HCI corpus), and a corpus pass
over `sections/07_cross_cutting_themes.md`. Sourcing correction from the corpus
pass: `dns_tool_engineering_report_view.md` is a page-scrape of the report
itself, not analysis — the analysis lives in `sections/*`. Where a future DNS-
practitioner field study contradicts these personas, the personas yield.

## The corpus's sharpest reframe

**The reader axis is task phase, not job title:** rapid assessment / incident
response (scan, jump-to-exception, stable positions) vs extended monitoring vs
post-hoc verification. The v2 gradient L0→L3 already mirrors this — ratify it
explicitly as the persona model.

## Personas → what they hunt first → v2 verdict

1. **Mail admin, deliverability failure today** — SPF validity + 10-lookup limit,
   DKIM for their ESP, DMARC + rua, **MX resolution**, *what changed*. Well served
   by Email Security open-by-default; hurt by MX living under "Infrastructure"
   (wrong mental model — they think *email*), raw records only at the tail diff,
   and the DKIM false-drift defect firing during their worst hour.
2. **Incident analyst, suspected spoofing** — DMARC **policy value** and SPF
   **terminal qualifier** (the deciding tokens — "configured" hides the answer),
   subdomain reality, zone-change timeline, contact chain (registrar/ASN/
   security.txt), evidence provenance. Provenance (§7) is a genuine strength;
   change-over-time and security.txt are buried; no spoofability rollup at L0.
3. **Domain owner after a phishing report** — plain-language protected-or-not,
   the Brand & Trust Big Picture Question (currently invisible until the 4th
   collapsed group is expanded), what-do-I-fix-first, **was it even my domain
   (lookalike) — NOT SURFACED, product-level gap**, who to call.
4. **MSP tech onboarding a client domain** — access inventory (well served by the
   L0 grid), baseline record export (tail-only again), **DS-record L0 hazard flag**
   (forgetting DS during NS transfer takes the zone dark — cheap badge, prevents
   the one silent-outage class this persona causes), SaaS TXT records, subdomains.
5. **Auditor / compliance reviewer** — protocol checklist incl. not-measured,
   provenance, per-claim reproduction commands, normative citations, artifact
   integrity, **tool-asserted (not user-picked) TLP**. Found two artifact defects:
   the "Ungrouped — pending contract v1.1" label is scaffolding leaking into a
   deliverable (never ship it), and **CAA renders in Brand Security while ratified
   §2 homes it in Domain Security** — contract-vs-template drift the §8.1 anchor-
   parity check must be built to catch.

## Cross-persona actions (deduplicated, ranked)

**Fixed tonight in the preview:**
- Nav/anchor jumps into closed `<details>` silently no-op'd — ancestor-opening
  JS now runs on every in-page fragment jump (nav pills, jump-to chips,
  findings links).

**v2 / renderer items:**
- L0 posture card carries the decisive tokens: DMARC policy value, SPF terminal
  qualifier — composes with the exception-first ruling.
- Third job-pill: **"What changed"** (History/Diff) — the third cross-persona hunt.
- Per-card raw-record reveal at L2 — resolves walkthrough open question #9 as
  "sooner"; three personas currently scroll to the tail for the only raw view.
- Email Security gains a see-also edge to MX (the mail admin's mental model);
  DS/DNSSEC hazard badge on the L0 grid; never ship the "Ungrouped" label —
  split a named "Evidence & Verification" tail group.

**Contract v1.1 items (Science + Carey):**
- §5 census holes: ICD 203 confidence panel, Intelligence Currency, resolver-
  discrepancy detail, Evidence Diff, Δ change detection, TTL guidance, SOA
  timers, provider RFC-compliance dossier, scanner-config, integrity/archive
  verification — all present in today's report, none has a named slot. Close
  before the parity ratchet goes live.
- **Comparison-content exemption:** the Evidence Diff and resolver-agreement
  views must render as co-located comparisons, never see-also jumps (corpus [7]
  spatial-proximity); PDF cross-refs need page/section locators.
- Exception-first navigation ratchet: every L0 chip not `configured` deep-links
  its canonical anchor — CI-checkable via §1.
- Name as §5 content classes: the question+answer verdict headers (the
  non-expert's only navigation vocabulary) and the epistemic-explainer prose
  bound to `not-measured`/`error` (visual distinctness without the explanation
  still reads as a defect to a non-expert).
- Resolve 7-statuses-vs-≤4-colors: state the color mapping (severity colors +
  one neutral for epistemic states; shape/label carry the rest).
- Stable-position requirement: expansion must never displace navigation chrome.
- CAA home: move the card or amend §2 — and make §8.1 catch this drift class.
- Sibling-view escalation path (Executive → Engineer) lands on canonical
  anchors, not the top of the document.

**Product-level (Carey's call, out of v2 scope):**
- Lookalike/cousin-domain signal (the most common true answer to "someone
  phished as us" is: it wasn't your domain).
- Onboarding/checklist export framing for the MSP persona.
