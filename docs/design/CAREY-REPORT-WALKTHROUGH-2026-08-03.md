# Carey's top-down walkthrough of the Engineer's Report — 2026-08-03

Primary-user research, narrated live while scanning a real report (GoDaddy-registered
domain, screenshots taken during). Carey noted a previous walkthrough's notes were
lost — this document is the durable record. Feeds: the v2 structure, the design
lane, and the defect chips. Verbatim flavor kept where it carries judgment.

## NORTH STAR (Carey, verbatim, same session)

> "I think that everyone would say wow, it's an impressive, detailed amount of
> information and no one else is doing that — but it's not navigable, it's not
> organized."

The moat is the depth. The defect is the navigation. Every design decision is
judged against both halves at once.

## THE BALANCE DOCTRINE (Carey, same session — binding on every lane)

Balance is not half-attention to each side; it is FULL attention to all of it at
once: the research of what users want AND the creative vision AND visual
perfection as scientific rigor ("the most high kinds of science are visually
perfect… because communication must happen if it will succeed"). Getting
corrected in one dimension is never license to swing to an extreme in another.

Operational consequences, each one checkable:
- **Multi-age readability bar:** a 10-, 15-, 22-, 35-, 55-, and 80-year-old must
  all be able to read it for it to survive. The gradient is the mechanism: L0/L1
  (Big Picture Questions, plain verdicts, glosses) is the everyone-layer and can
  carry a measured readability target; L2/L3 is the practitioner ramp. This
  makes "readable by all ages" a ratchet, not a vibe.
- Secure AND clean AND lightweight — simultaneously, not traded off.
- Privacy as architecture: no spying, no cookie sprawl (and no consent-popup
  circus, because there is nothing to consent to).
- Valid AND validated AND code quality that MEANS something: no badge earned by
  gaming the gate — "write a unit test that goddamn means something." (House
  exemplar: the goose-token detector pins the verbatim line that broke CI, so
  the test cannot rot into decoration.)
- Timeline: "all of it, and as long as it takes."

## KEEP — confirmed working, do not regress

| Element | Verdict |
|---|---|
| Title + domain | "fuck yeah" |
| Timestamps, duration seconds, SHA hashes | keep |
| Verify + Archived | "usually works, I like it" |
| **Cross-Referenced page** | "excellent… that page is cool — **make sure we keep that up to date**" (freshness obligation) |
| Replay button | OK — goes to the actual scan |
| Recon mode, Snapshot ("instantly downloads a very valuable little" file), Re-analyze, Scan new domain | all keep |
| Record-edit confirmation flow (edited SPF → confirmation banner) | keep — "we're helping them get to their changes" |
| Email Security content + **Big Picture Questions** | "really important" — first big destination, good detailed info |
| Analysis Confidence expandable | good |
| DKIM absent-selector handling | fine that it may not show — operators obfuscate selectors legitimately |

## DEFECTS — live in v1, independent of the redesign

1. **Topology button ignores context.** It does not take you to *that report's* topology.
   "Valuable real estate — why is topology there if it doesn't even…" Either the button
   deep-links to `/topology?domain=<this>` (prefill + auto-run, the #235 pattern) or it goes.
2. **Posture drift false-positives on DKIM keys.** Drift banner sometimes reports a DKIM
   key as changed when "it is the same fucking key." Suspected class: TXT representation
   artifacts (multi-string chunking / quoting / whitespace) comparing unequal strings for
   equal records. Needs investigation with a captured pair. Drift itself is good —
   "if it's real then they should know."
3. **RDAP block data quality + density.** "A lot of times that's messed up" — and it
   takes a whole screen for a tiny amount of information.

## STRUCTURE RULINGS — bind the v2 / design work

4. **The L0 posture stack is redundant.** From risk level down to Open Remediation
   Workspace is "a complete page… still scrolling… and all of that information is
   basically the same fucking shit." Command card + scorecard + findings summary +
   priority actions repeat the same facts (matches the recon map's §2-duplication note
   on the scorecard). The dashboard must be ONE compact block.
5. **"Low Risk" never shows what ISN'T low-risk.** Exception-first: the not-configured /
   provider-limited items must be visually loud inside the posture card, not prose.
6. **Density: full-screen-wide strips for tiny info** (registrar/RDAP, footprint).
   Compact grid treatment (the wireframe already does this).
7. **The hurry-path is MX → subdomains → DNSSEC.** "If I was really in a hurry the thing
   I'd be looking for is MX… then subdomains… then DNSSEC." MX renders ~line 5428
   (Traffic & Routing); subdomains at 5533; both were deep below the fold. Direct nav
   anchors required — done in v2 nav (MX & Routing, Subdomains pills).
8. **Intelligence Currency belongs after the report.** "I've always thought this should
   be after the report anyway." (v2 already moved it to the tail — validated.)
9. **Raw records surface too late.** The Evidence Diff "is really the only place they
   can see the raw record… I'm kind of wondering if that should be sooner — I just
   don't know." Design question: per-protocol raw-record reveal at L2 (the contract's
   gradient already puts records at L2), with the diff staying as the comparison view.

## OPEN QUESTION — routed for decision

10. **TLP selector: "I think that should go… when would a public thing that's already
    public ever be red?"** The case FOR keeping some marking: the *records* are public,
    but the *assessment* (verdicts, what's exploitable, remediation order) is the
    sensitive layer — the current footer says exactly this (TLP:AMBER "may reveal
    actionable vulnerabilities"). The case for Carey's instinct: a user-pickable
    SELECTOR is odd — the sensitivity of an assessment of public data doesn't change
    because a reader picked a different chip. Candidate resolution: fixed marking
    (AMBER, set by the tool, stated why) instead of a selector; possibly CLEAR for
    fixture/public-corpus domains. **Science rules on the epistemics; Carey decides.**

## Statistical caveat Carey raised on himself

"I wonder if statistically people who look at this are like me or are very
different" — this walkthrough is n=1 from the expert primary user. The corpus (43
cited works) supplies the general-population evidence; where they agree (keyhole,
landmarks, exception-first) confidence is high; where only one speaks, mark the
decision as provisional.

**Standing directive (Carey, same session): watch his back for the NORMAL DNS
practitioner.** He self-identifies as atypical ("pretty weird nerd… very different
than how even a lot of IT guys work") — the design must also serve what a typical
practitioner hunts for, using the research corpus where it speaks. Sourcing honesty:
the corpus is mission-critical HCI (how to present), not DNS-practitioner field
studies (what they seek) — persona coverage below is reasoned against the report's
content inventory and marked as such, not attributed to the 43 works.
