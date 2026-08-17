# Reading-Line Contract

The topology page's station captions — `00 · VANTAGE` through `05 · YOUR REPORT`,
plus `MEMORY` — form a **reading line**: a horizontal sequence that carries the
reader through the DNS-intelligence pipeline in reading order. This document is
the durable specification of that geometry, extracted from `topology.js`'s inline
comments. The minifier strips those comments, so the source file must not be the
only copy of this reasoning.

## Invariants

1. **Captions are geometry, not ink.** Station captions are first-class rects in
   the separation solve. (FIX-1: the prototype's captions ran through the ring
   cluster because they were treated as ink, not geometry.) The pairwise overlap
   pass moves *nodes* away from captions, never the captions — a caption that
   drifts stops being a reading line.

2. **Build order.** Captions are built *after* the shelf repartition and solver
   remap produce the final zone bounds. Reserving strips from bounds a later stage
   rebuilds are reservations the page never had — the first build sat before the
   repartition, and every "mysterious" caption collision was that ordering bug.

3. **Captions anchor to their member nodes, not their zone's rectangle.** A
   caption must sit over the nodes it names (the centroid of its members), not the
   zone's top-left corner. Anchoring to the zone's left edge floats the label over
   empty space and disconnects it from the content it introduces. Membership comes
   from each node's own `zone` field — never a hand list (that is how 02 landed on
   the hub it actually names).
   **The centroid is never used raw**: it clamps to
   `[z.bounds.x1 + tw/2 + 6, z.bounds.x2 − tw/2 − 6]` so a skewed centroid cannot
   re-author the FIX-1 caption-past-column collision. A contract that said
   "anchor to the centroid" without this clamp would license exactly the
   collision the code prevents.

4. **Captions hug their clusters** (Carey's ruling, 2026-08-16 frames): y drops
   to just above the zone's topmost member (`topEdge − capH/2 − 8`), so the label
   owns its contents instead of a rank line with dead air under it. Interior
   (hugging) captions are **plain anchored rects** — the pairwise solve moves
   nodes off them; a `reserveStrip` at interior height would push whole zone tops
   around. A zone with no members falls back to the rank-line home *with* its
   strip.

5. **The foundation row is anchored substrate.** The storage row is deterministic
   and exempt from solver mapping, and it is `_anchored` in the pairwise solve:
   at 1180 the source column's bottom node pushed `postgres` into `fixtures` at
   the row's packed minimum (probe-measured) — anchored, intruders yield. Space
   comes from the graph, never the foundation.

## Stage grammar

| num | name            | zone          | question                           |
|-----|-----------------|---------------|------------------------------------|
| 00  | VANTAGE         | *(the globe)* | head-only                          |
| 01  | SOURCES         | `source`      | WHERE DO THE FACTS COME FROM?      |
| 02  | AGGREGATE       | `hub`         | RESOLVERS AGREE?                   |
| 03  | ANALYZE + AUDIT | `engine`      | WHO CHECKS THE CHECKER?            |
| 04  | VERDICTS        | `protocol`    | NINE CHECKS — RINGS TELL THE STATE |
| —   | MEMORY          | `storage`     | WHAT DO WE REMEMBER & PROVE?       |
| 05  | YOUR REPORT     | *(flagship report card)* | —                      |

## Zone membership

- **SOURCES** (5 members): `root` (Root/TLD), `rdap` (RDAP/WHOIS), `ct`
  (CT/Subdomains), `cisa` (CISA/Threat), `probes` (Probe Fleet).
- **HUB** = `DNS Resolvers` (station 02's zone). NOT a source.
- **ENGINE** = `ICIE` (station 03's zone).
- **CONFIDENCE** = `ietf` (IETF Metadata) — edges to engine/icae/icuae; NOT a source.

## Anchoring rules

- **`00 VANTAGE`** anchors to the globe itself. There is no vantage zone — the
  globe is the station, and it lives *outside* `globalBounds` (the graph area
  starts right of it). Flooring on `globalBounds.x1` shoves the caption into the
  hub column.
- **`MEMORY`** sits *above* the storage band, in the inter-band gap, claiming no
  interior space (stealing a strip from its interior re-creates the squeeze the
  band repartition fixed — measured: the storage row is **236px of content in a
  211px band**, `topology.js:1462`; that figure is why the exception exists, and
  this parenthetical is its only home outside comments the minifier strips).
- **`reserveStrip`** reserves the caption strip in *every* zone whose x-range the
  caption spans — zones share x at narrow widths, and a neighbour zone's clamp
  squeezing a node back into a caption it never reserved is the `ct×rl02` failure.
- **The question (`q`)** renders only where the zone can hold it — a caption
  wider than its column is the FIX-1 collision re-authored, and the verifier
  would refuse it.
- **`05 YOUR REPORT`** anchors to the **flagship report card's measured DOM
  rect** (`.topo-scan-cta--flagship`, center-y converted to canvas coords the
  way the popover measures the console edge), so the arrow points at the thing
  it names — probe-verified delta 0px. At card height it is a plain anchored
  rect (a strip there would push zone tops below mid-canvas); when the card is
  unmeasurable it falls back to the top line with its strip.
  **Two relayout kicks are load-bearing**: the console builds in two async
  stages after a restore (CTA block, then owls+chips push the card ~103px
  down, measured) — without re-anchoring after both, the caption freezes
  pointing at the owl row.

## Geometry constants

- `titleSafe` = `max(H×0.07, 42, consoleTopReserve)` — top reservation.
- `consoleReserve` = `386` when `W ≥ 1000`, else `0` — **a width PROXY, not a
  spatial claim** (changed 2026-08-16, PR #416). It still bounds the initial
  pipe layout, but the console's real extent is a **rect measured from the DOM
  once per layout**; the full-height strip is only the fail-conservative
  fallback when the console is unmeasurable. The proxy overclaims everything
  below the console's actual bottom (~y620 at common widths) — that overclaim
  starved the 1180 storage row and produced two phantom "intrusions"
  (probe-measured, baseline-matched). The post-layout verifier tests
  intrusions **rect-vs-rect** against the measured box, and the foundation row
  frees its right bound when the band clears the console's bottom — the space
  under the console is real.
- Caption font: `600 10.5×SCL px ui-monospace`, `capH = 14×SCL`.

## Hazards (measured, not hypothetical)

- **The drift test bounds each status map by the FIRST occurrence of its
  identifier** (`verdict_status_drift_test.go` parses `topology.js` for
  `VERDICT_STATUS_ALIAS` / the absence set): naming one map's identifier inside
  another object's comment breaks the parse — it found `};` before `{` and
  failed the suite (2026-08-16). Keep the literals boundable; do not name the
  maps outside their declarations.
- **The generic `'error'` alias maps to `failed`**, but the DANE verification
  lane's `'error'` means *could not measure* — when the DANE ring consumes
  `dane_verification`, it must canonicalize through a DANE-specific table,
  never the generic map, or a transport failure renders as an adverse verdict.

## Acceptance apparatus

The five-width post-layout verifier sweep (1024 / 1180 / 1440 / 1920 / 2560;
`__topoDbg.postLayout` via the playwright harness) is the acceptance
instrument for any geometry change: **0 overlaps, 0 console intrusions at
every width**, with failures attributed by re-running the identical sweep on
main's bundles before blaming the change. The flow-switch work extends the
sweep into the 577–1000 band.

## Source of truth

The station table, zone membership, and caption construction live in
`topology.js` (the `readingLine` / `stations` block and the `SOURCES` / `HUB` /
`ENGINE` / `CONFIDENCE` node arrays). This document is the spec; the code is the
implementation. When the two disagree, the spec is corrected *and* the code is
re-measured — never one silently.
