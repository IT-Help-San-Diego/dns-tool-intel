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
   empty space and disconnects it from the content it introduces.

## Stage grammar

| num | name            | zone          | question                           |
|-----|-----------------|---------------|------------------------------------|
| 00  | VANTAGE         | *(the globe)* | head-only                          |
| 01  | SOURCES         | `source`      | WHERE DO THE FACTS COME FROM?      |
| 02  | AGGREGATE       | `hub`         | RESOLVERS AGREE?                   |
| 03  | ANALYZE + AUDIT | `engine`      | WHO CHECKS THE CHECKER?            |
| 04  | VERDICTS        | `protocol`    | NINE CHECKS — RINGS TELL THE STATE |
| —   | MEMORY          | `storage`     | WHAT DO WE REMEMBER & PROVE?       |
| 05  | YOUR REPORT     | *(console strip)* | —                             |

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
  band repartition fixed).
- **`reserveStrip`** reserves the caption strip in *every* zone whose x-range the
  caption spans — zones share x at narrow widths, and a neighbour zone's clamp
  squeezing a node back into a caption it never reserved is the `ct×rl02` failure.
- **The question (`q`)** renders only where the zone can hold it — a caption
  wider than its column is the FIX-1 collision re-authored, and the verifier
  would refuse it.
- **`05 YOUR REPORT`** anchors to the console strip's left edge, not the canvas
  top, so its arrow points at the report card rather than the ceiling.

## Geometry constants

- `titleSafe` = `max(H×0.07, 42, consoleTopReserve)` — top reservation.
- `consoleReserve` = `386` when `W ≥ 1000`, else `0` — the right report-console
  strip.
- Caption font: `600 10.5×SCL px ui-monospace`, `capH = 14×SCL`.

## Source of truth

The station table, zone membership, and caption construction live in
`topology.js` (the `readingLine` / `stations` block and the `SOURCES` / `HUB` /
`ENGINE` / `CONFIDENCE` node arrays). This document is the spec; the code is the
implementation. When the two disagree, the spec is corrected *and* the code is
re-measured — never one silently.
