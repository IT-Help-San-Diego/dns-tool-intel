# Black Site retired; Failure Registry adopted

**Date**: 2026-07-31
**Migration**: `017_failure_registry_retire_black_site.sql`
**Route**: `/black-site` → 301 → `/failure-registry`

## What this records

The page that publishes this project's own defects was called **Black Site**, and its
framing was built on the vocabulary of a secret prison: findings were "detainees" held in
"cells", processed by "rendition" and — in the page's own words — "enhanced interrogation
tactics". That phrase is the literal euphemism used to describe torture by the CIA, and
"rendition" is extraordinary rendition. The database carried the same freight:
`black_site_detainees`, `black_site_renditions`, `interrogation_notes`, and status values
`DETAINED`, `UNDER_INTERROGATION`, `RENDERED`, `EXTRADITED`.

This entry exists because **the retirement is itself part of the record**. The earlier
documents that used the old vocabulary (`docs/evolution/2026-03-18-*`,
`docs/plans/2026-03-08-*`) are dated records of what was true when they were written and
are deliberately left untouched — rewriting them would falsify the history rather than
correct it. This log entry is how the change is recorded: additively.

## What changed

**Name.** *Failure Registry.* It matches the house vocabulary (Golden Logic Registry,
citation registry) and states the actual thesis: an institution that publishes its own
failures is making a checkable claim about its own reliability. "Black Site" made a claim
about attitude.

**Status vocabulary** (migration 017, with the mapping preserved in that file's header):

| was | now |
|---|---|
| `DETAINED` | `OPEN` |
| `UNDER_INTERROGATION` | `UNDER_ANALYSIS` |
| `RENDERED` | `RESOLVED` |
| `EXTRADITED` | `REFERRED` |

`VERIFIED`, `CONTAINED`, `REGRESSED` and `DISMISSED` were already ordinary engineering
terms and are unchanged. No `legacy_status` column was added: `legacy_bsi_id` preserves an
*identifier* with external references, but a status is a state value with no external
reference, so a legacy column would be a permanent consistency obligation with no consumer.
The migration file is the provenance record.

**Dead tables dropped.** `black_site_detainees` and `black_site_renditions` were removed
rather than renamed. The project's standing rule is that migrations rename and never drop,
because a drop loses the ledger — that rule protects *data*, and measurement showed none in
the blast radius: 0 rows, 0 callers across all 12 generated query functions, no INSERT path
anywhere in the repository, and the live page reads `findings` (seeded by migration 013 with
the 46 records). A rename would have preserved dead code under a better name and left the
next reader unsure which table was authoritative.

Because "no write path exists" is an inference while a row count is a measurement, the
migration takes the measurement itself at run time and aborts with the counts in the error
if either table is non-empty on the database it executes against. The check cannot be
forgotten the way a human pre-flight step can.

**Route.** `/black-site` returns 301 to `/failure-registry` rather than 404: the path was
listed in the sitemap (`static.go`, monthly changefreq) and therefore actively advertised to
crawlers. `/failures` was *not* used — that path is already registered to an unrelated
handler, and re-registering it would panic gin at startup rather than fail in review.

## What was deliberately kept

The 46 findings and their fingerprints, the five-tier severity scale with S0 for
regressions, the T001–T005 team designations, the `findings` table name (referenced by the
migration, the queries, and `ListFindings` — renaming it would be a separate change with no
benefit), the `legacy_bsi_id` / `legacy_threat_level` columns, and the practice of
publishing defects against ourselves. The adversarial, red-team stance is the point of the
page and survives intact. Only the torture vocabulary was retired.
