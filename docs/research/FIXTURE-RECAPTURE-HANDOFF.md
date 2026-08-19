# Fixture Recapture Handoff — Claude Code lane

**Task:** recapture 7 golden fixtures through the production analyzer so the
`enterprise_dns_recognized` key is genuinely measured, not hand-renamed.

## Why this exists

Commit `d539644ae` hand-renamed `explains_no_dnssec` → `enterprise_dns_recognized`
inside 7 fixture JSONs. Those fixtures are stamped `_tool_version: 26.51.0-116` —
an instrument that never emitted that key. A hand-edited fixture is a proxy
measurement, and these fixtures are the acceptance instrument for the whole
Rust spike, so the provenance must be healed to genuinely-captured bytes.

## The 7 files (all under `tests/golden_fixtures/`)

- cia_gov.json
- cloudflare_com.json
- example_com.json
- google_com.json
- ietf_org.json
- red_com.json
- whitehouse_gov.json

## Gate already lifted

Production serves `v26.51.0-125-g6576ed150` (= main head), which emits
`enterprise_dns_recognized` natively. A straight recapture heals provenance with
zero code change — no producer fix needed.

## Recapture path

Use the #459 Browser-pane flow: the form-click passes botverify
(`scan_source=human`), then pull the fixture bytes from the analyzer output for
each domain. Re-stamp `_tool_version` to the recapture build.

## Verification (measured expectations from today's live bytes)

- `google_com` and `red_com` → `enterprise_dns_recognized: true` (recognized
  enterprise DNS provider).
- The other 5 (`cia_gov`, `cloudflare_com`, `example_com`, `ietf_org`,
  `whitehouse_gov`) → `false`.
- **Verdicts must not flip** — the DNSSEC/SPF/DMARC/DANE state of each fixture
  must stay identical to what's currently in the file; only the renamed key's
  provenance changes.

## Do NOT touch

The NXDOMAIN control fixture (not in the 7 above) stays untouched by design.

## Gotchas measured during the last execution

- Serial scan queue runs ~70s per domain; don't fire all 7 at once.
- Rapid fires are silently swallowed — wait for each to complete.
- Avoid the `sort | head` stale-ID trap when reading analysis IDs back.

## Done when

All 7 fixture files carry `enterprise_dns_recognized` captured from a real scan,
`_tool_version` re-stamped to the recapture build, verdicts byte-identical to
pre-recapture except the healed key, and CI (`TestGoldenFixtureStateCoverage`)
is green.
