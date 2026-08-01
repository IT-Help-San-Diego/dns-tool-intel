# The Flippers: local ↔ global across three surfaces

**Status:** decided product design, zero implementation. Recovered 2026-07-31 from
the 2026-07-30/31 session ("Topology title DOM correction"), the project memory
written by that session as it ran out of context, and the calibration-scope
lineage the pattern descends from. Sections are marked DECIDED (Carey already
ruled), RECOVERED (reconstructed from the transcript), or OPEN (needs sussing).

## The idea in one paragraph

DNS Tool runs as two instruments: the public cloud site and the local build,
which since 2026-07-26 runs banner-free with a `local` badge. Local scans stay
on the machine, always. A **publish flipper in the nav** (default OFF) lets a
local user opt into feeding their scans to the global database — contributing
to the science — with a label that names exactly what leaves the machine.
**History** grows a local ↔ global flipper tab: your machine's scan history
versus the cloud's. **Stats** splits the same way: statistics computed from
your local scanning versus the global dataset — with the self-selection caveat
printed on the page. Three surfaces, one mental model: *you always see which
instrument you're reading, and nothing leaves without a flipped switch.*

## The philosophy underneath (RECOVERED — this is the core of it)

The session established that local-vs-cloud is **not** a free-vs-premium or
crippled-vs-full split. The local build *is* the artifact. What differs isn't
capability — it's **what leaves the machine and what each can honestly claim**:

- **Local:** nothing leaves. No Internet Archive submission, no public URL, no
  cookie banner (already true), no shared rate limit. The claim it can make
  that the site can't: *"your domains were never disclosed to anyone, and you
  can verify the instrument that measured them."*
- **Site:** the public, citable, third-party-archived record. The claim it can
  make that local can't: *"this result has tamper-evident provenance outside
  our control."*

Those aren't more-vs-less. They're **different guarantees, and a scientist
wants both at different times**. The publish flipper is the bridge between
them: it converts a private measurement into a public, citable one — per the
user's explicit choice, never by default.

On stats, verbatim from the same discussion: local stats describe *your
scanning*. Global stats describe **what people chose to publish** — a
self-selected sample, and since the nav toggle defaults off, it's selected on
exactly the axis that matters. Anyone comparing "my DMARC failure rate"
against "the global rate" is comparing themselves to a population of people
who opted in. **The stats page should say that on the page, not in a
footnote** — the same discipline as everywhere else in the tool: the caveat
lives beside the number it qualifies.

## The three surfaces

### 1. Nav publish flipper (DECIDED)

- Lives in the nav, visible everywhere. **Default OFF.**
- **Honest label naming what leaves the machine** — Carey explicitly rejected
  euphemisms like "contribute to analytics." The label must say something
  shaped like: *"Publish scans to the global dataset — sends the domain name
  and full scan results to dnstool.it-help.tech."* Publishing a scan of a
  domain IS disclosing that you scanned that domain; the label owns that.
- **Publishing is additive.** Local history always collects regardless of the
  flipper. Flipping ON adds a copy to the global database; flipping OFF stops
  future copies. It never gates or deletes local data.

### 2. History flipper tab (DECIDED shape, OPEN mechanics)

- The history page gets a local ↔ global view flipper: personal on-machine
  history versus the cloud's public history.
- OPEN — two ways to source the global tab, with a shipped precedent for the
  first: **(a) direct-link** — the flipper navigates to the cloud site's
  /history (calibration-scope shipped exactly this "unified flipper with the
  direct-link approach" on all its surfaces; DNS Tool already adopted its
  mode-badge convention: cloud shows `v<version>`, local shows
  `local · v<version>`). Simple, no API, honest about which instrument you're
  reading. **(b) embedded** — local fetches a cloud API and renders both tabs
  in one page. Richer (could interleave/compare), but builds an API surface
  and muddies "which instrument am I reading."

### 3. Stats flipper (DECIDED shape + DECIDED caveat, OPEN mechanics)

- Local statistics computed from the local database; a flipper to the global
  view. Same direct-link vs embedded question as history.
- **The self-selection caveat is a decided requirement, on the page, not a
  footnote** (wording above). This is non-negotiable honesty: global stats are
  a statement about *the published sample*, never about "domains in general."

## What already exists (verified in the repo, 2026-07-31)

- `config.IsCloudDeployment` (`REPLIT_DEPLOYMENT` env) — the cloud→local
  lever, already gating the privacy/cookie banner off for local runs.
- The `local · v<version>` header badge — the mode is already declared.
- Local persistence: every scan lands in the local Postgres via the same
  schema the cloud uses (`domain_analyses` + drift + telemetry + ICuAE/ICAE
  score tables), migrated at startup by the embedded goose chain. The "local
  history always collects" half of the decision is already true.
- ~~Wayback archival fires on local scans~~ **FIXED — PR #254** (verified from
  source by the Courier, gated same day). The precise finding, because the two
  guarantees fared differently: every successful non-private local scan POSTed
  to web.archive.org naming `BaseURL/analysis/N` — *worse* than "a thing
  leaving the machine" (the request itself told a third party's logs "this IP
  runs DNS Tool and produced analysis N") and *narrower* than "your domains
  were disclosed" (only the numeric ID traveled; the domain never did). So
  the local build's stronger promise — *your domains were never disclosed to
  anyone* — was true throughout; the weaker *nothing leaves* was not, and now
  is: `shouldArchiveToWayback` carries `isCloudDeployment` as its first term,
  with an untagged deletion-guard test
  (`TestShouldArchiveToWayback_NeverOnLocalDeployment`).
- **Nothing else exists.** No toggle UI, no consent state, no contribution
  endpoint, no global tabs. Zero matches in templates/JS/commits.

## What has to be sussed out (OPEN — the real work)

1. **The payload.** What exactly crosses the wire on publish: the full
   `full_results` JSON? The posture/verdict summary? Scan telemetry? The
   domain name necessarily goes — that's the disclosure the label names.
   Decide field-by-field and write it down; the label's honesty depends on
   the payload being enumerable.
2. **The endpoint + trust model.** Cloud needs an ingest route. How does it
   authenticate/validate submissions? Anonymous-but-rate-limited? Signed by
   the local instance? What stops garbage or poisoned scans from polluting
   the science dataset? (Options: server-side re-scan verification — cloud
   re-measures the domain itself on receipt and stores its own measurement,
   treating the submission as a *request to look*, which sidesteps trusting
   client data entirely; or provenance-tagging rows `published_from_local`
   and keeping them a separate stratum in stats.) The Courier's review
   (2026-07-31) endorsed re-scan-on-receipt outright: it converts a
   submission from data-to-be-trusted into a request-to-look, eliminating
   client trust and version skew in one move.
3. **Version skew.** Local binaries lag the cloud. A 26.50 local publishing
   into a 26.53 cloud dataset mixes grader vocabularies (the cross-record
   consistency spec and deposit-version work live exactly here). Rows need
   the producing version, and stats need to decide how to handle mixed
   vocabularies — or the re-scan-on-receipt model makes it moot.
4. **Standing flipper vs per-scan choice.** Decided: a standing nav toggle.
   Open: does a per-scan "publish this one" button coexist? Does flipping ON
   offer to publish *past* local history (retroactive), or forward-only?
5. **The global tabs' phone-home tension.** Even read-only global views from
   a local instance disclose "someone at this IP runs DNS Tool." Fetch
   global data only on explicit flip, never on page load — or use
   direct-links, which make the disclosure obvious and voluntary.
6. **Consent state storage.** Where the flipper's state lives locally
   (server-side setting in the local DB, not a cookie — the local instance
   has no accounts), and how the scan pipeline reads it at persist time.
7. **Stats identity.** Which stats are "local" (computed from local DB — the
   existing stats handler pointed at local data mostly works) and which are
   inherently global-only (resolver PoP behavior, population distributions).
   The split forces naming what each number is *of*.

## SETTLED 2026-07-31/08-01 — the publish pipe's mechanics (Carey confirmed)

Sussed out with Carey directly; supersedes the corresponding open questions:

- **Re-scan on receipt is the pipe.** Flipper ON: the local scan runs and lands
  locally as always, AND a small API call asks the cloud to scan the same
  domain itself. The cloud's own scanner measures and writes with the write
  access it already has. No write credential ever leaves the server; the
  read-only role (claude_ro shape) serves only the cloud-viewing levers.
  Client data never becomes science data; version skew is gone (the global
  dataset is always the current production grader). The pipe mostly exists:
  `POST /analyze` is already "please scan X" from the world (verified:
  `AnalyzeRateLimit` attached, `anti_repeat` real at ratelimit.go:121) — v1
  adds a wrapper carrying `published_from_local` provenance. **The wrapper's
  semantics are GET-OR-PAIR, which dissolves the limiter collision the
  Courier caught:** *ensure a public measurement of X exists within freshness
  window W; trigger one only if absent; either way return the row to pair
  with.* An anti_repeat refusal means a contemporaneous public row already
  exists — that row IS the pair, so the limiter becomes the pipe's
  deduplicator instead of its enemy. **W = 1 hour, provisional, with its
  justification:** the 52,053-pair replication measurement behind the
  protocolVerdictSeverity refit found 99.62% posture reproduction, with decay
  appearing only at multi-day gaps — hour-scale W sits deep inside the stable
  regime. Provisional because hour-scale decay specifically hasn't been
  measured; when it is, the number follows the measurement, not the other way
  around. Genuine
  refusals (rate-limit proper) must SURFACE to the local user — "publish is
  ON" has to be a checkable claim, not a silent maybe. The provenance tag is
  the one genuinely new server-side piece.
- **Two scans, two records, two hashes — and the split is the feature.**
  Telemetry hashes always differ; POSTURE hashes should agree when the domain
  shows both vantages the same face. Agreement = free cross-instrument
  corroboration. Disagreement = the split-horizon/divergence signal (phase 2),
  already falling out of v1 as data.
- **Publishing is public visibility, and the label says so.** The cloud's
  paired scan lands in public history and Recently Analyzed like any visitor
  scan. "Contribute to the science" and "this domain will appear in the
  public scan history" are the same fact; the label ships the second
  sentence. The honest v1 label shape: *"sends the domain name to
  dnstool.it-help.tech and asks the public instrument to scan it; the domain
  and its results will appear in the public history."* The domain is the
  entire disclosure — smaller than the result-shipping design's.
- **The vantage asymmetry is real and the pair compensates.** Residential
  ISPs block outbound port 25, so a home local scan structurally cannot run
  the SMTP/STARTTLS/DANE-over-SMTP battery the VPS observers can. Tri-state
  discipline applies: locally those checks render *indeterminate — not
  measurable from this vantage*, never "failed"; the paired cloud scan fills
  the gap. This CORRECTS the earlier "what should differ isn't capability"
  line: true for product design, false for physics — the honest response is
  to declare the asymmetry and let the pair compensate.
- **Paired statistics are the local stats page's killer content** (each
  stated beside its published-sample caveat): agreement rate overall and
  per-protocol ("your vantage and the public instrument agreed on 34 of 36
  published scans"); vantage coverage ("port 25 unreachable on all 12
  transport checks; the cloud measured them for you"); divergence flags
  (posture-hash mismatches, each a split-horizon candidate); resolver-view
  differences (your ISP resolver vs the fleet consensus). One caveat carried
  from v1, and per the Courier it should be RENDERED as the feature it is:
  the global row is the CLOUD's measurement, so the local page shows *"your
  vantage / the public instrument's vantage"* side by side — the local build
  holds both numbers once it fetches the paired scan back, and the
  side-by-side turns the limitation into the demonstration. A local-only
  divergence is visible in the pair but never overwrites the public record.
- **ICuAE cutoff before ANY cloud statistic ships** (Courier, verified) — and
  the reason travels with the rule so nobody can relax it without refuting
  it: `overall_grade` is bound in the `INSERT`, so the `VARCHAR(5)` defect
  did not truncate grades — it **dropped whole rows** (SQLSTATE 22001) for
  every scan grading excellent / adequate / degraded, three of the five
  vocabulary words. The surviving pre-018 corpus is therefore bimodal *by
  construction* — filtered by string length, not by anything about the scans
  — and `ICuAEGetAggregateStats` computes `AVG`/`STDDEV_POP` over exactly
  those survivors. Every cloud-stats figure must scope to post-018 rows,
  cutoff derived from `goose_db_version`'s 018 timestamp, and say so on
  screen (the Replit lane's /confidence Grade Distribution scoping is the
  precedent and the pattern).
- **Carey's own instrument gets the dual-source shape**: local Postgres plus
  a read-only Neon role, same pages rendered from a flipped data source —
  right for the owner of both ends, impossible for the public build (would
  ship credentials), which uses the pipe + direct-links instead.

## PHASE 2 — divergence reports (designed 2026-08-01, ships after v1)

Carey asked whether the flipped-on user's local-vs-cloud comparison should
also go up. Answer: yes, but as a CLAIM, never as data — the same rule
recursively. The local build fetches its own paired cloud scan back (it's
public) and computes the diff locally; the comparison itself needs nothing
sent. What optionally goes up is a **divergence report**: domain, "my posture
hash differed," and the field *names* that differed — no values. Stored in
its own stratum (`vantage_divergences`, never `domain_analyses`), shown only
in aggregate, always labeled unverified ("3 vantage-divergence reports"). A
malicious client can inflate an unverified counter and nothing more. The
endgame applies re-scan-on-receipt recursively: enough reports on a domain
become a request to look harder — the cloud probes from multiple VPS
observers and verifies split-horizon behavior itself, or doesn't. A report
prompts measurement; it never is measurement. Label consequence if it ships:
one added clause — reporting a divergence discloses "my view of this domain
differed," still zero record values.

## House rules that bind this work (from project memory)

- Labels name mechanics, not virtue ("what leaves the machine," never
  "contribute to analytics").
- Absence is never presented as a result; a caveat lives beside the number it
  qualifies, in the artifact, so it can't drift away.
- Global stats describe the published sample — every surface that shows them
  says so on the surface.
- The right-hand scan console on /topology is untouchable; the nav flipper
  must not crowd it.
- Publishing is additive; local collection is unconditional and free.

## Suggested build order (from the 2026-07-31 assessment)

The session that decided this also ranked it: risk-reduction work (ink
registry, owl-gate correctness) before surface-adding work — "the toggles and
the stats split are good product work, but they add surface." When it's
green-lit: (1) write this brief's decisions into the repo (this file), (2) fix
the wayback leak on local, (3) history flipper via direct-link (smallest,
ships the mental model), (4) stats split with the caveat, (5) the publish pipe
last — it's the piece with a trust model attached.
