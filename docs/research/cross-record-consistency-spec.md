# Cross-record consistency findings — rule specification

**Measured:** 2026-07-31 · **n = 339** (75 mailbox-provider domains,
264 tenant domains drawn from DNS Tool's own scan history) · **0 lookup failures**

> **Class-assignment correction, 2026-07-31.** The first pass measured 345 rows and counted six
> domains twice — `hotmail.com`, `mailbox.org`, `proton.me`, `tuta.io`, `yahoo.com`, `zoho.com`
> are mailbox providers *and* appear in the scan history because users scanned them. A domain
> belongs to one class; a provider domain is a provider domain regardless of who scanned it.
> Removing the duplicates from the tenant class moves the tenant rates slightly and strengthens
> the transport contrast. Every conclusion is unchanged. Superseded figures are noted inline.
>
> **How the correction itself was applied badly, twice.** The first sweep replaced the literal
> string `345`→`339` and assumed the derived counts followed; two rule totals did not, and a
> predicate re-check against the recomputed data caught them. The second sweep then targeted a
> per-class split by its literal text — which did not occur in that form, so the substitution was a
> silent no-op — and the verifier only tested totals of the form `N of 339`, so the stale split
> `46/187` passed while the total three sections away read `232`. Both are the same defect the six
> rules exist to catch: **a check that cannot fail, reported as a check that passed.** Splits are
> now verified by extracting every `A provider … B tenant` pair from this document and asserting
> set equality against the computed splits — deriving from the producer, asserting equality, not
> a subset of remembered strings.

## What this document is

A specification for findings that arise from **two records read together**, where each record
passes its own conformance check. No rule here asserts that an operator made a mistake. Each
rule states an *entailment* between two published records and reports when the pair does not
satisfy it. Intent is not measurable from DNS and is therefore never claimed.

The distinction this rests on:

| question | answerable from DNS? |
|---|---|
| What does this record say? | Yes — determinate |
| Do these two records satisfy a documented entailment? | Yes — determinate |
| *Why* did the operator choose this? | **No** — never asserted |

## Two findings that corrected earlier claims

**1. Provider domains are not systematically softer than tenant domains.** An earlier
illustration from ten hand-picked domains suggested that mailbox providers run permissive
policies while custom domains enforce. At n=339 that is not supported:

| | publishes DMARC | enforces (reject or quarantine) |
|---|---|---|
| Mailbox provider | **96.0%** | 58.7% |
| Tenant domain | **65.9%** | 47.7% |
| | χ² = 25.1, p = 5.5e-07 | χ² = 2.4, p = 0.12 (n.s.) |

The real difference is **publication, not strictness**. 34% of tenant
domains publish no DMARC record at all. The earlier sample showed every custom domain at
`p=reject` because recognizable companies were selected; the observed scan population does not
look like that. A selected sample is not an observed one.

**2. Unsigned DNS is not an absence of transport security.** DNSSEC adoption is statistically
similar across classes (46 provider and 186 tenant domains lack both DNSSEC and
MTA-STS), but MTA-STS adoption differs sharply — 36.0% of provider domains versus 9.1% of
tenant domains, with TLS-RPT at 37.3% versus 12.5%.

MTA-STS achieves enforced SMTP TLS via the **web PKI** rather than via DNSSEC. A domain with
MTA-STS and TLS-RPT has chosen the PKI-anchored path over the DNS-anchored one. Reporting such
a domain as lacking transport protection is factually wrong.

**Consequence for grading:** DNSSEC absence must be **conditional**, not a flat gap.

- DNSSEC absent **and** MTA-STS absent → real transport gap
- DNSSEC absent **with** MTA-STS present → architectural choice, not a deficiency

DANE absence is **entailed** by DNSSEC absence (DANE requires DNSSEC) and must never be counted
as an independent second finding.

## The rules

Each rule names two facts already collected by the scan, plus the entailment that connects them.
Hit counts are from this survey.

### R1 — Inverted enforcement ramp (`sp` stricter than `p`)

**Facts:** DMARC `p` tag; DMARC `sp` tag.
**Entailment:** RFC 7489 §6.3 defines `sp` as the policy for subdomains; the conventional
deployment ramp tightens the organizational domain first, because the apex is the most
impersonated identity.
**Fires when:** `sp` is strictly stronger than `p`.
**Observed:** 13 of 339 domains
(8 provider, 5 tenant).

**Full observed set** (reproduced from the written CSV, not from the producing code):
`apple.com`, `dpsg-radolfzell.de`, `github.com`, `gmail.com`, `isc.org`, `live.com`, `msn.com`,
`outlook.com`, `posteo.de`, `rediffmail.com`, `seznam.cz`, `spitalulorasenescbaicoi.ro`,
`terra.com.br`. An earlier hand-off named six of these from a truncated print and omitted the two
most notable — `isc.org` (the organization that maintains BIND) and `github.com`. The count was
measured; the example list was recalled. Counts in this document are computed; names are quoted
from the dataset.

This is the highest-value rule in the set. It is a coherent consumer-mail pattern — the apex
carries a large legitimate long tail (forwarding, mailing lists, third-party senders) that
subdomains do not — and no conformance scanner reports it, because both records are valid.

### R2 — Transport enforced, sender identity not

**Facts:** MTA-STS policy record presence; DMARC `p`.
**Entailment:** publishing MTA-STS asserts that message transport for this domain is worth
protecting against downgrade (RFC 8461 §2). `p=none` requests no disposition for a message
that fails authentication (RFC 7489 §6.3).
**Fires when:** MTA-STS present and `p` is `none` or DMARC absent.
**Observed:** 11 of 339
(10 provider, 1 tenant).

The pipe is guaranteed; the sender is not.

### R3 — Strict alignment with soft disposition

**Facts:** `aspf` and `adkim`; DMARC `p`.
**Entailment:** strict alignment (RFC 7489 §3.1) *narrows* what counts as a pass, increasing
the failure rate. A soft disposition then declines to act on those additional failures.
**Fires when:** `aspf=s` and `adkim=s` and `p` is not `reject`.
**Observed:** 10 of 339 (3 provider, 7 tenant).

**This rule must not be reported as a weakness.** Strict alignment with quarantine and forensic
reporting is a *stricter matching rule with a retention-friendly disposition* — a quarantined
message is evidence still held, where a rejected one is gone. It is plausibly an intelligence
posture rather than a gap, and the finding should present the tension without ranking it.

### R4 — Partial enforcement (`pct` < 100)

**Facts:** `pct`; `p`.
**Entailment:** RFC 7489 §6.3 defines `pct` as the percentage of messages to which the policy
is applied; below 100 a proportion of failing mail receives no disposition.
**Observed:** 3 of 339.
Usually mid-rollout, which is legitimate — the finding is informational.

### R5 — BIMI without enforcement

**Facts:** BIMI record presence; DMARC `p`/`sp`.
**Entailment:** BIMI requires the domain to be at DMARC enforcement; a BIMI record on a
non-enforcing domain asserts a precondition the DMARC policy does not provide.
**Observed:** 1 of 339.

Rare, which makes it high-signal when it fires.

### R6 — No transport anchor (population statistic, **not** a per-domain finding)

**Fires when:** DNSSEC absent and MTA-STS absent.
**Observed:** 232 of 339
(68%).

At this prevalence it is a **baseline, not a signal**. A finding that fires on more than two thirds of all
domains conveys almost no information per domain. It belongs on the education surface as a
population statistic, not as a ring on individual nodes.

## Reproducing the survey

The survey is regenerable, and its class assignment is **asserted rather than remembered**:

```
docs/research/survey_dmarc_posture.py    # generator, with hard data-integrity assertions
docs/research/survey_providers.txt       # 75 mailbox-provider domains (curated)
docs/research/survey_tenants.txt         # 264 tenant domains (from scan history)
docs/research/dmarc_provider_tenant_survey.csv
docs/research/dmarc_survey_summary.json

python3 docs/research/survey_dmarc_posture.py \
    --providers docs/research/survey_providers.txt \
    --tenants  docs/research/survey_tenants.txt \
    --out-dir  docs/research
```

Three assertions abort the run rather than warn, because a class-assignment error produces
plausible-looking rates that nothing downstream can detect:

1. **Provider and tenant classes must be disjoint** — checked *before any network work*, so the
   failure is instant and cheap. This is the defect that moved four figures above.
2. **Every domain appears exactly once** across the survey.
3. **Lookup failures are reported and excluded from rates**, never coerced to a negative.

Verified 2026-07-31: an overlapping input pair aborts in 0 s with exit 1, no requests issued and
no output file written; a disjoint pair completes and writes the CSV.

One measurement note encoded in the generator: presence of MTA-STS, TLS-RPT, BIMI and SPF is
judged by a **literal version-token match** (`v=STSv1`, `v=TLSRPTv1`, `v=BIMI1`, `v=spf1`), not by
"is there a TXT record at this name." `apple.com` answers a wildcard `v=spf1 redirect=...` at
`_mta-sts.apple.com`; a presence check would call it MTA-STS-protected and **excuse a genuine
transport gap**.

## Relation to existing code — three different things called the same word

| symbol | what its "consistency"/"entailment" means | overlap with R1–R6 |
|---|---|---|
| `delegation_consistency.go` | intra-DNSSEC/delegation coherence: DS↔DNSKEY alignment, glue completeness, parent/child TTL, SOA serial | **none** — single-protocol zone infrastructure |
| `verdict_entailment_test.go` | **verdict ↔ evidence**: a verdict may assert a predicate only if an observation entails it | none directly; pins the same honesty *class* on single-protocol verdicts |
| this document | **record ↔ record** via a documented RFC entailment | the six rules |

These are three distinct concerns sharing two words. Cross-record consistency is a **new** concern,
not an extension of `delegation_consistency.go`.

**Where pair evaluation belongs.** The existing verdict builders (`buildEmailVerdict`,
`buildDNSVerdict`) are single-protocol: one verdict per protocol from that protocol's own records.
The six rules need two records at once. Pair evaluation therefore belongs in a **separate analyzer
package** consuming the already-collected per-protocol results map — mirroring how
`delegation_consistency.go` is its own concern — rather than inside `buildEmailVerdict`, which is
the function `verdict_entailment_test.go` pins most densely and where the two senses of
"entailment" would collide.

## Evaluability — the third state

Every rule takes two operands. If either lookup did not complete authoritatively, the rule is
**not evaluable** and must render as neither satisfied nor violated. This is the existing
`indeterminate` vocabulary: a transient resolver failure or a multi-resolver conflict is never
evidence of absence (RFC 7208 §4.6, RFC 7489 §6.6.3), and the honest response is *re-run this*,
not a finding.

Distinguish this from a rule that **cannot** be evaluated by re-running — for example an
organizational domain that the compiled public-suffix snapshot cannot derive. Re-running hits
the same table. The honest message differs: *"run it again"* versus *"this cannot be determined
until the reference data is updated."* Collapsing them wastes the reader's time and implies the
tool might return a different answer.

One selector-specific case belongs here: **DKIM selectors are not enumerable from DNS.** A probe
of a guessed selector name that returns nothing establishes only that the guess was wrong. It
must report *not determinable*, never *no DKIM*.

## Rendering contract

The existing renderer already allocates every visual channel, with reasons recorded in source:

| channel | current meaning |
|---|---|
| Node body colour | protocol **family** (email / transport / policy / brand) — an absent protocol is drained, not recoloured, so it still reads as a family member |
| Ring (`drawVerdictRings`) | **the verdict** — described in source as its sole carrier |
| Ring dash | `indeterminate` / `info` |
| Glow | hover / dim |
| Body flash | verdict landing |
| `drawRunningRing` | in flight |

Therefore a consistency finding **does not get a new channel**. It is a verdict about a node —
one derived from a record pair rather than a single record — and belongs as an additional keyed
status in `VERDICT_RING_COLORS` / `VERDICT_RING_OUTER`, inheriting the shape branch, dimming and
hover behaviour already implemented.

`drawVerdictRings` already branches on node shape: `isBoxNode(n) ? ringBoxPath(n, 9) :
ctx.arc(n.x, n.y, effRadius(n) + 9, …)`. Protocol nodes are circular (`drawProtocolNode`), so
`arc()` is correct for them; the box path applies to the rectangular source-zone nodes.

**Which node carries the ring.** A tension holds between two nodes, but a ring is per-node. Mark
the node whose record makes the **claim**, and name the counterpart in the popover — BIMI asserts
DMARC enforcement, so BIMI carries the ring and the popover names DMARC. Ringing both nodes
would report one finding twice.

## Wording constraint

Each finding states that two records are in tension and names the entailment. It does not state
that the operator was wrong.

Observed configurations in this survey have plausible operational justifications that DNS cannot
confirm: a consumer mail apex at `p=none` almost certainly reflects forwarding and mailing-list
breakage at scale; an inverted ramp almost certainly reflects a legitimate long tail on the apex
that subdomains lack. **These are good reasons, and they are not measurable.** A configuration is
evidence of a choice, not proof of a reason. Reasoning about intent belongs in a separately
labelled interpretation, or nowhere.
