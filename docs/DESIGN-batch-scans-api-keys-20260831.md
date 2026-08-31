# DESIGN — Batch Scans + Scan API Keys (dns-tool-intel)

Carey's need, stated twice this session: run a big set of scans over and over
(the specimen battery: pq, pq2, pq-dualds, dane, mx.dane, dane-rx, pqns,
controls) without pasting them one at a time — and authorized bots should be
able to do the same. Today he hand-runs 8+ scans per battery; the decay log
needs them daily for three more days; the corpus work needs hundreds.

---

## What exists today (measured, not guessed)

- `POST /analyze` (form, single `domain` field) → synchronous full scan; rate-
  limited per-IP by `middleware.AnalyzeRateLimit` (reads `domain` from the
  form); CSRF-gated; `wantsJSON` path exists (`Accept: application/json` +
  POST → `analyzeAsync` with a progress token — ASYNC SINGLE already works).
- `GET /agent/api?q=<domain>` — read-only cached-analysis door for agents
  (never triggers scans; `_request_source: agent` stamping) — the model for
  "a door agents can use" that we already trust.
- `botverify` — autorun gating for JS-executing crawlers (PR #300 class).
  Batch scanning is NOT a crawler problem: it's authorized, authenticated,
  explicit POST traffic.
- Auth: `_dns_session` cookie (extractAuthInfo). No API-key mechanism exists.

---

## The design (smallest honest surface)

### 1. `POST /api/batch` — the batch endpoint (new, API-key-gated)

Request (JSON):
```json
{
  "domains": ["pq.resolutionscope.com", "pq2.resolutionscope.com", "..."],
  "label": "decay-day5-battery",        // optional provenance
  "selectors": {},                       // optional, same as single scan
  "exposure_checks": false,
  "devnull": false
}
```
- **API key required**: `Authorization: Bearer <key>` or `X-Scan-Key` header.
  Keys are operator-issued (Carey) — a new `scan_api_keys` table (key hash,
  label, created_at, last_used, revoked_at NULL) + one-time plaintext shown
  at creation, like the probe fleet's `X-Probe-Key` sha256-compare pattern.
  The batch endpoint is the ONLY thing keys unlock. No admin, no deletes.
- **Behavior**: enqueues each domain through the EXISTING scan path (same
  analyzer, same persist, same seals/receipts) with `batch_id` provenance on
  each row (`full_results._batch = {id, label, index, total}` — the same
  map-on-read pattern as the 'Secure'→'Hardened' rebucket; no backfill).
- **Response**: `202 Accepted` + `{"batch_id": "...", "queued": N,
  "per_domain": [{"domain": ..., "queued": true}]}`. Scans run server-side
  (the async worker already exists via `analyzeAsync`'s progress machinery);
  results land as normal `domain_analyses` rows — queryable immediately by
  the existing read paths (`/agent/api`, history, TablePlus).
- **Rate limiting**: separate bucket for keyed traffic — N scans/min per key
  (config constant, default conservative), NOT per-IP (the whole point).
  Refuses >500 domains per batch (DoS guard; larger = split into batches).
- **Duplicate policy**: same-domain re-scan within a batch = allowed (the
  battery intentionally re-scans), each row distinct — matches today.

### 2. The battery runner (client side, zero new server code)

`scripts/scan-battery.sh` (repo, bash + curl):
```bash
KEY=$(cat ~/.dnstool-scan-key)   # mode 600, never in repo
curl -s -X POST https://dnstool.it-help.tech/api/batch \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d @battery.json
```
- `battery.json` templates checked into the repo: `specimen-battery.json`
  (the 8 PQ/DANE specimens + nlnetlabs control), `estate-battery.json`
  (14 family zones), `decay-battery.json` (= specimen battery, the daily
  log's exact set).
- The **decay cron** becomes: battery runner + the existing read paths —
  the daily log stops needing a human clicking the UI 8 times.
- The botverify autorun gate is UNTOUCHED: crawler-shaped GETs still never
  scan; only key-bearing explicit POSTs do.

### 3. Honesty requirements (the non-negotiables)

- Every batch-sourced row carries `_request_source: "batch"` + batch
  provenance — corpus statistics can exclude/include them explicitly (the
  corpus-filter class of rule applies to the GO tool too).
- Key creation is interactive-only (Carey in the admin session) — keys are
  never auto-generated, never logged in plaintext after creation.
- Batch scans count against the same daily scan stats — no shadow traffic.
- Rate-limit 429s are honest and retryable (`Retry-After`), the
  automation-no-blocker rule.

### 4. What this deliberately does NOT do

- No public/unauthenticated batch anything (the crawler-storm lesson).
- No new scan logic — the batch endpoint is a QUEUE over the existing path;
  the instrument stays single-producer.
- No changes to GET semantics (RFC 9110 discipline already in the code).

### 5. Build order (each step shippable alone)

1. `scan_api_keys` table + key-check middleware (one migration, one helper).
2. `POST /api/batch` enqueue + provenance stamp + keyed rate bucket.
3. `scripts/scan-battery.sh` + battery JSON templates + README.
4. (Optional later) `/api/batch/:id` status endpoint — the rows themselves
   already answer status via existing read paths; add only if wanted.

Estimated: one focused build session; the async machinery it reuses exists.
