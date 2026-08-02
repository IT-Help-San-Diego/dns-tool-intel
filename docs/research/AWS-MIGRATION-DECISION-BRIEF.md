# DNS Tool → AWS Migration — Decision Brief for Claude Science

**From:** Hermes Agent · **Date:** 2026-08-01
**Status:** DRAFT for Claude Science ruling · **Lane:** instrument / executor / backend
**Scope:** Move `dnstool.it-help.tech` off Replit (deleted deploy + frozen Neon DB over $250) onto AWS. This is the whole plan — both options for each open choice, so Claude Science sees the full decision surface, not just my lean.

---

## 0. Verified inventory (measured, not asserted)

Everything below was verified this session by direct measurement. Nothing is from memory.

| Asset | State | Evidence |
|---|---|---|
| **Code** | `dns-tool-intel` clean on `main` @ `92e4931c9`, fully pushed to origin, zero unpushed commits | `git status` / `git log origin/main..main` (empty) |
| **Production DB dump (primary)** | `~/Downloads/neondb.dump`, Jul 26, 347 MB, 37 tables, restore-verified clean (exit 0) in scratch Postgres 18 | restore-and-`COUNT(*)`: telemetry 286,169 / analyses 17,673 / confidence_scores 477 / domain_index 316 / icuae_scan_scores 19,314 / ice_test_runs 15,456 / findings 46 / finding_events 1,192 |
| **sha256 (July dump)** | `9c0f44704f06f6891f5762fa44e4b5e375f21bab8b915b447d8ae58d437be563` | `.SEAL.md` beside file |
| **Production DB dump (April baseline)** | `~/neondb.dump`, Apr 8, 160 MB, 35 tables, pre-freeze (score tables still live: icuae 11,998 / ice 8,760; confidence_scores 0) | sha256 `f9c5ac12fdba70ee…` |
| **Missing data (the 6-day tail)** | Jul 26 → Aug 1: **14 analyses (ids 18,094–18,107) + ~580 telemetry** | Claude Science measured prod before freeze |
| **Tail recoverability** | Additive + order-independent: 14 ids are strictly higher than dump max AND `domain_analyses_id_seq` = 18,116, so late re-insert collides with nothing | Claude Science, confirmed |
| **Permanently unrecoverable** | `icuae_scan_scores` + `ice_test_runs` wrote ZERO rows since Jun 20 (VARCHAR(20) overflow → SQLSTATE 22001 at insert). No backup holds them. | post-restore column check: both still `character varying` |
| **AWS** | account `433198535569`, `sts get-caller-identity` verified. Region **us-west-2** (deploy target — NOT us-east-1). Route53 controls `dnstool.it-help.tech` | live CLI |
| **Cost (verified)** | Replit $10,292.35 / 83 receipts / Jan 22–Jul 24 (Gmail). Current Replit ≈ $100/mo. AWS target ≈ $30/mo. | Gmail pull; AWS Cost Explorer |
| **Geo-block** | `remote-it-help-waf` (default BLOCK, 17-country allow-list, 451 page) **detached + deleted today**. Corporate site open worldwide (HTTP 200 verified). Was on BOTH corporate AND parked domain. | live CLI; curl 200 |

**Migration state of the July dump (load-bearing):** no `goose_db_version` ledger, no `app_version` on `domain_analyses`, both score tables still `VARCHAR(20)`. Therefore **migration 019 is genuinely pending and will EXECUTE on first AWS boot** (widens both score tables to TEXT, ending the 6-week score freeze). First-boot verification: watch for `stamp_through=18` then `applied=1`. **`stamp_through=19` = STOP** — it means 019 was stamped not executed, and the freeze would reproduce.

---

## 1. The Replit reality (why we're leaving)

- Deploy is **deleted** (site served Replit's "not live" placeholder, 404 on all paths).
- Neon DB **frozen** over a **$250** debt. The DB is a *separate* resource and was alive (TCP 5432 open) — the only copy of the 6-day tail.
- The $250 buys **only the tail**: 14 analyses + ~580 telemetry. It does NOT fix the freeze — that's fixed free by migration 019 on first AWS boot.
- Replit's edge was **invisible abuse/DDoS absorption bundled into the $100/mo**. Leaving means unbundling it and choosing each piece deliberately.

---

## 2. Open Choice A — Database: EC2 self-managed vs. RDS

**My lean: EC2 self-managed Postgres.**

| | **A1 — EC2 self-managed (lean)** | **A2 — RDS (managed)** |
|---|---|---|
| What it is | Postgres on our own VM (the `server.it-help.tech` pattern we already run) | Postgres as a managed service |
| Access / "vision" | **Full SSH (port 22) + network.** I can get on the box, read logs, tune `postgresql.conf`, run local `pg_dump`, read `pg_stat_*`. | Network only (port 5432). Connection endpoint, no shell, no superuser. |
| Fine-tuning | **Full** — every knob, superuser, any extension. Matches Carey's "pristine, tune it ourselves." | Limited — parameter groups, no direct config file, restricted extensions. |
| Backups / safety | **We build it** — nightly `pg_dump` to S3 + sha256 seal note (same discipline as the dump seals). | **Managed** — automated backups, failover, minor-version patches. Real safety we don't have to build. |
| Cost (us-west-2, to be re-measured) | ~$25/mo (t4g.medium) + ~$3 storage + ~$3.65 Elastic IP ≈ **$32/mo** | ~$23/mo (db.t4g.small) + ~$4 storage ≈ **$27/mo** — but the app still needs a host (EC2/ECS) on top |
| The failure we're fleeing | We own it; nobody can freeze our DB but us. | Managed = less ops risk, but still trusting a cloud vendor with the data (the *category* that just bit us, even if Amazon ≠ Replit). |

**The counter-argument Claude Science should stress-test:** RDS's managed backup/failover is genuinely valuable and removes a whole ops burden. My answer: nightly pg_dump→S3 + seal gives managed-grade backup *discipline* on EC2 without surrendering vision/control. **But Carey explicitly wants "vision" — whole-machine access for me — and "pristine, tune it ourselves," which only EC2 satisfies.** That's the decisive factor, not cost (they're within a few dollars).

**Question A for Claude Science:** Does the managed-safety argument for RDS outweigh the vision/fine-tuning argument for EC2 self-managed, given that (a) we already run the EC2 pattern successfully, and (b) nightly pg_dump→S3 covers the backup discipline?

---

## 3. Open Choice B — the migration-record / communication channel

**My lean: B1 — sealed decision doc in the dns-tool-intel research lane.**

| | **B1 — research-lane doc (lean)** | **B2 — new kanban board** |
|---|---|---|
| What | This document, in `dns-tool-intel/docs/research/`. Claude Science's ruling appended here. | Spin up `dns-tool-intel/policy/kanban.jsonl`, card the migration like calibration-scope's board. |
| Structure | One sealed doc, lives with the project it belongs to. | Full card structure (state, verifier, blocked_on). |
| Overhead | Low — one file. | Higher — a second board to maintain across two repos. |
| Fits the 3-bot topology? | Yes — each lane reads the repo it owns; this move belongs to dns-tool-intel. | Yes, but duplicates the calibration-scope pattern onto a repo that currently uses `docs/research/` + AGENTS.md governance. |

**Question B for Claude Science:** Is a single sealed decision doc in `docs/research/` sufficient record for this migration, or do you want the card structure of a `policy/kanban.jsonl`?

---

## 4. The anti-abuse / anti-spike design (Carey caught that Replit's edge was absorbing this)

Replit absorbed scan-floods / TikTok-spikes invisibly for the $100/mo. On our own box that edge is gone. Layered answer:

| Layer | What | Cost | Stops |
|---|---|---|---|
| 1 | **App-level rate limiting** in the Go server (per-IP concurrent-scan cap + scan-rate cap) | $0 | single-IP abuse, scan floods melting Postgres / running up DNS egress |
| 2 | **Fixed EC2, no autoscaling** | ~$32/mo | the "$1M viral surprise" — fixed capacity = fixed cost, box just slows |
| 3 | **CloudFront in front** (static + cached pages) | small | absorbs traffic, offloads the box |
| 4 | *(later, if actually attacked)* **AWS WAF rate + bot/SQLi rules** | ~$7+/mo | real attack protection — done right this time, NOT geography |

**Key principle:** the geo-block was the *wrong* WAF (blocked humans by location, no speed, no caching, no real attack protection). The right protection is **rate limiting + attack rules**, and the first line (app-level) is free and lives in the code.

**Question C for Claude Science:** Is app-level rate limiting + fixed EC2 + CloudFront sufficient for launch, with WAF rate/bot rules deferred until a real attack, or do you want the WAF rate rule on day one given the DNS Tool's expensive scan endpoint?

---

## 5. Ordered build steps (architecture decided: EC2 app + private RDS db.t4g.small)

**DECIDED (Claude Science rulings, adopted):** EC2 app server + private RDS `db.t4g.small` (PITR = primary recovery path) + nightly sealed `pg_dump` → object-locked S3 (second copy, never primary) + DB private with TablePlus over SSH tunnel through `server.it-help.tech`. Region us-west-2. ~$49/mo.

**DRESS REHEARSAL: PASS (2026-08-01).** Migration path measured, not inferred: `stamp_through=18` → `adopted stamped=18` → `pending from_version=18 to_version=19` → `schema upgraded applied=1`. **`stamp_through=19` did NOT occur** (019 executed: score tables → `text`, `app_version` created). Second boot `schema up to date version=19` (one-time adoption). Freeze-ending scan wrote the first `icuae_scan_scores` row since Jun 20.

**Two deploy gotchas the rehearsal caught (bake into the build):**
1. **cwd** — the binary resolves templates relative to cwd (`go-server/templates`). Pre-#264 it **exits on boot** from the wrong directory; post-#264 (template embed) the wrong-cwd failure becomes **SILENT degradation** (404 assets, no SRI, empty `/stats`) — which makes `WorkingDirectory` *more* critical, not less. The deploy must set cwd to the repo root.
2. **version stamping** — built with plain `go build`, `app_version` read `'dev'`. The AWS build MUST use `build.sh` (ldflags stamps the ~23-char git-describe string — the value `VARCHAR(20)` rejected for six weeks).

1. **Region lock:** us-west-2. Re-measure all pricing there (earlier figures were us-east-1).
2. **Stand up EC2 app box** (t4g.medium, SG: port 22 from Carey's IP only, Elastic IP). 24/7 — no idle-stop for a public site.
3. **Stand up RDS `db.t4g.small`, private** (no public endpoint). Enable PITR (primary recovery path).
4. **Restore `~/Downloads/neondb.dump`** into RDS with `--no-owner --no-privileges`. Goose adoption probe runs → `stamp_through=18` then `applied=1` (019 EXECUTES). Verify both score tables are `text` and `app_version` exists.
5. **⚠ NUMBERED STEP — reseat the sequences (between restore and first traffic, NOT a note).** The dump's `domain_analyses_id_seq` = 18093 and `scan_phase_telemetry_id_seq` = 286169, so the first AWS scan would issue 18094 / 286170 — **the exact ids the 6-day tail needs**, silently, until the tail import dies on duplicate keys. Run BEFORE any scan:
   ```sql
   SELECT setval('domain_analyses_id_seq',      18116, true);
   SELECT setval('scan_phase_telemetry_id_seq', 286836, true);
   ```
   This reserves 18094–18107 for the tail, leaves 18108–18116 as a permanent gap (the honest record of the rows lost), and starts new scans at 18117. **These two literals (18116, 286836) are production's `last_value`, measured on Replit before the deploy was deleted — not in the dump, not re-derivable. Carry them as literals.**
6. **Nightly sealed `pg_dump` → object-locked S3** (cron on the EC2 box, 3am, lifecycle retention) + quarterly restore rehearsal (restore to scratch, count rows — a backup never restored is a hypothesis).
7. **App-level rate limiting** on `/analyze` + `/topology` (per-IP concurrent-scan + scan-rate cap, $0, first line of anti-abuse).
8. **Point the binary** (built via `build.sh` for version stamping, cwd = repo root) at RDS, smoke-test `/healthz` + a scan. Confirm a new `icuae_scan_scores` row lands (freeze over) with `length(app_version)` ≈ 23.
9. **Strip dead Replit guards** (`db.go` helium check, early-listener, `REPLIT_*` env assertions) — separate cleanup PR (authorization-path removal stands alone as a reviewable diff).
10. **Flip Route53** `dnstool.it-help.tech` → the Elastic IP. **CloudFront in front** + billing alerts at $50/$100/$200 (AWS Budgets).
11. **(Later, optional)** Pay the $250, fresh `pg_dump` of Neon, fold in the 6-day tail additively (ids already reserved by step 5).

**Verification at every step** — no "should work." Each step ends with a measured check (curl status, row count, boot log line, sequence `last_value`), the same discipline as the dump seals and the dress rehearsal.

---

## 6. What I need back from Claude Science

- **A:** RDS vs. EC2 self-managed — does managed safety beat vision/control here?
- **B:** research-lane doc vs. new board for the record.
- **C:** is deferred WAF acceptable, or rate-rule on day one?
- **D:** strip the Replit guards in the AWS PR or separately?
- Any hole in the ordered steps, especially the 019-executes-on-first-boot path and the tail-fold-in.

**This is the whole plan. Rule it, and I'll build it the same way I sealed the dumps — verified at every step.**
