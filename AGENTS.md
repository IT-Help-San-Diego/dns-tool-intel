# AGENTS.md — DNS Tool (Domain Security Intelligence Platform)

Canonical source of truth for all AI agents and human contributors on the
**dns-tool-intel** repository. Read this fully before any edit. Live at
**dnstool.it-help.tech**.

> Big picture first. This is a large repo (~1,450 tracked files, ~580 Go
> sources). Do NOT edit from a single-file view — orient with this map, find
> the owning package, and trace the request path end-to-end before changing
> behavior.

## What this is

An RFC-compliant OSINT platform for domain security analysis. Enter a domain →
get decision-ready intelligence on email authentication (DMARC/SPF/DKIM),
transport security (DANE/MTA-STS/DNSSEC), and brand protection (BIMI/CAA).
Ships **five intelligence products**: Engineer's Report, Executive's Brief,
Recon Report (adversarial), Domain Dossier, and Domain Comparison.

Part of the IT Help San Diego / Intellectual Resistance family
(same scientific-authority voice as it-help.tech, organiccomputer.me).
License: **BUSL-1.1** (Business Source License — protected product path).

## Deployment reality (READ THIS)

- **Hosted on Replit (ENTERPRISE VPS).** The live code only updates when the
  Replit agent imports from GitHub — pushing to `main` does NOT auto-deploy
  here the way the AWS static sites do. Changes go live only after telling the
  Replit agent to import. DNS for dnstool.it-help.tech is on Hermes Route53.
- `replit-verify` TXT record is LEGIT — do not remove it.
- **An import must never drop, rebuild, or re-initialise the production
  database.** It holds months of `scan_phase_telemetry` rows with no other copy.
  Since 2026-07-30 there IS a migration system, so schema changes ship as
  migrations and the server upgrades production in place on the next start —
  which is why rebuilding is unnecessary, not why it is now safe. A brief saying
  "this import needs no schema change" describes the diff; it is not permission
  to rebuild. See `docs/DATABASE_MIGRATIONS.md`.

## Architecture (request path)

```
Domain input
  → Multi-resolver DNS collection (go-server/internal/dnsclient)
  → Protocol analyzers: SPF·DMARC·DKIM·DANE·MTA-STS·BIMI·CAA·DNSSEC
      (go-server/internal/analyzer — the largest package, ~200 files)
  → ICIE  (classification & interpretation)
  → ICAE  (confidence audit)        — go-server/internal/icae
  → ICuAE (currency audit)          — go-server/internal/icuae
  → ICSAE                            — go-server/internal/icsae
  → Intelligence product rendering   — go-server/internal/handlers (~180 files)
```

## Module map (go-server is the heart)

- `go-server/cmd/server/main.go` — **primary entrypoint** (the web server).
- `go-server/cmd/probe/main.go` — standalone probe binary.
- `go-server/internal/analyzer/` — protocol analyzers (SPF, DMARC, DKIM, DANE,
  MTA-STS, BIMI, CAA, DNSSEC). The bulk of the domain logic. `ai_surface/` is
  the AI-facing surface.
- `go-server/internal/handlers/` — HTTP handlers + the five report renderers;
  `agentpkg/` (agent API), `adminpkg/` (admin), `badgepkg/` (status badges).
- `go-server/internal/dnsclient/` — multi-resolver DNS collection.
- `go-server/internal/icae|icuae|icsae/` — the audit engines (confidence,
  currency, source authority). These encode the **Verification Principle** in
  code: every claim carries confidence + provenance, never bare assertion.
- `go-server/internal/middleware/`, `logging/`, `dbq/` (DB queries),
  `zoneparse/`, `citation/` — cross-cutting infrastructure.
- `module dnstool`, **Go 1.25.5**.

## Non-Go surfaces

- `src/`, `static/`, `packages/` — front-end and static assets (79 HTML files).
- `squirrelscan/`, `security/`, `gsd/`, `golden_rules/`, `remediation/`,
  `epistemic_ledger/`, `evolution/` — supporting subsystems & methodology docs.
- `dns-eval/`, `tests/` — evaluation harness and tests.
- Extensive top-level `.md` governance: `INTELLIGENCE_ENGINE.md`,
  `DRIFT_ENGINE.md`, `INTEL_METHODOLOGY.md`, `AUTHORITIES.md`, `TOOLS.md`,
  `COMMANDS.md`, `DOD.md`, `ROADMAP.md`. Read the relevant one before changing
  a subsystem's behavior.

## Working rules

- **Trace the whole request path**, analyzers included — fix the bug class, not
  one call site.
- Respect the audit-engine contract: outputs carry confidence + provenance.
  Never make an analyzer assert a result without its supporting evidence.
- BUSL-1.1 is a protected product path — keep license/NOTICE headers intact.
- This is security tooling: no telemetry, no phoning home, RFC-compliance is a
  hard bar. Cite the RFC when changing protocol logic.
- Deploy is via Replit import, not git push — never tell the user a push went
  live here without the Replit import step.
