# Licensing Model (Open Core)

DNS Tool is licensed under **Business Source License 1.1 (BUSL-1.1)** with a rolling Change Date of **three years from the publication of each version**, after which it converts to **Apache-2.0**.

## What this means

### You can:
- Read, study, and learn from the source code
- Modify the code and create derivative works
- Use it for development, testing, research, and education
- Run it in production to audit domains you own or control
- Use it as a security consultant or MSP to audit domains on behalf of your clients
- Run it as an internal tool within your organization for security operations
- Contribute improvements back to the project

### You cannot:
- Offer it (or a derivative) as a hosted, managed, or API-based DNS audit service to third parties
- Embed it in a competing commercial product where DNS security audit functionality is material to the offering
- Sell a competing commercial service built on this code

### What is a "Competitive Offering"?
A product or service that is (a) offered to third parties on a Hosted, Managed, Embedded, or API-based basis AND (b) provides DNS security audit, DNS intelligence, or domain posture assessment functionality that is material to the value of the offering.

**Formal definitions:**

- **Hosted** — Making the functionality of the Licensed Work available to third parties as a service, where the service operator (not the end user) controls the infrastructure.
- **Managed** — Offering the Licensed Work to third parties as a managed service where the operator handles deployment, maintenance, upgrades, or operational responsibility on behalf of the end user.
- **Embedded** — Including the Licensed Work (in whole or in substantial part) in source code, executable code, or packaged form within another product, or packaging a product such that the Licensed Work must be accessed, downloaded, or invoked for it to operate.

### Security consultants and MSPs
Using DNS Tool to audit client domains as part of professional services (consulting, managed security, IT administration) is explicitly permitted. The restriction applies only to offering the tool itself as a standalone hosted or managed product to those clients.

### After the Change Date:
Each version automatically converts to **Apache-2.0** — fully permissive, no restrictions — three years after it is first publicly distributed. For versions published before 2026-02-14, the Change Date is 2029-02-14.

## The Science Is Free Now (CC BY 4.0)

The scientific methodology is not time-locked. The following documents are licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/), effective immediately — each carries its own license notice:

- [`docs/dns-tool-methodology.md`](docs/dns-tool-methodology.md) — the confidence-scored analysis methodology (data collection, RFC-grounded protocol evaluation, calibration model)
- [`docs/philosophical-foundations.md`](docs/philosophical-foundations.md) — the epistemic framework for security analysis communication
- [`docs/owl-semaphore-mathematical-foundations.md`](docs/owl-semaphore-mathematical-foundations.md) — mathematical exploration of the Owl Semaphore state system (superseded exploratory draft; the authoritative Owl Semaphore specifications are published from the [owl-semaphore](https://github.com/IT-Help-San-Diego/owl-semaphore) repository, DOI [10.5281/zenodo.19473697](https://doi.org/10.5281/zenodo.19473697))

You may copy, redistribute, translate, adapt, and build upon these documents for any purpose — including commercially — with attribution (© 2024–2026 IT Help San Diego Inc. / Carey James Balboa; cite the DOI shown in each document's header). No BUSL analysis is required to use the science.

**For researchers, in plain English:** running DNS Tool, studying it, modifying it, and citing it for research, education, testing, or personal use is expressly permitted under the BUSL Additional Use Grant — those uses are never a "Competitive Offering." The methodology documents above are additionally yours to reuse under CC BY 4.0 today.

The split is deliberate: **the knowledge is free today; the machine that automates it becomes free on a schedule.** The gap between those two clocks is what funds the research.

## What this repository contains

This repository contains the complete DNS Tool platform:

### Core platform (default build)
- Go/Gin web server, routing, middleware, templates
- DNS client (multi-resolver, DoH fallback, UDP fast-probe)
- SMTP transport probes
- Frontend (Bootstrap dark theme, PWA, dual intelligence products with TLP classification)
- Email Header Analyzer (SPF/DKIM/DMARC verification, spoofing detection, OpenPhish integration)
- IP Intelligence (reverse lookups, ASN attribution, geolocation)
- AI Surface Scanner (llms.txt, AI crawler governance, prompt injection detection)
- DKIM selector discovery and key strength analysis
- Enterprise DNS provider detection
- Edge/CDN vs. origin detection
- SaaS TXT footprint extraction and classification
- Posture drift detection (canonical SHA-3-512 hashing)
- Remediation engine with RFC-aligned Priority Actions
- Golden rules test suite
- Live integration test suite

### Provider Intelligence (providers.go)
- DMARC monitoring provider detection databases (vendor identification from rua/ruf domains)
- SPF flattening provider detection (include-pattern matching)
- Hosted DKIM provider identification and crediting
- Dynamic service detection (zone-based CNAME delegation scanning)
- CNAME-based provider classification database

### Infrastructure Classification (infrastructure.go)
- Self-hosted, managed, and government DNS tier databases
- Government domain recognition and classification
- Managed DNS provider tier detection
- Extended web, DNS, and email hosting detection patterns
- Email security management detection (provider-aware analysis)
- Alternative security posture item collection

### DKIM State Enrichment (dkim_state.go)
The DKIM state classification engine (Absent, Success, ProviderInferred, ThirdPartyOnly, Inconclusive, WeakKeysOnly, NoMailDomain) is fully implemented. Provider-aware state transitions credit known hosted DKIM providers.

### Intelligence Confidence (confidence.go)
- Extended confidence levels beyond the base Observed/Inferred/Third-party system

### IP Investigation (ip_investigation.go)
- Full PTR record analysis and forward-confirmed reverse DNS (FCrDNS) verification
- ASN-to-CDN correlation and CDN/edge network detection
- Domain relationship classification (direct assets, email providers, SPF-authorized senders, CT subdomain matches)
- IP neighborhood analysis with executive verdicts
- SPF record deep-inspection and include-chain IP matching
- PTR-based hosting provider detection

### AI Surface Scanner (ai_surface/*.go)
- SSRF-hardened HTTP text file fetcher
- llms.txt detection, parsing, and structured field extraction
- Known AI crawler database for robots.txt governance analysis
- AI recommendation poisoning detection patterns (prefilled prompts, CSS-hidden prompt injection)

### Feature Parity Manifest (manifest.go)
- Build-time populated feature registry for internal quality assurance and coverage tracking

## Contributing

By contributing code to this repository, you agree that your contributions may be used under the terms of the BUSL-1.1 (and the Apache-2.0 license after the Change Date). A Contributor License Agreement (CLA) may be required for substantial contributions.

## Commercial Licensing

For organizations that need capabilities beyond the BUSL-1.1-permitted uses, commercial licenses are available by arrangement. Contact us to discuss your specific requirements.

### What a commercial license can include
- All capabilities plus access to premium intelligence databases
- Self-hosted deployment (on-premises or private cloud)
- Additional deployment and integration options as needed

### Who should contact us
- Security vendors who want to embed DNS audit capabilities in their platform
- Managed service providers who want to offer DNS Tool as a branded service
- Enterprises requiring dedicated deployment with custom integrations
- Organizations needing capabilities beyond the BUSL-1.1-permitted uses

## Citation & DOI Policy

DNS Tool publishes scholarly metadata via Zenodo. Two kinds of DOI are involved, and they are not interchangeable:

- **Concept DOI** — `10.5281/zenodo.19468134`. Stable across all versions; resolves to the latest release in the Zenodo chain. Use this DOI for citations that should track the project over time (papers, READMEs, methodology documents, embedded attribution).
- **Version DOI** — Issued by Zenodo per release (e.g., `10.5281/zenodo.19217071` for a prior version). Pin a version DOI only when the citation must refer to a specific, immutable artifact (e.g., a reproducibility statement attached to a published result).

Rules:

1. `CITATION.cff` (`doi:` field) and `codemeta.json` (`identifier`) carry the **concept DOI**, not a version DOI. Dev bumps (config-only) must not modify these fields.
2. Per-release version DOIs are recorded by Zenodo automatically on archive deposit; `.zenodo.json` describes the deposit metadata but does not itself carry the resulting version DOI.
3. `scripts/release-gate.sh` updates `version:` fields in versioned artifacts (`CITATION.cff`, `codemeta.json`, methodology docs) at tag time; the concept DOI does not change.
4. Migrating to a new concept DOI (new Zenodo chain) requires an explicit migration note and a sweep of every metadata file that embeds the DOI string. This is intentionally rare.

When citing DNS Tool externally, prefer the concept DOI unless a specific version is required.

## Third-Party Data & Service Permissions

External permissions the project holds, recorded here so the obligation ships
with the code that eventually exercises it.

### RIPE Atlas (RIPE NCC)

**Commercial use of RIPE Atlas DNS measurements in DNS Tool is permitted.**
Requested via RIPE NCC support ticket **#1087914** (filed 2026-08-13,
"Commercial-use permission request — RIPE Atlas DNS measurements (DNS Tool)"),
escalated to the Atlas team 2026-08-14, and resolved as Atlas ticket **AT-351**
on 2026-08-18 by Johan ter Beest (RIPE Atlas Engineer): "This use is totally
fine," with the request to give attribution to RIPE Atlas where applicable.

**Standing obligation:** as of 2026-08-18 the codebase contains no RIPE Atlas
integration — this record deliberately predates it. Whoever lands Atlas
measurements or probe data in the product MUST ship attribution to RIPE Atlas
in the same change: on every UI surface where Atlas-derived data appears, and
in report provenance. The permission covers DNS measurements; a materially
different use (bulk redistribution, a competing measurement service) needs a
fresh ask.

## Questions

For licensing inquiries or commercial arrangements, contact: licensing@it-help.tech
