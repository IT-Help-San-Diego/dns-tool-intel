# DNS Tool — Roadmap

> Last updated: March 2, 2026

---

## Completed

| Feature | Version | Completion Date |
|---------|---------|-----------------|
| Optional Authentication Model (Google OAuth 2.0 with PKCE) | v26.20.56–57 | Feb 2026 |
| Drift Engine Phase 1 (Posture Hashing) | v26.19.40 | Feb 2026 |
| Drift Engine Phase 2 (Structured Diff, Drift Alert UX) | v26.19.40 | Feb 2026 |
| Probe Network First Node | v26.20.0+ | Feb 2026 |
| LLM Documentation Strategy (Implementation Verification Sections) | v26.25.26 | Feb 2026 |
| XSS Security Fix (Tooltip Safe DOM Rendering) | v26.25.26 | Feb 2026 |
| Architecture Page with Mermaid Diagrams | v26.20.77–83 | Feb 2026 |
| DKIM Selector Expansion (39→81+ Selectors) | v26.20.69–70 | Feb 2026 |
| Brand Verdict Matrix Overhaul | v26.20.71 | Feb 2026 |
| Email Header Analyzer (Multi-Format, Spoofing Detection, Scam Analysis) | v26.20.0+ | Feb 2026 |
| Intelligence Confidence Audit Engine (ICAE) | 129 Test Cases | Feb 2026 |
| Intelligence Currency Assurance Engine (ICuAE) | 29 Test Cases | Feb 2026 |
| Color Science Page (CIE Scotopic Validation, WCAG Contrast) | v26.20.0+ | Feb 2026 |
| Badge System (SVG Badges, Shields.io Integration) | v26.20.0+ | Feb 2026 |
| Domain Snapshot | v26.20.0+ | Feb 2026 |
| Owl of Athena Logo (AI-Generated Original) | v26.20.0+ | Feb 2026 |
| Certificate Transparency Resilience (Certspotter Fallback) | v26.20.76 | Feb 2026 |
| Nmap DNS Security Probing | v26.20.0+ | Feb 2026 |
| One-Liner Verification Commands | v26.20.0+ (commands.go GenerateVerificationCommands) | Feb 2026 |
| Zone File Upload for Analysis | v26.20.0+ (Authenticated-only, /zone endpoint) | Feb 2026 |
| Hash Integrity Audit Engine | v26.21.45 | Feb 2026 |
| Download Verification (SHA-3-512 Checksums, Kali-Style Sidecar) | v26.21.49–50 | Feb 2026 |
| Accountability Log (/confidence/audit-log) | v26.21.46 | Feb 2026 |
| TTL Tuner (Beta) | v26.25.86–88 | Feb 2026 |
| Six-Agent Security & Performance Audit | v26.25.88 | Feb 2026 |
| TLD NS Count Bug Fix + Executive TLD Gating | v26.25.90 | Feb 2026 |
| CSRF Form Fix (TTL Tuner & Watchlist) | v26.26.41 | Feb 2026 |
| TTL Tuner UX Overhaul (Loading, Auto-Scroll, Profile Selection) | v26.26.42–43 | Feb 2026 |
| DNS Provider Detection Expansion (5→15 Providers) | v26.26.44 | Feb 2026 |
| NS Provider-Locked Display + Rate Limit Redirect Fix | v26.26.44 | Feb 2026 |
| HTTP Observatory A+ Infrastructure (Secure Cookies, Full Header Suite) | v26.27.01 | Feb 2026 |
| Mobile Homepage Scroll Fix + Navbar Dropdown Refinement | v26.27.01 | Feb 2026 |
| TTL Tuner Mobile Responsive Table | v26.27.02 | Feb 2026 |
| SonarCloud Quality Gate Fixes (Unchecked Error Returns) | v26.27.02 | Feb 2026 |
| RFC Compliance vs Operational Security Pattern (SPF/DKIM/DMARC) | v26.28.36 | Mar 2026 |
| CVE Context in Email Security Panels (CVE-2024-7208/7209/49040) | v26.28.36 | Mar 2026 |
| DMARCbis Forward-Looking Notes (Standards Track, pct→t, np=) | v26.28.36 | Mar 2026 |
| DANE Context Deadline Fix (Fresh Context for Post-Parallel Tasks) | v26.28.34 | Feb 2026 |
| DNS Intelligence Upgrade (EDNS0 + DO Bit, AD Flag Tracking) | v26.28.35 | Feb 2026 |
| Topology Text & Container Sizing | v26.28.37 | Mar 2026 |
| Golden Fixtures Node Promoted to Cylinder | v26.28.38 | Mar 2026 |
| Action Pill Nodes (Persist, Seeds, Baselines, Validates) | v26.28.39 | Mar 2026 |
| Fully Responsive Zone-Based Layout with Collision Enforcement | v26.28.40 | Mar 2026 |
| Edge Labels Hover-Only, Explicit Protocol Angle Mapping, Persist Pill Repositioned | v26.28.41 | Mar 2026 |
| Unified OG Image System (6 images, consistent design, ImageMagick generator script) | v26.28.44 | Mar 2026 |
| Forgotten Domain Video (embedded on approach page, dedicated sharing page at /video/forgotten-domain) | v26.28.44 | Mar 2026 |
| Performance Optimization (gzip DefaultCompression, CSS/font preload hints) | v26.28.45 | Mar 2026 |
| Video Styling Fix (approach page — constrained width, poster, label, caption) | v26.28.46 | Mar 2026 |
| Test Coverage Expansion (exports_ice_test.go, coverage_boost14_test.go, main_test.go) | v26.28.46 | Mar 2026 |

---

## In Progress / Queued

| Feature | Status | Priority | Notes |
|---------|--------|----------|-------|
| Personal Analysis History | Queued | Medium | Currently shared global feed. Requires per-user session tracking and database schema expansion. |
| Drift Engine Alerts | Queued | Medium | Notifications when domain security posture changes. Requires webhook/email notification subsystem. |
| Saved Reports | Queued | Medium | Bookmark and revisit past analyses. Requires report snapshot storage and user library. |
| API Access (Programmatic Analysis) | Queued | High | Programmatic analysis for automation workflows. Requires rate limiting, authentication, versioning. |
| CLI App (Homebrew/Binary) | Queued | High | Terminal application for macOS/Linux. Requires cross-platform distribution and binary packaging. Works without login for basic analysis; authenticated mode unlocks history sync, drift alerts, and API quota. |
| Drift Engine Phases 3–4 | Queued | Medium | Phase 3: Timeline visualization of posture changes. Phase 4: Scheduled monitoring and baselines. Full roadmap in dns-tool-intel (private). |
| Probe Network Expansion | Queued | High | Additional OSINT verification nodes: SMTP/TLS verification, DANE/DNSSEC validation, testssl.sh analysis. Multi-probe consensus, geo-variance detection, regional blocking detection. |
| Multi-Probe Consensus Engine | Queued | High | Cross-probe agreement analysis: TLS config consensus, DANE validation from independent resolvers, certificate fingerprint comparison, latency differentials. |
| Probe Security.txt + Landing Pages | Queued | Medium | Transparency artifacts for probe VPS nodes: /.well-known/security.txt + minimal landing page declaring measurement purpose and abuse contact. |
| Globalping.io Integration | Queued | Low | Distributed DNS resolution probes from 100+ global locations. Complements (not replaces) existing SMTP port 25 probe. Adds "resolving consistently worldwide?" capability. |
| Homebrew Distribution | Queued | Medium | macOS/Linux package distribution. Coordinates with CLI app delivery. |
| Zone File Import as Drift Baseline | Queued | Low | "Baseline Snapshot" comparison. Upload zone file to establish posture baseline for future drift detection. Zone parsing library selected; UX copy/disclaimer to be drafted. |
| Raw Intelligence API Access | Queued | Low | Direct access to collected intelligence without processing layers. Requires access control and audit logging. |
| ISC Recommendation Path Integration | Queued | Low | Integration with ISC (Internet Systems Consortium) remediation/hardening recommendations. Requires partnership or integration with ISC tooling. |
| CVE Database Matching | Queued | Medium | Automated CVE cross-referencing for protocol findings. Map discovered configurations to known vulnerabilities (NVD/MITRE). Currently manual CVE citations; future automated matching against live CVE feeds. |
| DMARCbis Standards Track Tracking | Queued | Medium | Monitor draft-ietf-dmarc-dmarcbis progression through IETF. Auto-update compliance guidance when RFC is published. Track pct→t migration, np= tag adoption, DNS tree walk mandate. |
| TLD Zone Health: Parent/Child Delegation Consistency | Queued | High | Compare NS set in parent (root zone) vs child (TLD zone), DS/DNSKEY alignment, glue completeness (esp. in-bailiwick NS for ccTLDs), TTLs at parent vs child. This is "delegation security" as registries understand it. |
| TLD Zone Health: Nameserver Fleet Matrix | Queued | High | Per-nameserver characterization: IPv4+IPv6 addresses, ASN/operator diversity scoring, UDP+TCP reachability (v4/v6), EDNS0 buffer sizing, truncation/TCP fallback, AA flag + lame delegation check, SOA serial per NS (detect sync issues). Currently we show NS hostnames but don't characterize the fleet. |
| TLD Zone Health: DNSSEC Operations Deep Dive | Queued | High | Beyond current "Signed, algorithm, AD flag, DS record" — add: DNSKEY RRset (KSK vs ZSK key tags, key sizes), RRSIG inception/expiration windows (how close to expiry?), NSEC vs NSEC3 with parameter sanity, rollover readiness signals (multiple DNSKEYs present? DS aligned?). Heart of "zone health" for operators. |
| TLD Zone Health: Multi-Vantage Availability | Queued | Medium | Global latency distribution, timeout/SERVFAIL rates, regional anomalies, regressions over time. Complements multi-resolver consensus. Requires probe network expansion. Similar to RIPE DNSMON concept but with change detection. |
| TLD Zone Health: Pre-Delegation Simulation Mode | Queued | Medium | Let TLD operators paste candidate NS set (hostnames + IPs) and/or candidate DS/DNSKEY, then run full delegation + DNSSEC verification as if live. Maps to Zonemaster "delegation quality" testing and ICANN PDT readiness. |
| TLD Zone Health: Change Detection & Alerting | Queued | Medium | Registry-specific drift: "What changed since last run?" (NS/DS/DNSKEY/SOA timers). Alerts on DS mismatch, DNSKEY changes, SOA serial divergence, NS unreachable, DNSSEC validation failures. Timeline keyed to "incident start." Builds on existing drift engine. |
| TLD Zone Health: Machine-Consumable Outputs | Queued | Low | Stable versioned JSON API for current TLD status, webhook events for state transitions, export formats for NOC tooling. Leverages existing integrity hashes. |
| TLD Zone Health: Registry Identification & IANA Metadata | Queued | Low | Show registry operator + IANA metadata instead of "Registrar unknown / DNS hosting unknown." Current domain-owner fields don't map to registry reality. |

---

## Concept Stage

| Idea | Status | Notes |
|------|--------|-------|
| Terminal CLI + Web Terminal Demo | Needs Vetting | Real terminal app (Homebrew/binary) that works in actual terminals, plus potentially a web-based terminal demo for browser. Uncertain whether web demo adds value or dilutes the real-terminal experience. Requires architectural discussion before commitment. |

---

## Rationale & Notes

### Completed Items

All items in the "Completed" section have working implementations in the codebase (v26.20.0–v26.28.46 as of March 2026). Every item has either been verified by test suites, deployed to production, or demonstrated in public releases.

**Key completions**:
- **Authentication (v26.20.56–57)**: Zero-friction paste-and-go remains; login is optional, premium features require authentication.
- **Drift Engine Phases 1–2**: Foundation (posture hashing with SHA-3-512) and comparison (structured diff, drift alert UX) are complete. Phases 3–4 (timeline, scheduled monitoring) remain queued.
- **Email Header Analyzer**: Multi-format support (.eml, .json, .mbox, .txt), third-party vendor detection (Proofpoint, Barracuda, Microsoft SCL, Mimecast), subject line scam analysis, homoglyph normalization.
- **ICAE/ICuAE**: Intelligence scoring engines with 129 and 29 test cases respectively, covering confidence and currency/timeliness.

### Queued Items

Items in "In Progress / Queued" are documented, architected, but not yet implemented. Priority reflects relative importance:

- **High**: API access, CLI app, and TLD Zone Health features (delegation consistency, fleet matrix, DNSSEC deep dive) unlock programmatic workflows, terminal-first users, and the registry operator market. Strategic for market expansion.
- **Medium**: Personal history, drift alerts, saved reports, Homebrew distribution, Phases 3–4, TLD pre-delegation simulation, TLD change detection require moderate engineering and provide strong user value.
- **Low**: Raw intelligence API, ISC integration, zone file import, TLD machine-consumable outputs, TLD registry metadata are specialized features with narrower user bases.

**API Access** and **CLI App** are strategically important for automation workflows and developer adoption. Both require authentication, rate limiting, and careful versioning.

**Drift Engine Phases 3–4** are high-value commercial features (timeline visualization, scheduled monitoring). Full technical roadmap is confidential (in dns-tool-intel private repo).

### Concept Stage

**Terminal CLI + Web Terminal Demo** remains in concept because it requires architectural vetting:
- Does a web-based terminal demo add practical value, or does it dilute the real-terminal experience?
- What integration points are needed with the live DNS Tool web app?
- Should it be a separate deployment or embedded feature?

This item should not advance to queued until core architects and the security research community provide feedback.

---

## Version & Maintenance

**Last Updated**: March 2, 2026  
**Next Review**: Post-v26.29.0 release or every two weeks  
**Owner**: DNS Tool Architecture Team

When marking items as complete:
1. Cite the version number where implementation occurred
2. Update this document within the same session
3. Archive detailed release notes in `EVOLUTION.md`
