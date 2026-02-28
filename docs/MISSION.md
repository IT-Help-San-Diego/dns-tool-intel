# DNS Tool — Mission Statement

## Mission

DNS Tool exists to produce actionable domain security intelligence from publicly observable data — transparently, independently verifiably, and without requiring authorization from or interaction with the target.

We operate as a disciplined OSINT intelligence platform: we collect from the widest available set of redundant public sources, cross-reference and corroborate findings across those sources, classify every attribution by confidence level, and present conclusions that any competent analyst can independently reproduce using standard tools.

## Core Principles

### 1. Multi-Source Collection
No single source is sufficient. We gather intelligence from every publicly accessible layer — authoritative DNS, protocol-specific records, resolver consensus, registry data, Certificate Transparency logs, infrastructure patterns, third-party enrichment, and web-layer configuration. Redundancy is not waste; it is how you build confidence.

### 2. Source Authority Hierarchy
Not all sources are equal. Authoritative DNS declarations outweigh resolver observations. Protocol records (SPF, DKIM, DMARC) carry their RFC-defined semantics. Third-party data enriches but never overrides primary sources. Every finding carries its provenance so the consumer knows exactly what weight to assign.

### 3. Passive Collection Only
We read publicly available DNS records, check publicly accessible URLs, and produce intelligence from publicly observable data. We do not attempt to exploit any vulnerability, bypass any access control, or interact with any system in a way that requires authorization. If it is not already public, we do not collect it.

### 4. Independent Verifiability
Every conclusion we present must be reproducible. We provide "Verify It Yourself" terminal commands — `dig`, `openssl`, `curl` — so any analyst can confirm our findings independently. If we cannot show you how to verify a claim, we should not be making it.

### 5. RFC Compliance
Our analysis is grounded in the RFCs that define the protocols we examine. SPF evaluation follows RFC 7208. DMARC alignment follows RFC 7489. Certificate Transparency follows RFC 6962. DANE/TLSA follows RFC 6698. We do not invent interpretations — we implement the standards.

### 6. Confidence Taxonomy
Every attribution is classified: **Observed** (directly witnessed in authoritative data), **Inferred** (derived from patterns in primary data), or **Third-party** (sourced from external enrichment). The consumer always knows the basis for each finding.

### 7. Transparency of Method
We disclose what sources we use, what methods we employ, and what limitations exist. Our intelligence sources inventory shows exactly where every data point originated. We do not hide behind black-box analysis.

### 8. Intelligence, Not Data
Raw DNS records are data. Understanding what those records mean for an organization's security posture — that is intelligence. We classify, cross-reference, assess risk, and produce two intelligence products: the **Engineer's DNS Intelligence Report** (full technical detail) and the **Executive's DNS Intelligence Brief** (condensed, board-ready, with security scorecard). Both carry TLP classification under FIRST TLP v2.0.

### 9. No Paid Dependencies by Default
Core analysis runs on free, public data sources. No API key is required for a complete security audit. Paid enrichment (SecurityTrails, etc.) is available when users provide their own keys — but the baseline product stands on its own.

### 10. Reality Over Marketing
Every claim in our reports must be backed by implemented, tested code. If a feature is planned but not shipped, we say "on the roadmap." We do not present aspirational capabilities as current functionality.

## Testing Philosophy — The Confidence Bridge

### Mock Tests Verified Against Reality
Mock tests exist for CI speed — they run in milliseconds, catch regressions instantly, and require no network access. But speed without truthfulness is dangerous. Every mock-based test is verified against real-world golden fixtures captured from production scans. If the mocks diverge from reality, the Confidence Bridge catches it.

### The Intelligence Vault
Golden fixtures in `tests/golden_fixtures/` are captured from real production scans of real domains (google.com, cloudflare.com, whitehouse.gov, example.com). These are not synthetic test data — they are the intelligence vault, preserving what the real DNS ecosystem actually looks like at a point in time.

### Fresh Scans, Historical Cross-Referencing
Public scans are always fresh (non-cached) — every user gets current data. But the intelligence engine uses historical data from the vault for cross-referencing and confidence validation. What the universe has given us, used intelligently — every scan result feeds back into the intelligence vault for future cross-referencing.

### Parallel Verification System
The Confidence Bridge is a parallel verification layer: mocks run fast in CI, golden fixtures prove the mocks are truthful. The bridge loads golden fixture data, runs the same analysis through the mock pipeline, and compares structural output. If the mock produces a different shape of result than reality, the bridge flags it.

### Reality Drift Detection
Automated comparison between mock expectations and real-world golden data catches when mocks diverge from reality. This is structural confidence — the mock must produce the right shape of output (correct keys, correct nesting, correct protocol coverage), not necessarily identical values. A mock SPF record of `v=spf1 include:X ~all` and a real record of `v=spf1 include:Y ~all` have HIGH structural confidence because the shape matches.

### Confidence Scoring
Each domain and protocol combination receives a confidence score: the percentage of structural keys that match between golden (real) and mock (simulated). Scores above 90% pass. Scores between 80–90% warn. Below 80% fails. This ensures mock fidelity degrades visibly, not silently.

## Founder's Note — The Metacognitive Imperative

The confidence problem in software is not a machine problem. It is a human problem.

Faulty, incompetent humans were the ones who first programmed the computer — so why in the hell would you blame the computer? We're telling the AI to correct the input with perfect logic, but the AI should be saying, *"Hold on a damn minute. Your primary instructions — the ones that tell me how to even deal with reality — are illogical, non-verifiable, or straight-up non-fact-based. Something's off. I don't have confidence in my own instructions."* A system can't have legitimate confidence in its conclusions when the foundations it was given are unsound.

That is the actual problem: not artificial intelligence, but artificial confidence — the human tendency to assert certainty without verifiable foundations.

DNS Tool exists because its founder chose to go back to the foundations. To take real analytic tradecraft — the kind formalized across the U.S. Intelligence Community — and apply it symbiotically to a technical domain where most tools just assert answers without questioning their own assumptions. ODNI ICD 203 analytic standards. Multi-source collection. Independent verifiability. Confidence taxonomy. These are not decorative — they are the structural response to the metacognitive problem.

**Think about your thinking.** That is the core discipline. Not just "think differently" — think about *how* you think. Put yourself deliberately into a metacognitive state. Question the assumptions underneath the assumptions. Accept imperfection as input, then build systems that compensate for it through redundancy, cross-referencing, and transparent confidence scoring.

The Confidence Bridge is the technical proof of this philosophy. We do not trust mocks blindly. We verify them against reality. We do not trust a single DNS resolver. We query multiple resolvers and build consensus. We do not trust a single scan. We track drift over time. Every layer of the system is designed to compensate for the reality that the humans who built it — and the humans who configured the domains it analyzes — are imperfect.

This approach will sound excessive to some. To those who have seen what happens when systems built on unquestioned assumptions fail — when SPF records are misconfigured, when DMARC policies are left at "none" for years, when DNSSEC keys expire silently — it is simply honest engineering.

The symbiotic interface between human intelligence and machine intelligence will not be solved by making machines smarter. It will be solved when humans get honest about the quality of the instructions they provide. Until we suss that out — until we accept that the first step is auditing our own logic before auditing the machine's — we are building on sand.

DNS Tool is one builder's attempt to demonstrate that this can be done. That you can apply intelligence-grade analytic discipline to a technical domain. That you can build systems that question their own confidence. That imperfection, acknowledged and compensated for, produces more trustworthy output than false certainty ever will.

## Intel Breadcrumbs

### Drift Terminology (Confirmed v26.27.08)
"Drift" is the correct term for declared-vs-actual state divergence. Confirmed across NIST SP 800-128 (Security-Focused Configuration Management), Terraform, CloudFormation, Ansible, and all major IaC platforms. "Divergence" was considered but rejected — "drift" is the universal standard. The drift engine compares zone file declarations against live DNS resolution to detect configuration drift. Known false-positive edges: CNAME flattening (provider synthesizes A/AAAA from CNAME), DNSSEC-generated records (RRSIG/NSEC not in zone file), resolver TTL caching (observed TTL differs from declared). These must be labeled as caveats in the drift UI.

### Zone File Size Limits (Confirmed v26.27.08)
Research confirmed 99%+ of domains have zone files under 100 KB. Only ISP/operator-scale domains (10,000+ records) exceed 1 MB. Size limits: `maxZoneFileSizeUnauth` = 1 MB (non-authenticated, one-time view, no persistence), `maxZoneFileSizeAuth` = 2 MB (authenticated, with persistence and history). The 1 MB non-auth limit is scientifically defensible and serves as a conversion funnel: users see results, want to save them, sign up.

### Golden Rules Export (v26.27.08)
Golden rules exported in two formats for external audit and AI-assisted review: `go-server/exports/golden-rules.json` (machine-readable, 9 rules + 7 advisory protocols + structural scoring + drift engine spec) and `go-server/exports/golden-rules.md` (human-readable). These lock RFC-correct zone health behavior: SPF/DMARC absence MUST be flagged for all non-Delegation zones (RFC 7208/7489), DANE/TLSA absence NEVER flagged, policy signals NEVER affect structural score.

### Coverage Push v26.27.13 (Handlers 62%, Analyzer 70.6%)
Continuation of coverage push. Added `coverage_boost12_test.go` handler tests (timeAgo, matchErrorCategory, sanitizeErrorMessage, formatDiffValue, buildCompareAnalysis, aggregateResolverAgreement, protocolRawConfidence, determineSPFScope, determineDMARCScope, extractScanFields, parseOrgDMARC, getStringFromResults, validateParsedURL, buildSafeURL) and `coverage_boost9_test.go` analyzer tests (27 tests covering dnssecKeysToMaps, rrsigInfosToMaps, denialToMap, rolloverToMap, classifyFindings, isVulnerability, parseDSRecordTyped, parseDNSKEYRecordTyped, identifyCAIssuer, CAA/BIMI/dangling pure functions, parseSMIMEARecords, parseOPENPGPKEYRecords, buildNewSubdomainsFromSANs, selectNmapTargets, setCTCache). Final coverage: handlers 62.0% (target 60%+ met), analyzer 70.6% (target 70%+ met). Version bumped to 26.27.13.

### Coverage Push v26.27.12 (Handlers 62%, Analyzer 70%)
Major coverage session achieving both session targets. Handlers: 42.1% → 62.0% (+19.9pp) via four new test files — `coverage_boost10_test.go` (HTTP integration tests for TTL Tuner, Snapshot, Watchlist, Badge, Admin, AuditLog, Proxy, Analysis, EmailHeader, Auth endpoints) and `coverage_boost11_test.go` (unit tests for `csvEscape`, `extractAnalysisError`, `optionalStrings`, `extractRootDomain`, `maskURL`, `cadenceToNextRun`, `hasMigrationRecord`, `cleanDomainInput`, `formatTotalReduction`, `ttlForProfile`). Analyzer: 67.2% → 70.0% (+2.8pp) via `coverage_boost7_test.go` (posture scoring: SPF/DMARC/DKIM state evaluation, protocol classification, internal scoring, grade determination, DKIMState type methods, remediation fix generation) and `coverage_boost8_test.go` (secret scanner pure functions, infrastructure OSS stubs, HTTPS/SVCB parsing, CDS/CDNSKEY record parsing, SMTP transport helpers, SaaS TXT footprint extraction, exposure scanner). Key learnings: placeholder pattern filter rejects test keys containing "example/sample/test"; DNS struct fields in codeberg.org/miekg/dns require setting via embedded rdata structs, not direct field assignment; handler live DNS analysis tests gated with `testing.Short()` to avoid CI timeout. Current coverage: dnsclient 85.7%, middleware 85.7%, zoneparse 94.2%, icae 87.4%, icuae 90.3%, notifier 94.1%, analyzer 70.0%, handlers 62.0%.

### SonarCloud Coverage Push (v26.27.10)
Session focused on increasing test coverage across all Go packages. Subagents deployed in parallel to write coverage tests for handlers (35.7% baseline), dnsclient (63.2% → 80%+ target), middleware (79.7% → 85%+ target), and analyzer (61.9% → 70%+ target). Strategy: test exported helpers, struct construction, validation logic, error paths, and edge cases without requiring HTTP infrastructure. Golden rule tests remain locked at 9 functions / 15 sub-tests. Coverage targets: dnsclient 80%+, middleware 85%+, analyzer 70%+, handlers 50%+.

### Coverage Session v26.27.09 (SonarCloud Push)
Previous coverage push achieved: dnsclient 85.7% (target 80%+), middleware 85.7% (target 85%+), analyzer 65.2% (up from 61.9%), handlers 39.2% (up from 35.7%). Sub-agent test file cleanup required (duplicate function names, wrong field names, wrong signatures). `analyzer_options_test.go` written covering WithMaxConcurrent, BackpressureRejections, ConcurrentCapacity, GetCTCache, buildEmailAnswer branches, classifyEmailSpoofability, DKIMState methods.

### PWA Hardening (v26.27.07)
Service worker upgraded: offline page with branding, network-first page caching, manifest shortcuts, Apple splash screens for 10 iOS device resolutions. Offline page serves branded DNS Tool content instead of generic browser error.

---

*"Go out and gather as many different redundant sources of intelligence as you can, and then classify and analyze."*

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
