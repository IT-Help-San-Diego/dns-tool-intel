# DNS Tool — Boundary Manifest

> **Status:** ARCHIVED (v26.48 — intel/oss build-tag split removed)
>
> This document described the former open-core boundary between `_oss.go` stubs
> and `_intel.go` implementations. The codebase was unified under BUSL-1.1 in
> v26.48; all implementations now live in `_impl.go` files with no build-tag
> separation. Retained as historical record.

**Version:** 1.0
**Architecture:** ~~Single-repo open-core with Go build tags~~ — Unified single-repo (BUSL-1.1)

---

## Purpose

This document inventoried every stubbed subsystem in the public repository and defined the boundary between public framework code and private intelligence modules. It existed so that contributors, auditors, and AI assistants could understand what was implemented in the open-core public build versus what required the `intel` build tag.

---

## Subsystems — Analyzer Package

### `internal/analyzer/`

| Subsystem | Framework File | Implementation | Description |
|-----------|---------------|----------------|-------------|
| **Edge/CDN Detection** | `edge_cdn.go` | `edge_cdn_impl.go` | Detects CDN and edge providers from ASN, CNAME, and header patterns |
| **Infrastructure Detection** | `infrastructure.go` | `infrastructure_impl.go` | Identifies hosting, DNS, and email infrastructure providers |
| **Provider Classification** | `providers.go` | `providers_impl.go` | ESP detection, DKIM provider maps, SPF flattening service identification |
| **IP Investigation** | `ip_investigation.go` | `ip_investigation_impl.go` | Deep IP intelligence — geolocation, ASN enrichment, threat correlation |
| **Posture Diff** | `posture_diff.go` | `posture_diff_impl.go` | Compares security posture between scans to detect drift |
| **Manifest** | `manifest.go` | `manifest_impl.go` | Intelligence manifest — tracks what sources contributed to each finding |
| **SaaS TXT** | `saas_txt.go` | `saas_txt_impl.go` | Detects SaaS domain verification TXT records and classifies services |
| **Remediation** | `remediation.go` | (inline) | RFC-aligned remediation engine with priority fixes |
| **Confidence** | `confidence.go` | (inline) | Confidence classification — Observed, Inferred, Third-party attribution |
| **Commands** | `commands.go` | (inline) | "Verify It Yourself" terminal command generation |

### `internal/analyzer/ai_surface/`

| Subsystem | Framework File | Implementation | Description |
|-----------|---------------|----------------|-------------|
| **AI HTTP Surface** | `http.go` | `http_impl.go` | Detects AI-relevant HTTP headers and configurations |
| **LLMs.txt** | `llms_txt.go` | `llms_txt_impl.go` | Parses and validates llms.txt files for AI crawler guidance |
| **Poisoning Detection** | `poisoning.go` | `poisoning_impl.go` | Detects DNS and content poisoning indicators relevant to AI training |
| **Robots.txt AI** | `robots_txt.go` | `robots_txt_impl.go` | Analyzes robots.txt for AI-specific crawler directives |
| **AI Surface Scanner** | `scanner.go` | `scanner_impl.go` | Orchestrates AI surface analysis across all sub-modules |

---

## Stubs Reference Directory (Removed)

The `stubs/` directory formerly contained reference copies of the `_oss.go` stub files.
It was removed when the codebase was unified under BUSL-1.1 in v26.48.
All implementations now live directly in `go-server/internal/analyzer/` as `_impl.go` files.

---

## Boundary Integrity Tests (Removed)

The former boundary integrity tests (`boundary_integrity_test.go`) were removed
when the intel/oss build-tag split was eliminated. They verified the now-obsolete
contract between `_oss.go` stubs and `_intel.go` implementations.

---

## What Stays Public

The following subsystems are fully implemented in the public repository with no intel-gated components:

- **SPF Analysis** (`spf.go`) — RFC 7208 compliant
- **DMARC Analysis** (`dmarc.go`) — RFC 7489 compliant
- **DKIM Discovery** (`dkim.go`) — RFC 6376, 81+ known selectors
- **DNSSEC Validation** (`dnssec.go`) — RFC 4033-4035
- **DANE/TLSA** (`dane.go`) — RFC 6698
- **MTA-STS** (`mta_sts.go`) — RFC 8461
- **TLS-RPT** (`tlsrpt.go`) — RFC 8460
- **BIMI** (`bimi.go`) — RFC 9495
- **CAA** (`caa.go`) — RFC 8659
- **DNS Client** (`dnsclient/`) — Multi-resolver queries
- **ICAE** (`icae/`) — Intelligence Confidence Audit Engine
- **ICuAE** (`icuae/`) — Intelligence Currency Audit Engine
- **All handlers** (`handlers/`) — Request handling, auth, export
- **All templates** (`templates/`) — HTML rendering
- **All middleware** (`middleware/`) — CSP, rate limiting, analytics

---

## Design Principles

1. **Build must be fully functional**: The default build produces a working application. Implementation files return safe defaults where full logic has not yet been built out. Users see "no data available" rather than crashes.

2. **No proprietary logic in framework files**: Framework files define interfaces and types. Classification algorithms, provider databases, and detection heuristics live exclusively in `_impl.go` implementations.

3. **Implementations are contracts**: The function signatures in `_impl.go` files must match the framework file counterparts.

4. **One-way dependency**: Implementation code extends framework code. Framework code never depends on implementation details.

---

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
