# Subdomain Discovery Pipeline — Implementation Details

> **CLASSIFICATION: PROPRIETARY — Intel Repo Only**
> This document contains implementation details that MUST NOT appear in the public DnsToolWeb repository.
> Public-facing documentation should describe WHAT (CT + DNS + CNAME) at a high level, NEVER HOW.

## Pipeline Overview

The subdomain discovery pipeline is the tool's most valuable differentiator — it consistently finds subdomains where competing tools fail. **Treat as critical infrastructure. Do not modify without golden rule test coverage.**

## Pipeline Sequence (Order is Load-Bearing)

```
CT fetch → deduplication → processCTEntries() → DNS probing → CNAME traversal → enrichSubdomainsV2() → recount → sortSubdomainsSmartOrder() → cache → applySubdomainDisplayCap()
```

### Stage 1: Certificate Transparency Fetch
- Source: crt.sh PostgreSQL interface
- URL format: `https://crt.sh/?q=%.{domain}&output=json`
- Independent 10-second context via `context.Background()` — crt.sh can no longer block the analysis
- Body limit: 10MB (for large domains like apple.com)
- CT unavailability is graceful fallback, not an error — DNS probing still runs independently

### Stage 2: CT Entry Processing — `processCTEntries()`
- Deduplicates CT entries by normalized hostname
- Extracts subdomain names from certificate `name_value` fields
- Detects `*.domain` wildcard patterns → reports active/expired status with info banner
- Wildcard entries get normalized to base domain and filtered from explicit subdomain list
- Date parsing via `parseCertDate()` handles multiple formats (ISO 8601, date-only, datetime)

### Stage 3: DNS Probing — `probeCommonSubdomains()`
- Probes ~290 common service names (www, mail, api, admin, vpn, sso, owa, etc.)
- **Transport**: High-speed UDP DNS queries (single packet) to 8.8.8.8 with fallback to 1.1.1.1
- **NOT DoH**: DoH is orders of magnitude more expensive for bulk operations (TCP+TLS+HTTP/2 overhead vs single UDP packet)
- **Method**: `ProbeExists()` — queries A record only, extracts CNAME from response (single query per name, not 3 separate A/AAAA/CNAME)
- **Concurrency**: 20 goroutines with semaphore cap
- **Context**: Independent 15-second context, separate from the shared analysis context
- Source attribution: "DNS" for probed subdomains

### Stage 4: CNAME Chain Traversal
- Follows CNAME chains to show where each hostname actually points
- Reveals third-party infrastructure (CloudFront, Azure, Akamai, etc.)
- Integrated into the probe step — CNAME extracted from the same A record query

### Stage 5: Enrichment — `enrichSubdomainsV2()`
- **MUST happen before sort and count** — it mutates `is_current` based on live DNS resolution
- Uses `ProbeExists()` (UDP) not `QueryDNS` (DoH) — matches the probing transport
- Independent 10-second context with 20-goroutine concurrency
- Determines current vs historical status via live DNS A/CNAME resolution

### Stage 6: Sort — `sortSubdomainsSmartOrder()`
- Smart ordering: well-known service names first, then DNS-resolving hosts, then by certificate activity
- Preserves all fields through sort: source, first_seen, cname_target, cert_count

### Stage 7: Display Cap — `applySubdomainDisplayCap()`
- Soft cap: 200 displayed subdomains
- Historical overflow: 25 additional historical-only entries
- **NEVER hides current/active subdomains** — only historical entries are capped
- CSV export bypasses display cap: `/export/subdomains?domain=X` exports ALL cached subdomains

## Key Invariants (DO NOT BREAK)

1. Enrichment (`enrichSubdomainsV2`) MUST happen before sort and count
2. Display cap NEVER hides current/active subdomains
3. CT unavailability is graceful fallback — DNS probing still runs
4. Golden rule tests protect: ordering, display cap, field preservation, free CA detection
5. `ProbeExists()` uses UDP, not DoH — performance critical
6. Each pipeline stage has its own independent timeout context

## Performance Characteristics

- **CT fetch**: 10-second independent context
- **DNS probing**: ~1 second for ~290 names (UDP, 20 goroutines, 15s cap)
- **Enrichment**: ~1 second (UDP, 20 goroutines, 10s cap)
- **Total pipeline**: ~2-5 seconds typical, vs 60+ seconds with original DoH implementation

## Design Lessons

- DoH is orders of magnitude more expensive than UDP DNS for bulk operations
- Single UDP DNS query: one packet sent, one received (~100 bytes each)
- Single DoH query: TCP handshake + TLS handshake + HTTP/2 framing + HTTPS overhead (hundreds of packets)
- For bulk probing ~290 names, the difference is catastrophic (60s+ vs <2s)
- Independent timeout contexts prevent one slow stage from consuming the entire analysis budget

## Golden Rule Tests (Subdomain-Related)

- `TestGoldenRuleWildcardCTDetection` — wildcard-only CT entries produce 0 explicit subdomains but trigger wildcard flag
- `TestGoldenRuleWildcardNotFalsePositive` — explicit subdomain entries don't falsely trigger wildcard detection
- `TestGoldenRuleSubdomainSmartOrder` — smart ordering preserves expected priority
- `TestGoldenRuleSubdomainDisplayCapNeverHidesActive` — display cap invariant
- `TestGoldenRuleCTUnavailableFallbackProducesResults` — empty CT entries gracefully produce empty results
- `TestGoldenRulePipelineFieldsPreservedThroughSort` — source, first_seen, cname_target, cert_count survive sort
- `TestGoldenRuleFreeCertAuthorityDetection` — free vs paid CA classification

## Source Files (Public Repo)

| File | Contains |
|------|----------|
| `go-server/internal/analyzer/subdomains.go` | Full pipeline implementation |
| `go-server/internal/dnsclient/client.go` | `ProbeExists()` UDP method |
| `go-server/internal/analyzer/golden_rules_test.go` | Golden rule test coverage |

---

*Last updated: February 18, 2026 — v26.19.42*
*This document is PROPRIETARY. It belongs in the careyjames/dnstool-intel private repository ONLY.*
