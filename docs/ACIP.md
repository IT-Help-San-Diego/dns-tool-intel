# DNS Tool — AI Change Interrogation Protocol (ACIP)

**Status:** Active
**Version:** 1.0
**Applies to:** All AI-assisted code changes in `dns-tool-web` and `dns-tool-intel`

---

## Purpose

ACIP is a lightweight governance protocol for interrogating AI-generated code changes before they enter the codebase. It exists because AI assistants optimize for plausibility, not correctness — and plausible-but-wrong changes are the most dangerous kind.

This protocol ensures that every AI-assisted change is subjected to the same epistemic discipline that DNS Tool applies to DNS intelligence: multi-source verification, confidence classification, and independent reproducibility.

---

## The Three Questions

Every AI-generated change must answer three questions before merge:

### 1. What changed and why?

- Diff must be human-reviewable (no bulk reformats mixed with logic changes)
- The change rationale must reference a concrete requirement, bug, or task ID
- If the AI invented a requirement, the change is rejected

### 2. What could this break?

- Boundary integrity: Does this change cross the public/intel boundary?
- Stub contracts: Do OSS stubs still compile and return safe defaults?
- Test coverage: Do existing tests still pass? Are new paths covered?
- RFC compliance: Does this change alter how any RFC-defined protocol is parsed or evaluated?

### 3. How do we verify it?

- Unit tests must cover the changed logic
- Boundary integrity tests (`boundary_integrity_test.go`) must pass
- Golden fixture tests must not regress
- Build must succeed with both default and `intel` build tags

---

## Change Classification

| Category | Risk | Required Verification |
|----------|------|-----------------------|
| **Template/CSS** | Low | Visual review, mobile check |
| **Handler logic** | Medium | Unit tests, integration test |
| **Analyzer logic** | High | Unit tests, golden fixtures, ICAE cases |
| **Stub/boundary files** | Critical | Boundary integrity tests, dual-tag build |
| **Database schema** | Critical | Migration review, rollback plan |
| **DNS client** | Critical | Multi-resolver tests, live integration test |

---

## Boundary-Sensitive Changes

Changes to files in the public/intel boundary require additional scrutiny:

1. **OSS stub files** (`*_oss.go`): Must compile independently, return safe defaults, never import intel-only packages
2. **Framework files** (e.g., `edge_cdn.go`, `confidence.go`): Must not embed proprietary logic — classification algorithms, provider databases, and methodology belong in the intel repo
3. **Build tags**: `//go:build !intel` on stubs, `//go:build intel` on intel implementations — never omitted, never inverted
4. **Stubs directory** (`stubs/`): Reference copies must stay synchronized with their corresponding OSS files

---

## AI-Specific Failure Modes

These are patterns where AI assistants commonly introduce errors in this codebase:

| Failure Mode | Detection | Prevention |
|---|---|---|
| **Hallucinated RFC citations** | Cross-reference against IETF datatracker | Never trust AI-generated RFC numbers without verification |
| **Stub contract violation** | `boundary_integrity_test.go` fails | Run boundary tests before any merge |
| **Silent behavior change** | Golden fixture diff | Compare analyzer output against golden fixtures |
| **Dependency injection** | `go.mod` diff review | No new dependencies without explicit approval |
| **Hard-coded test data** | Code review | Test data must come from golden fixtures or deterministic generators |
| **Confidence inflation** | ICAE score regression | ICAE audit scores must not decrease after a change |

---

## Protocol Enforcement

ACIP is enforced through existing automated checks:

- **Build**: `go build` (OSS) and `go build -tags intel` (full) must both succeed
- **Boundary tests**: `go test ./internal/analyzer/ -run TestBoundary` must pass
- **ICAE**: Protocol confidence scores must not regress
- **Golden fixtures**: Structural confidence bridge must maintain ≥90% match

Manual enforcement:

- Reviewer must confirm the change answers the Three Questions
- Changes touching `*_oss.go` or `*_intel.go` files require explicit boundary review
- RFC-affecting changes require citation verification against the actual RFC text

---

## Relationship to Other Governance

- **BOUNDARY_MANIFEST.md**: Documents which subsystems are stubbed and where the public/intel boundary lies
- **MISSION.md**: Defines the epistemic principles that ACIP enforces procedurally
- **ICAE**: Provides quantitative confidence scoring that ACIP references for regression detection
- **ICuAE**: Ensures data currency standards are maintained through changes

---

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
