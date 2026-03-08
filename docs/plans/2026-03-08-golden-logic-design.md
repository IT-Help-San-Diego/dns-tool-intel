# Golden Logic — Traceable Logic Drift Detection

**Status**: Draft — Approved for development  
**Version**: 0.1.0  
**Date**: 2026-03-08  
**Author**: Carey James Balboa / Architect Review / Deep Research  
**Classification**: dns-tool:scrutiny science  

## The Problem

Everyone watches the data. Data drift detection, schema drift detection, model drift detection — entire industries exist to monitor when *data* changes. But nobody asks the prior question: **is the logic we're using to interrogate this data even correct?**

The fundamental failure mode between humans and computers is not bad data. It's bad logic — flawed reasoning encoded into code, executed faithfully by machines, producing wrong answers that nobody catches because they're only watching the output.

When a DNS Tool analysis says "SPF is misconfigured," that verdict flows from a chain of logical decisions. Each decision was made by a human, grounded (or not) in an RFC, encoded into Go, and tested (or not) by a test. If any link in that chain is wrong — the RFC was misread, the code diverged, the test proves the wrong thing — the output is wrong. And today, there's no way to see that chain, hash it, or detect when it drifts.

**Golden Logic solves this.**

## The Principle

*Check your logic before you blame your data.*

This principle is universal. It applies to DNS security analysis, personal websites, ML pipelines, financial systems — anywhere humans encode reasoning into code. DNS Tool is the first system to implement it as traceable, hashable, drift-detectable infrastructure.

## What Golden Logic Is

A system where every logical decision in the codebase:

1. **Has a canonical definition** — a named rule with a deterministic ID
2. **Traces to its foundation** — the RFC section, standard, or original reasoning that justifies it
3. **Traces to its implementation** — the exact file, line, and function in code
4. **Traces to its proof** — the test that verifies the logic produces correct results
5. **Has a cryptographic hash** — SHA-3-512 of the rule definition, computed at build time
6. **Is monitored for drift** — when code changes, test changes, or reasoning changes without the others being updated, the system detects the misalignment
7. **Is visually connected** — in TheBrain (relationship graph), Topology (mathematical/spatial), Mermaid/SVG (architectural), and Notion (structured tracking)

## What Makes This Novel

Deep research confirms: **nobody has built this.**

### What Exists (Adjacent Work)

| Domain | What It Tracks | What It Misses |
|--------|---------------|----------------|
| Data drift (ML) | Statistical distribution changes in data | The logic interpreting the data |
| Schema drift (data engineering) | Structural changes in databases | The reasoning behind the schema |
| Configuration drift (DevOps) | Infrastructure config changes | Why the config was set that way |
| Process drift (business process mining) | Behavioral changes in workflows | The logic design behind the workflow |
| Formal verification (TLA+, Coq) | Mathematical proof of correctness at a point in time | Temporal drift — how logic evolves over time |
| Policy compliance (regulatory) | Current state vs. regulatory requirements | Historical drift and reasoning evolution |

### What Golden Logic Adds

- **Logic-level integrity monitoring** — watching the *reasoning*, not just the code or data
- **Temporal drift detection** — tracking how logic evolves over time with cryptographic proof
- **Multi-dimensional traceability** — RFC → reasoning → code → test → visual, all linked
- **Origin classification** — distinguishing RFC-derived logic from DNS Tool-invented logic
- **Disagreement tracking** — where our interpretation differs from others' reading of the same standards
- **Intentional vs. unintentional change detection** — "we updated the rule" vs. "the code drifted without updating the rule"

### Intellectual Heritage

The chain traces from Aristotle's formal logic (the syllogism as the first logical rule), through Frege's *Begriffsschrift* (first formal logic language, 1879), Russell's type theory, Gödel's incompleteness theorems (you cannot prove everything from inside the system — which is *why* external verification is necessary), Turing's computability theory, Dijkstra's structured programming, Hoare logic (preconditions/postconditions), and modern formal methods (TLA+, Coq, Isabelle). Golden Logic extends this lineage by adding *temporal drift detection* to formal reasoning — not just "is this correct now?" but "has this drifted from when we verified it?"

## Data Model

### Logic Rule

```yaml
# Example rule from docs/logic/registry.yaml
- rule_id: LR-SPF-HARDFAIL-v1
  title: "SPF Hard Fail Means Reject"
  statement: >
    When an SPF record contains the '-all' mechanism, unauthorized senders
    MUST be rejected. This is the strongest SPF enforcement level.
  origin_type: rfc_derived  # rfc_derived | invented | hybrid
  status: active            # draft | active | deprecated | superseded
  protocol: spf
  scrutiny_class: science
  
  # Foundation — where the logic comes from
  rfc_refs:
    - rfc: "RFC 7208"
      section: "4.6.2"
      normative_level: MUST
      quote: "'-' prefix means fail: the client is not authorized"
      quote_hash: "sha3-512:abc123..."
  
  # Implementation — where the logic lives in code
  code_refs:
    - file: "go-server/internal/analyzer/spf.go"
      line_start: 142
      line_end: 158
      symbol: "classifySPFEnforcement"
      repo: public
    - file: "go-server/internal/analyzer/remediation.go"
      line_start: 89
      line_end: 95
      symbol: "spfRemediationForSoftFail"
      repo: intel
  
  # Proof — what tests verify this logic
  test_refs:
    - test_id: "TestSPFHardFailClassification"
      file: "go-server/internal/analyzer/spf_test.go"
      line: 234
      assertion_type: behavioral  # behavioral | boundary | regression | golden
    - test_id: "TestGoldenRuleSPFEnforcement"
      file: "golden_rules/golden_rules_test.go"
      repo: intel
      assertion_type: golden
  
  # Reasoning — why we made this decision
  reasoning: >
    RFC 7208 §4.6.2 is unambiguous: '-all' means fail. Some implementations
    treat soft fail (~all) and hard fail (-all) identically, but this conflates
    two distinct sender intentions. We honor the RFC distinction because the
    domain owner chose '-all' deliberately.
  
  # Disagreements — where we differ from others
  disagreements:
    - source: "Google/Gmail implementation"
      their_position: "Treats ~all and -all identically in practice"
      our_position: "We distinguish them because the RFC distinguishes them"
      adjudication: "RFC-grounded — our position matches the standard"
      confidence_delta: 0.0  # no confidence reduction; we're right
  
  # Hash — computed at build time
  rule_hash: ""  # populated by build system
  last_verified: "2026-03-08T10:00:00Z"
  last_verified_by: "TestSPFHardFailClassification"
```

### Origin Types

| Type | Meaning | Tracking Requirement |
|------|---------|---------------------|
| `rfc_derived` | Logic directly from an RFC section | MUST cite RFC, section, normative level |
| `invented` | DNS Tool's own logic, not from any RFC | MUST document reasoning and justification |
| `hybrid` | RFC foundation + our extension | MUST cite RFC AND document our additions |

### Rule Status Lifecycle

```
draft → active → [deprecated | superseded]
                       ↓              ↓
                    (archived)    (new rule_id with supersedes link)
```

## Drift Detection

### What Gets Hashed

Each rule's hash is computed from:
- `statement` + `origin_type` + `rfc_refs` + `reasoning` + `disagreements`

The hash does NOT include `code_refs` or `test_refs` (those change with refactoring). Instead, drift detection watches for *misalignment* between the rule hash and the code/test behavior.

### Drift Types

| Drift Type | Detection Method | Severity |
|------------|-----------------|----------|
| **Logic drift** | Rule hash changed without `last_verified` update | Critical |
| **Code drift** | Code at `code_refs` changed (git diff) but rule hash unchanged | Warning — may be benign refactor |
| **Test drift** | Test at `test_refs` changed but rule hash unchanged | Warning — test may have been weakened |
| **Orphan rule** | Rule exists but no code_ref or test_ref points to it | Critical — unimplemented logic |
| **Orphan test** | Test exists but no rule claims it | Warning — test may be testing phantom logic |
| **Foundation drift** | RFC has been updated/superseded (e.g., DMARCbis) | Advisory — review needed |
| **Reasoning drift** | `disagreements` section changed without rule review | Critical — position may have shifted |

### CI Enforcement

```bash
# Phase 1: Registry integrity
golden-logic check          # all rules parse, hashes valid
golden-logic orphans        # no orphan rules, no orphan tests
golden-logic coverage       # every science-tagged file has ≥1 rule

# Phase 2: Drift detection
golden-logic drift          # compare hashes against last verified
golden-logic alignment      # code_refs still point to correct lines
golden-logic foundation     # check if cited RFCs have been updated
```

## Visual Representations

### TheBrain Integration

- **One thought per rule** (e.g., "LR-SPF-HARDFAIL-v1")
  - Parent: protocol thought (e.g., "SPF Protocol")
  - Jump links: RFC section thought, code file thought
  - Label: rule title + origin type badge
  - Notes: full rule definition
- **One thought per RFC section** (e.g., "RFC 7208 §4.6.2")
  - Children: all rules derived from this section
- **Category nodes**: "RFC Foundation", "DNS Tool Logic", "Disagreements"
- **Link types**: `derived_from` (rule → RFC), `implemented_by` (rule → code), `verified_by` (rule → test), `disputed_by` (rule → disagreement)

### Topology Integration

Add `mode=logic` to the topology page:
- **Zones**: RFC Foundation (bedrock layer), DNS Tool Logic (architecture layer), Code (implementation layer), Tests (proof layer), Disagreements (edge cases)
- **Nodes**: each logic rule, colored by origin type (gold = RFC-derived, blue = invented, green = hybrid)
- **Edges**: derivation chains, dependencies, conflicts
- **Drift indicators**: nodes with detected drift glow red; orphans pulse
- **Mathematical layout**: use the existing constrained layered-stress solver

### Mermaid/SVG Outputs

1. **Rule dependency graph** — which rules depend on which
2. **RFC coverage map** — RFC sections ↔ rules ↔ tests (heatmap: covered/uncovered)
3. **Disagreement map** — our positions vs. industry interpretations
4. **Drift timeline** — historical view of rule changes over time

## Registry Location

**Git is the source of truth.** Everything else is a projection.

```
docs/logic/
├── registry.yaml          # canonical rule definitions
├── schema.json            # JSON schema for validation
├── LOGIC.md               # human-readable logic overview
└── generated/
    ├── coverage-map.svg   # RFC coverage heatmap
    ├── dependency-graph.svg
    └── logic-graph.json   # topology solver input
```

**Sync pipeline**: `registry.yaml` → Notion database + TheBrain thoughts + topology JSON + Mermaid SVGs

**Why Git-first**: 
- Code is the authority. Logic rules live next to the code they govern.
- Git tracks history — every rule change has a commit hash.
- CI can enforce integrity checks.
- Notion and TheBrain are *views*, not sources.

## Intel Repo Integration

- Shared schema and ID namespace across public and intel repos
- Private intel repo has rules with `repo: intel` code_refs and test_refs
- Intel CI publishes a coverage artifact (rule IDs + pass/fail + hashes)
- Public CI ingests the summary only — no private code or logic leaks
- SonarCloud onboarding for intel repo: create project, add sonar-project.properties, mirror CI workflow

## Connection to Existing Systems

| System | How Golden Logic Connects |
|--------|--------------------------|
| EDE (Epistemic Disclosure Events) | EDEs document when we discover our logic was wrong — Golden Logic prevents it from happening silently |
| Confidence Bridge | Per-analysis confidence scores are computed by logic rules — Golden Logic verifies the rules themselves are sound |
| ICAE/ICuAE | Intelligence engines use calibrated logic — Golden Logic traces each calibration decision to its source |
| Scrutiny tags (science/design/plumbing) | Golden Logic rules map to science-tagged files — the scrutiny system tells you WHERE, Golden Logic tells you WHY |
| Golden fixtures | Fixtures are data snapshots — Golden Logic rules define what the code should DO with that data |
| Standing Gates | Quality gates verify the output — Golden Logic verifies the reasoning that produces the output |

## Phase Plan

### Phase 1: Registry + Schema (MVP)
- Define YAML schema for logic rules
- Seed 10-15 foundational rules (SPF, DMARC, DKIM core logic)
- Build `golden-logic check` CLI validator
- Add `golden-logic orphans` for test-rule alignment
- Compute SHA-3-512 hashes per rule

### Phase 2: Drift Detection
- Build `golden-logic drift` comparator
- Integrate with CI pipeline
- Add `golden-logic alignment` for code_ref validation
- Hash history tracking (rule_hash over time)

### Phase 3: Visual Layer
- TheBrain sync (rules → thoughts, RFC refs → thoughts)
- Topology `mode=logic` with constrained layout solver
- Mermaid SVG generation for coverage and dependency maps
- Notion database sync (structured view of all rules)

### Phase 4: Intel Integration
- Cross-repo rule namespace
- Intel CI coverage artifact
- SonarCloud for intel repo
- Combined coverage report (public + intel)

### Phase 5: Foundation Monitoring
- RFC update detection (IETF datatracker API)
- DMARCbis tracking
- Automatic "foundation drift" advisories
- Historical reasoning timeline

## Naming and Brand

**Golden Logic** — because:
- Gold is the color of verified truth in the DNS Tool palette (Emblem Gold #d4a853)
- Logic is the living thing — fluid but bounded, traceable, connected
- "Golden" parallels golden fixtures (data truth) and golden rules (boundary truth)
- The visual representation uses gold nodes for RFC-derived logic, reinforcing the connection

In the UI, the Golden Logic topology view should be visually striking — gold nodes on dark background, connection lines that pulse with verification status, drift indicators that glow when misalignment is detected. Real, live, connected, dynamic, logic, error-corrected, confidence-driven truth.

## The Larger Claim

Golden Logic is, to the best of our research, the first system that mathematically tracks logic drift — not data drift, not schema drift, not configuration drift, but the *reasoning itself*. It extends a lineage from Aristotle through Gödel to modern formal methods by adding temporal drift detection to logical verification.

This matters because the fundamental problem between humans and computers is not bad data or bad code. It's bad logic — flawed reasoning that gets encoded faithfully and executed perfectly, producing wrong answers that nobody catches because they're only watching the output.

Come home to the data. But first, check your logic.
