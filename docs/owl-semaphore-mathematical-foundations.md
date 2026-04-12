# The Owl Semaphore: Mathematical and Philosophical Foundations

> **SUPERSEDED** — This document is an agent-generated exploratory draft. The authoritative Owl Semaphore specifications are the five documents published from the [owl-semaphore](https://github.com/IT-Help-San-Diego/owl-semaphore) repository (DOI: [10.5281/zenodo.19473697](https://doi.org/10.5281/zenodo.19473697)). This file is retained for reference only and is not served or linked from any page.

**Carey James Balboa**
ORCID: [0009-0000-5237-9065](https://orcid.org/0009-0000-5237-9065)
DOI: [10.5281/zenodo.19473697](https://doi.org/10.5281/zenodo.19473697)
Project: [dnstool.it-help.tech](https://dnstool.it-help.tech)
Source: [github.com/IT-Help-San-Diego/dns-tool-intel](https://github.com/IT-Help-San-Diego/dns-tool-intel)

*Non-normative research artifact. This document explores the mathematical structure of the Owl Semaphore system in depth, examines whether the current three-state model is algebraically complete under O(2), and investigates whether a fourth owl is required to close the group. It is a companion to the Owl Semaphore specification (Balboa, 2026) and is intended to support further research into visual epistemic notation.*

---

## 1. The Problem Statement

The Owl Semaphore encodes epistemic state — the relationship between a claim and the evidence supporting it — using geometric transforms from the orthogonal group O(2) of the Euclidean plane. Three states are currently defined:

| State | Transform | Matrix | det | Mapping |
|-------|-----------|--------|-----|---------|
| **NORMATIVE** | Identity I | [[1,0],[0,1]] | +1 | (x, y) → (x, y) |
| **NON-NORMATIVE** | Vertical reflection σ_v | [[-1,0],[0,1]] | −1 | (x, y) → (−x, y) |
| **CRITICAL** | 180° rotation C₂ | [[-1,0],[0,-1]] | +1 | (x, y) → (−x, −y) |

The question this document investigates:

> **Is the three-element set {I, σ_v, C₂} algebraically closed under composition in O(2)? If not, what is missing, and does the missing element correspond to a real epistemic state?**

This is not an aesthetic question. If the semaphore claims to be grounded in O(2), and the selected transforms do not form a closed algebraic structure under composition, then either (a) the mathematical claim must be weakened, (b) a fourth state must be added, or (c) a rigorous argument must be made for why closure is not required. All three paths are explored below.

---

## 2. The Orthogonal Group O(2)

### 2.1 Definition

The orthogonal group O(2) is the group of all 2×2 real matrices M satisfying:

```
M^T · M = I    (orthogonality condition)
```

where M^T is the transpose and I is the 2×2 identity matrix. Equivalently, O(2) is the group of all distance-preserving linear transformations of the Euclidean plane R².

Every element of O(2) is either:
- A **rotation** R(θ) by angle θ, with det = +1 (these form the special orthogonal group SO(2)), or
- A **reflection** σ(θ) across a line through the origin at angle θ/2, with det = −1

### 2.2 Key Elements

The specific elements used by the Owl Semaphore are drawn from the finite subgroups of O(2):

```
I = R(0°)     = [[1, 0], [0, 1]]       Identity (0° rotation)
C₂ = R(180°)  = [[-1, 0], [0, -1]]     Half-turn rotation
σ_v           = [[-1, 0], [0, 1]]       Vertical reflection (mirror across y-axis)
σ_h           = [[1, 0], [0, -1]]       Horizontal reflection (mirror across x-axis)
```

### 2.3 The Multiplication Table

The composition of any two elements in {I, C₂, σ_v, σ_h} produces another element in the same set:

```
        I       C₂      σ_v     σ_h
  I  |  I       C₂      σ_v     σ_h
  C₂ |  C₂      I       σ_h     σ_v
  σ_v|  σ_v     σ_h      I      C₂
  σ_h|  σ_h     σ_v     C₂       I
```

This is the **Klein four-group** V₄ ≅ Z₂ × Z₂. Every element is its own inverse. The group is abelian (commutative).

### 2.4 The Closure Problem

The current semaphore uses three elements: {I, σ_v, C₂}. This set is **not closed** under composition:

```
σ_v ∘ C₂ = σ_h    (horizontal reflection)
C₂ ∘ σ_v = σ_h    (same result — the group is abelian)
```

The composition of two semaphore states produces a transform (σ_h) that has no corresponding owl. The system leaks. It references O(2) but does not form a subgroup of O(2).

For {I, σ_v, C₂} to be a group, it would need to be closed: every pairwise composition must land back in the set. Since σ_v ∘ C₂ = σ_h ∉ {I, σ_v, C₂}, the set fails the closure axiom.

**This is the mathematical gap the Owl Semaphore must confront.**

---

## 3. The Missing Fourth Transform: σ_h

### 3.1 What σ_h Does Geometrically

The horizontal reflection σ_h maps (x, y) → (x, −y). It mirrors across the x-axis. The owl would be flipped upside-down (vertical inversion) while preserving left-right orientation:

```
σ_h = [[1, 0], [0, -1]]
det(σ_h) = −1     (improper — orientation-reversing)
```

Visually: the owl is inverted top-to-bottom but NOT left-to-right. Compare:
- σ_v (Non-Normative): left-right mirror, owl faces the other way
- C₂ (Critical): both axes inverted, owl is upside-down AND reversed
- σ_h (???): owl is upside-down but still faces the original direction

### 3.2 The Relationship Between All Four Elements

The four elements have a clean algebraic structure:

```
I   = identity                    det = +1   (proper)
C₂  = σ_v ∘ σ_h = σ_h ∘ σ_v     det = +1   (proper — product of two reflections)
σ_v = C₂ ∘ σ_h                   det = −1   (improper)
σ_h = C₂ ∘ σ_v                   det = −1   (improper)
```

The 180° rotation C₂ is the *composition* of both reflections. This is a fundamental result in group theory: every proper rotation can be decomposed into two reflections, and every improper transformation (det = −1) is a single reflection.

### 3.3 Algebraic Consequences of Omitting σ_h

Without σ_h, the following algebraic operations are undefined in the semaphore:

1. **Composing Non-Normative with Critical**: If a Non-Normative finding is subjected to Critical re-evaluation, the result is σ_v ∘ C₂ = σ_h — a state with no notation.

2. **Decomposing Critical**: The Critical state C₂ = σ_v ∘ σ_h is the product of Non-Normative and the missing fourth. Without σ_h, the Critical state cannot be algebraically decomposed within the system.

3. **Inverse structure**: In V₄, every element is its own inverse. The three-element set inherits this property for each individual element but lacks the structural completeness that makes the inverse law meaningful across compositions.

---

## 4. Does Epistemology Need Four States?

### 4.1 The Three-State Argument

The current three-state model is grounded in a mapping to established epistemic categories:

| State | Epistemic Category | RFC 2119 | Psychological Analog |
|-------|-------------------|----------|---------------------|
| NORMATIVE (I) | Verified knowledge | MUST / SHALL | Ego-syntonic certainty |
| NON-NORMATIVE (σ_v) | Exploratory knowledge | NOTE / Informative | Metacognition — thinking about thinking |
| CRITICAL (C₂) | Inverted knowledge | MUST NOT / SHALL NOT | Ego-dystonic insight — your proof turns on you |

These three states map cleanly to how knowledge is *classified* in standards bodies (RFC, ISO, W3C), in scientific publishing (verified / exploratory / retracted), and in cybersecurity (compliant / advisory / vulnerability). The argument for sufficiency: these categories cover the full epistemic space that practitioners encounter.

### 4.2 The Case for a Fourth State: σ_h

If σ_h exists as a geometric transform, and if the semaphore claims mathematical grounding in O(2), then the question becomes: *is there a real epistemic state that σ_h corresponds to?*

Consider what σ_h does algebraically:
- det = −1 (orientation-reversing, like Non-Normative)
- But the inversion is vertical, not horizontal
- The owl is upside-down but still faces the original direction

Candidates for a fourth epistemic state:

#### 4.2.1 Candidate: DEPRECATED / SUPERSEDED

Knowledge that was once Normative but has been replaced by newer Normative knowledge. Not wrong (that would be Critical), not exploratory (that would be Non-Normative), but *no longer the standard while remaining historically valid*.

**Example**: Newtonian mechanics after general relativity. Newton's laws are not wrong — they are superseded. They remain valid within their domain of applicability but are no longer the authoritative framework.

**Epistemic character**: The vertical axis (authority) is inverted — the claim has lost its standing — but the horizontal axis (correctness within scope) is preserved. This is (x, y) → (x, −y): the content is unchanged, but the authority is flipped.

**Standards mapping**: RFC "OBSOLETED BY" status. A deprecated API. A paper that has been superseded by a correction that does not constitute a retraction.

#### 4.2.2 Candidate: PROVISIONAL / UNDER REVIEW

Knowledge that is in the process of being verified — neither exploratory (Non-Normative) nor confirmed (Normative), but actively under evaluation. A pre-print. A patch awaiting review. A finding in the verification pipeline.

**Epistemic character**: The content faces forward (horizontal axis preserved) but the vertical axis — the claim's relationship to established ground — is inverted. The claim is suspended, hanging in evaluation space.

#### 4.2.3 Candidate: ARCHIVED / HISTORICAL

Knowledge preserved for the record but no longer active. Not deprecated (still valid in context), not critical (not dangerous), not exploratory (exploration is finished). Simply *completed and filed*.

**Epistemic character**: The temporal axis is inverted — the claim has moved from present to past — while the content axis remains unchanged.

### 4.3 The Composition Test

If σ_h represents DEPRECATED / SUPERSEDED, then the composition table gains epistemic meaning:

```
σ_v ∘ C₂ = σ_h:
    "Reflecting on a Critical finding produces Deprecated knowledge."
    Translation: When you explore (Non-Normative) a finding that has inverted
    the standard (Critical), the result is knowledge that retains its content
    but has lost its authority — it becomes historical, superseded.

C₂ ∘ σ_v = σ_h:
    "A Critical inversion of exploratory work produces Deprecated knowledge."
    Translation: When a Critical finding strikes Non-Normative work,
    the exploration is terminated — not because it was wrong,
    but because the ground it was exploring has been invalidated.

σ_h ∘ σ_v = C₂:
    "Deprecating exploratory work produces a Critical state."
    Translation: When Non-Normative work is superseded (not by better work,
    but by the removal of its foundation), the result is Critical —
    the entire line of inquiry has been inverted.

σ_h ∘ C₂ = σ_v:
    "Deprecating a Critical finding produces Non-Normative knowledge."
    Translation: When a Critical finding is itself superseded — when the
    danger it revealed is resolved — it returns to Non-Normative status:
    historically interesting, no longer binding, worth reflecting on.
```

Every composition produces a meaningful epistemic transition. The algebra aligns with how knowledge actually evolves.

---

## 5. The Deep Structure: Why V₄ Is Not Arbitrary

### 5.1 V₄ in Mathematics

The Klein four-group V₄ = {I, a, b, ab} where a² = b² = (ab)² = I is one of the most fundamental structures in abstract algebra. It appears across mathematics:

- **Symmetries of a rectangle**: The rectangle (non-square) has exactly four symmetries: identity, 180° rotation, horizontal reflection, vertical reflection. This is V₄.
- **Galois theory**: V₄ is the Galois group of the biquadratic polynomial x⁴ − 1 over Q.
- **Boolean logic**: V₄ is isomorphic to Z₂ × Z₂, which is the group structure underlying two independent binary choices.
- **Topology**: V₄ governs the orientability classification of 2-manifolds.

### 5.2 V₄ in Epistemology

The two independent binary choices that generate V₄ can be mapped to two fundamental epistemic axes:

```
Axis 1 (horizontal — content correctness):
    +1 = content is correct within its scope
    −1 = content is incorrect or inverted

Axis 2 (vertical — authority/currency):
    +1 = currently authoritative
    −1 = no longer authoritative (superseded, deprecated, historical)
```

The four combinations:

| Content | Authority | Transform | det | State |
|---------|-----------|-----------|-----|-------|
| correct (+1) | current (+1) | I | +1 | NORMATIVE |
| incorrect (−1) | current (+1) | σ_v | −1 | NON-NORMATIVE (exploring, not yet confirmed) |
| incorrect (−1) | not current (−1) | C₂ | +1 | CRITICAL (your proof has turned on you) |
| correct (+1) | not current (−1) | σ_h | −1 | DEPRECATED (was correct, no longer the standard) |

This is a reinterpretation. In the original semaphore, "Non-Normative" is not "incorrect" — it is "exploratory, not yet verified." The σ_v reflection reverses the *horizontal axis of established truth*, which means the content has been laterally displaced from the standard. The content is not wrong — it is *reflected*, seen from a different angle, under examination.

Similarly, "Deprecated" (σ_h) does not mean the content is wrong — it means the *vertical axis of authority* has been inverted. The content stands, but the ground it stood on has moved.

### 5.3 The Two Generators

V₄ is generated by any two of its three non-identity elements:

```
⟨σ_v, σ_h⟩ = V₄     (two reflections generate the full group)
⟨σ_v, C₂⟩  = V₄     (one reflection + rotation generate the full group)
⟨σ_h, C₂⟩  = V₄     (the other reflection + rotation generate the full group)
```

The current semaphore uses {σ_v, C₂} as its generating set. Since these two elements generate all of V₄, the fourth element σ_h is *already implied* by the system's own generators — it exists whether or not we name it.

---

## 6. Can Three Owls Close the O(2) Loop?

### 6.1 The Short Answer

No. Three elements cannot form a closed subgroup of V₄ (unless one of them is the identity and the other two form a Z₂ subgroup). The only subgroups of V₄ are:

```
{I}                          — trivial (1 element)
{I, C₂}    ≅ Z₂             — rotational subgroup
{I, σ_v}   ≅ Z₂             — vertical reflection subgroup
{I, σ_h}   ≅ Z₂             — horizontal reflection subgroup
{I, C₂, σ_v, σ_h} = V₄     — the full group (4 elements)
```

There is no 3-element subgroup. The number 3 does not divide |V₄| = 4, so by Lagrange's theorem, no subgroup of order 3 can exist. The three-element set {I, σ_v, C₂} is not a group.

### 6.2 The Longer Answer: What "Closing the Loop" Means

"Closing the loop" means achieving algebraic closure: every composition of semaphore operations produces a result that is itself a semaphore operation. With three states:

```
NORMATIVE ∘ anything = that thing          (I is the identity — always works)
NON-NORMATIVE ∘ NON-NORMATIVE = NORMATIVE  (σ_v² = I — reflecting twice returns to standard)
CRITICAL ∘ CRITICAL = NORMATIVE            (C₂² = I — inverting twice returns to standard)
NON-NORMATIVE ∘ CRITICAL = ???             (σ_v ∘ C₂ = σ_h — undefined in three-state system)
```

The first three compositions are well-defined. The fourth leaks. Three owls cannot close the loop.

### 6.3 What About Larger Groups?

Could we use a different subgroup of O(2) — say, the cyclic group Z₃ with three elements {I, R(120°), R(240°)}?

This would give three states with closure, but at a cost:
- The rotations R(120°) and R(240°) have det = +1 — they are both proper rotations
- There would be no reflections (det = −1) in the system
- The fundamental epistemic distinction between "shifted perspective" (rotation, det = +1) and "reversed orientation" (reflection, det = −1) would be lost

The determinant carries genuine semantic weight in the semaphore: det = +1 means the fundamental orientation of inquiry is preserved (you may have moved, but you're still facing the same way); det = −1 means orientation is reversed (the ground has shifted under you). Abandoning this distinction to achieve three-element closure would be a mathematical gain at a philosophical loss.

### 6.4 The Z₃ Alternative in Detail

The cyclic group C₃ = {I, R(120°), R(240°)} with rotation matrices:

```
I       = [[1, 0], [0, 1]]
R(120°) = [[-1/2, -√3/2], [√3/2, -1/2]]
R(240°) = [[-1/2, √3/2], [-√3/2, -1/2]]
```

Properties:
- All elements have det = +1
- R(120°) ∘ R(120°) = R(240°) — closed
- R(240°) ∘ R(120°) = I — closed
- R(120°) ∘ R(240°) = I — closed

This is algebraically clean. But the semantic mapping fails:
- R(120°): a 120° shift in perspective — rotated but not reflected
- R(240°): a 240° shift — further rotated, still not reflected
- No element captures the *reversal* of orientation that defines Critical and Non-Normative findings

The 120° rotation doesn't correspond to any natural epistemic transition. "Your perspective has shifted by exactly one-third of a full rotation" is not a concept that maps to RFC compliance, scientific peer review, or cybersecurity disclosure.

**Conclusion: Z₃ achieves closure but loses semantic fidelity. The determinant distinction matters.**

---

## 7. Can Four Owls Close the O(2) Loop?

### 7.1 Yes — Trivially

Four elements {I, C₂, σ_v, σ_h} form V₄, which is a subgroup of O(2). Every composition is defined. Every element has an inverse (itself). The system is algebraically closed, associative, and has an identity. All four group axioms are satisfied.

### 7.2 What This Means for the Semaphore

Adding σ_h as a fourth state would give the Owl Semaphore the mathematical rigor to claim it operates within O(2) as a genuine subgroup. The four-state system would be:

| State | Transform | det | Visual | Epistemic Meaning |
|-------|-----------|-----|--------|-------------------|
| NORMATIVE | I | +1 | Owl upright, facing right | This is the standard |
| NON-NORMATIVE | σ_v | −1 | Owl reflected left-right | This reflects the standard |
| CRITICAL | C₂ | +1 | Owl rotated 180° | This inverts the standard |
| DEPRECATED | σ_h | −1 | Owl flipped top-bottom | This was the standard |

### 7.3 The Color Problem

The current three-state system uses three colors with deep historical and psychological grounding:

- **Gold** (#d4a853): Authority, verified truth, the Athenian tetradrachm
- **Verdigris/Teal** (#316964): Patina, reflection, aged copper, the color of thinking
- **Crimson** (#990f1e): Danger, blood, the inversion of safety

A fourth state needs a fourth color. Candidates:

| Color | Hex | Rationale | Risk |
|-------|-----|-----------|------|
| **Slate/Pewter** | #708090 | Neutrality, archival, aged metal | Too close to default UI gray — may lack distinction |
| **Amber** | #D4A017 | Caution, aging, sunset — not gold, not red | Too close to Gold (Normative) — chromatic confusion |
| **Indigo** | #4B0082 | Depth, history, twilight | No historical precedent in the Athenian iconography |
| **Bronze** | #CD7F32 | Aged metal, historical durability, third-age | Patinated bronze is verdigris — recursive reference to Non-Normative |
| **Sepia** | #704214 | Archival photography, historical documents | Strong association with "old" — aligns with Deprecated semantics |

### 7.4 The Contrast Requirement

The semaphore's triple-redundant encoding (color + orientation + label) means the fourth state must be distinguishable from all three existing states across:

1. **Full color**: All four colors must be discriminable on both dark and light backgrounds
2. **Deuteranopia** (red-green color blindness): Gold, teal, and crimson are already carefully chosen to survive deuteranopic perception. The fourth color must also survive.
3. **Monochrome/grayscale**: The four lightness values must be sufficiently distinct
4. **Small render sizes**: At 16×16px (favicon, tag icon), orientation becomes ambiguous. Color must carry the full signal alone at small sizes.

Current grayscale lightness values (relative luminance L):
- Gold #d4a853: L ≈ 0.36
- Teal #316964: L ≈ 0.08
- Crimson #990f1e: L ≈ 0.04

Sepia #704214 has L ≈ 0.07 — too close to teal and crimson in grayscale. Slate #708090 has L ≈ 0.20 — good separation. Indigo #4B0082 has L ≈ 0.03 — too dark, collapses with crimson.

---

## 8. The Philosophical Case: Three vs. Four

### 8.1 Aristotle's Categories

Aristotle's square of opposition from *De Interpretatione* maps four logical relationships:

```
    UNIVERSAL AFFIRMATIVE (A)  ←→  UNIVERSAL NEGATIVE (E)
              ↕                              ↕
    PARTICULAR AFFIRMATIVE (I) ←→  PARTICULAR NEGATIVE (O)
```

The four positions:
- A: "All S are P" — NORMATIVE (this IS the standard, universally)
- E: "No S are P" — CRITICAL (this is NOT the standard, universally)
- I: "Some S are P" — NON-NORMATIVE (this REFLECTS the standard, partially)
- O: "Some S are not P" — ??? (this WAS the standard, partially)

The "O" position — particular negative — is the Deprecated state. "Some of what was claimed is no longer the case." Not a universal inversion (Critical), not a partial exploration (Non-Normative), but a partial withdrawal of authority.

The square of opposition has the same algebraic structure as V₄. This is not a coincidence — both structures encode two independent binary axes (universal/particular, affirmative/negative).

### 8.2 The Hegelian Dialectic

Hegel's dialectic proposes three stages: Thesis, Antithesis, Synthesis. This maps naturally to a three-state system:

- Thesis → NORMATIVE (the standard)
- Antithesis → CRITICAL (the inversion)
- Synthesis → NON-NORMATIVE (the reflection — incorporating both)

But Hegel's own system was not static. The synthesis becomes the new thesis, which generates its own antithesis. The dialectic is a *process*, not a fixed taxonomy. What happens to the old thesis once the synthesis supersedes it?

It becomes DEPRECATED. The Aufhebung (sublation) preserves the content while negating the authority. This is precisely σ_h: (x, y) → (x, −y) — the content survives, the standing is inverted.

### 8.3 Kuhn's Paradigm Shifts

Thomas Kuhn's *The Structure of Scientific Revolutions* (1962) describes the lifecycle of scientific knowledge:

1. **Normal science**: Working within an accepted paradigm → NORMATIVE
2. **Anomaly accumulation**: Observations that don't fit → NON-NORMATIVE
3. **Crisis**: The anomalies become undeniable → CRITICAL
4. **Paradigm shift**: The old paradigm is replaced → The old paradigm becomes DEPRECATED

Kuhn explicitly describes the fourth state: the old paradigm is not "wrong" in an absolute sense — it is *superseded*. Newtonian mechanics did not become incorrect when Einstein published general relativity. It became *deprecated*: valid within its domain, no longer the authoritative framework.

### 8.4 The Psychiatric Parallel

The three-state psychiatric mapping in the current semaphore:

- NORMATIVE → Ego-syntonic certainty (your beliefs align with evidence)
- NON-NORMATIVE → Metacognition (thinking about your thinking)
- CRITICAL → Ego-dystonic insight (your evidence turns on your beliefs)

A fourth state extends this:

- DEPRECATED → **Grief / acceptance** (what you once knew to be true is no longer the standard — not because it was wrong, but because the world moved on)

This is Kübler-Ross's acceptance stage. It is also the resolution of cognitive dissonance when the dissonance is resolved not by rejecting the new information (denial) but by releasing the old framework (acceptance). The content of the old belief is preserved — "I understand why I thought that, and it was reasonable given what I knew" — but its authority is relinquished.

---

## 9. The O(2) Continuous Structure

### 9.1 Beyond Finite Subgroups

V₄ is a *finite* subgroup of O(2). The full group O(2) is continuous — it contains rotations by every angle θ ∈ [0, 2π) and reflections across every axis. The semaphore samples four discrete points from this continuum.

The continuous structure raises a question: are there epistemic states between the four discrete positions?

### 9.2 Intermediate Rotations

Consider R(θ) for 0 < θ < 180°:

```
R(30°):  A slight shift in perspective — questioning has begun but the standard mostly holds
R(45°):  Moderate shift — growing uncertainty, the data is ambiguous
R(90°):  Orthogonal — the claim is at right angles to the evidence, maximum uncertainty
R(135°): Strong shift — the evidence is mostly against the claim
R(180°): Full inversion — CRITICAL
```

The continuous rotation from I (0°) to C₂ (180°) traces the path from certainty to crisis. This is the *confidence gradient* — and it maps directly to DNS Tool's confidence scoring engine (ICAE). A confidence score of 1.0 is the identity (full certainty, Normative). A score approaching 0.0 is the half-turn (the evidence contradicts the claim). The continuous rotation from Normative to Critical *is* the confidence interval.

### 9.3 The Confidence Score as a Rotation Angle

If we define θ = π(1 − c) where c is the confidence score on [0, 1]:

```
c = 1.0  →  θ = 0°    →  R(0°) = I        →  NORMATIVE
c = 0.75 →  θ = 45°   →  R(45°)            →  High confidence, some uncertainty
c = 0.5  →  θ = 90°   →  R(90°)            →  Maximum uncertainty — orthogonal
c = 0.25 →  θ = 135°  →  R(135°)           →  Low confidence, evidence mostly contradicts
c = 0.0  →  θ = 180°  →  R(180°) = C₂      →  CRITICAL
```

This gives the Owl Semaphore a continuous backbone: the discrete states are landmarks on a continuous confidence manifold. The four states (with σ_h added) become the vertices of the manifold's discrete skeleton:

```
                  NORMATIVE (I, c=1.0)
                     ↑  θ=0°
                     |
    DEPRECATED ←—————+—————→ NON-NORMATIVE
    (σ_h, det=-1)    |        (σ_v, det=-1)
                     |
                     ↓  θ=180°
                  CRITICAL (C₂, c=0.0)
```

The vertical axis is the rotation angle (confidence). The horizontal axis is the reflection (orientation reversal). The four states sit at the four cardinal points.

### 9.4 The Fiber Bundle Interpretation

For readers familiar with differential geometry: the Owl Semaphore can be interpreted as a fiber bundle over the confidence interval [0, 1]:

- **Base space**: [0, 1] — the confidence score
- **Fiber**: Z₂ = {+1, −1} — the orientation (proper or reflected)
- **Total space**: [0, 1] × Z₂ — the full state space

Each point in the total space is a pair (confidence, orientation):

```
(1.0, +1) = NORMATIVE       (verified, proper orientation)
(1.0, −1) = DEPRECATED      (verified content, reversed authority)
(0.0, +1) = CRITICAL        (inverted, proper orientation of the inversion)
(0.0, −1) = NON-NORMATIVE   (inverted and reflected — exploratory)
```

The fiber bundle is trivial (it is a product space), but the triviality is itself informative: it means the confidence axis and the orientation axis are genuinely independent. You can have high-confidence Non-Normative work (well-supported exploration that hasn't been adopted as standard) and low-confidence Normative claims (claims that are technically the standard but poorly supported — a dangerous state that the semaphore can flag).

---

## 10. The Three-Owl Defense: Why Incompleteness May Be a Feature

### 10.1 The Pragmatic Argument

Three states are cognitively manageable. Traffic lights use three states. RFC 2119 keywords cluster into three groups (MUST / SHOULD / MAY). The US military threat advisory system was redesigned from five levels to three actionable categories. Adding a fourth state increases cognitive load and may reduce adoption.

### 10.2 The Semiotic Argument

The semaphore is a semiotic system — it communicates meaning through signs. Semiotic systems do not need algebraic closure to function. Natural language is not algebraically closed (composing two nouns does not always produce a noun), yet it communicates effectively. Musical notation uses three primary durations (whole, half, quarter) without requiring mathematical closure of the duration group.

### 10.3 The "Implied Fourth" Argument

Since V₄ is generated by any two non-identity elements, and the semaphore already uses σ_v and C₂, the fourth element σ_h is *mathematically implied*. One could argue that the system is complete by generation even if it is not complete by enumeration. The fourth state exists in the algebra — it simply has not been given a visual form.

This is analogous to the quaternion system in physics: the three imaginary units i, j, k are explicitly named, but their compositions (ij = k, jk = i, ki = j) are derived rather than independently defined. The derived elements are not "missing" — they are structurally present.

### 10.4 The Danger of Forced Completion

Adding a fourth state solely to satisfy algebraic closure risks creating a state that doesn't correspond to genuine epistemic experience. If "Deprecated" is forced into the system for mathematical reasons rather than empirical ones, it may:

- Create false precision (four categories where three suffice)
- Introduce classification ambiguity (is this Deprecated or Non-Normative?)
- Dilute the visual impact of the three strong states

---

## 11. Resolution: The Recommended Path Forward

### 11.1 Three States for Practice, Four for Theory

The Owl Semaphore should maintain three visual states for practical use while acknowledging the four-element algebraic structure in its theoretical documentation:

- The three visual owls (Normative, Non-Normative, Critical) cover the epistemic states that practitioners encounter and need to communicate
- The mathematical foundation explicitly references V₄ and acknowledges σ_h as the algebraically implied fourth element
- The fourth state is held in reserve: if empirical use of the semaphore reveals a genuine need for a "Deprecated / Superseded" category, the mathematical structure is already prepared to accommodate it

### 11.2 Notation for the Fourth State

Even without a visual owl, the fourth state can be notated in text:

```
T = σ_h    det = −1    (x, y) → (x, −y)    "This was the standard."
```

If and when a visual form is needed:
- **Orientation**: Owl inverted vertically (upside-down, still facing right)
- **Color**: Sepia or slate (to be determined by contrast analysis)
- **Label**: DEPRECATED or SUPERSEDED

### 11.3 The Mathematical Claim — Corrected

The Owl Semaphore page currently states that it uses "three mathematical transforms from the orthogonal group O(2)." This should be revised to:

> "The Owl Semaphore selects three of the four generators of the Klein four-group V₄ ⊂ O(2). The three visual states — Normative (I), Non-Normative (σ_v), and Critical (C₂) — span the epistemic space of active knowledge work. The fourth element (σ_h, horizontal reflection) is algebraically implied by the composition σ_v ∘ C₂ and corresponds to the epistemic state of superseded knowledge. It is structurally present in the system's algebra but is not visually instantiated in the current specification."

### 11.4 The Continuous Extension

The connection between O(2)'s continuous rotation group and the confidence scoring engine (Section 9) should be developed further. The rotation angle θ = π(1 − c) maps the confidence score directly to a rotation within SO(2), giving the semaphore a continuous backbone that connects to DNS Tool's quantitative confidence model (ICAE). This bridge between discrete epistemic categories and continuous confidence measurement is, to the author's knowledge, novel.

---

## 12. Open Questions for Further Research

1. **Empirical validation**: Do practitioners working with the three-state semaphore encounter situations where a fourth "Deprecated / Superseded" state would improve classification accuracy? This can be tested by tracking unclassifiable findings in operational use.

2. **The confidence-rotation mapping**: Is θ = π(1 − c) the correct mapping, or should the rotation angle scale non-linearly with confidence? In particular, should low-confidence states (c < 0.3) map to faster angular change, reflecting the psychological experience that uncertainty accelerates as confidence collapses?

3. **Higher-dimensional extensions**: O(3) — the orthogonal group of 3D space — has richer structure (proper rotations SO(3), improper rotations, reflections through planes). Does the addition of a third axis (e.g., temporal currency, scope of applicability, or evidentiary depth) produce an O(3) semaphore with genuinely useful additional states? The octahedral group O_h ⊂ O(3) has 48 elements — clearly too many for visual notation — but smaller subgroups like the tetrahedral group T_d (24 elements) or D₃ (6 elements) might offer tractable extensions.

4. **The Brier score connection**: DNS Tool's confidence calibration uses Brier scores. The Brier score B = (1/N) Σ(f_i − o_i)² measures the mean squared error between forecast probabilities and observed outcomes. Is there a natural group-theoretic interpretation of the Brier score in terms of the O(2) rotation? Specifically: does a well-calibrated system (B → 0) correspond to a system whose epistemic states cluster near the identity and whose angular excursions from I are well-predicted?

5. **The temporal evolution operator**: If a finding's epistemic state evolves over time (Normative → Non-Normative → Critical → Deprecated), this evolution can be modeled as a sequence of group operations. Is there a natural "time evolution operator" U(t) ∈ O(2) that describes how epistemic states decay, and does this operator connect to the posture drift detection engine already implemented in DNS Tool?

6. **Cross-disciplinary validation**: The claim that V₄'s algebraic structure maps to genuine epistemic categories requires validation beyond DNS security. Testing domains: medical diagnosis (confirmed / differential / contraindicated / superseded), legal precedent (binding / persuasive / overruled / distinguished), intelligence analysis (confirmed / assessed / disconfirmed / stale).

---

## 13. Summary

The Owl Semaphore is grounded in the orthogonal group O(2), but its three visual states {I, σ_v, C₂} do not form a closed subgroup. The smallest closed subgroup containing these three elements is the Klein four-group V₄ = {I, σ_v, C₂, σ_h}, which requires a fourth element: the horizontal reflection σ_h, mapping (x, y) → (x, −y).

Three owls cannot close the O(2) loop. Four owls can. The question is whether the fourth element corresponds to a genuine epistemic state that practitioners need. The candidate — DEPRECATED / SUPERSEDED — maps to well-established concepts across philosophy (Hegelian Aufhebung), science (Kuhnian paradigm shifts), psychology (Kübler-Ross acceptance), and standards bodies (RFC OBSOLETED BY status).

The recommended resolution: maintain three visual states for practical use while explicitly acknowledging the four-element algebraic structure in the system's mathematical documentation. Hold the fourth state in reserve. If operational use reveals a genuine need, the algebra is ready.

The deeper insight: the connection between O(2)'s continuous rotation group and the confidence scoring engine opens a path toward a unified framework where discrete epistemic categories and continuous confidence measurement are different views of the same underlying geometric structure. The Owl Semaphore may be, in mathematical terms, a *discretization* of an inherently continuous confidence manifold — and the choice of discretization (three states vs. four) is ultimately an empirical question about how human beings process and communicate uncertainty.

---

*"The owl stands where the math says it should. If the math says there should be four, then we owe it to the math — and to the owl — to find out what the fourth one means."*

— Carey James Balboa

---

**References**

- Aristotle. *De Interpretatione* (c. 350 BCE). The square of opposition.
- Aristotle. *Rhetoric* (c. 350 BCE). Book I, Chapters 2–3.
- Aristotle. *Nicomachean Ethics*. Book VI. (Phronesis, techne.)
- Armstrong, M. A. (1988). *Groups and Symmetry*. Springer. (V₄, O(2), finite subgroups.)
- Brier, G. W. (1950). "Verification of forecasts expressed in terms of probability." *Monthly Weather Review*, 78(1).
- Hegel, G. W. F. (1807). *Phenomenology of Spirit*. (Aufhebung, dialectical sublation.)
- Kübler-Ross, E. (1969). *On Death and Dying*. Macmillan. (Five stages of grief.)
- Kuhn, T. S. (1962). *The Structure of Scientific Revolutions*. University of Chicago Press.
- Serre, J.-P. (1977). *Linear Representations of Finite Groups*. Springer. (Representation theory of V₄.)
- Vlastos, G. (1983). "The Socratic Elenchus." *Oxford Studies in Ancient Philosophy*, 1, 27–58.
- Balboa, C. J. (2026). "The Owl Semaphore: Three States of Knowledge." DOI: 10.5281/zenodo.19468134.
- Balboa, C. J. (2026). "Confidence-Scored Analysis of Domain Security Infrastructure." DOI: 10.5281/zenodo.19468134.
- Balboa, C. J. (2026). "Philosophical Foundations for Security Analysis Communication." DOI: 10.5281/zenodo.19468134.

---

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
License: BUSL-1.1
