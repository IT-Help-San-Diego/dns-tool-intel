# Replit Agent Instructions for PR #98

You are working on DNS Tool PR #98 from the `Replit-Agent` branch. The PR contains a standalone diagnostic script named `confidence_gap_lab.py`.

## Goal

Use `confidence_gap_lab.py` to validate the DNS Tool ICAE confidence calibration issue shown on:

https://dnstool.it-help.tech/confidence

The specific question is why the reliability diagram has a gap in the `80-90%` confidence bin, and whether an evidence-first fix can move the current `good` and `adequate` calibration ratings to `excellent` without simply relabeling thresholds.

## What to Run

Run the script exactly as a standalone file:

```bash
python3 confidence_gap_lab.py
```

It should require no network access and no third-party Python packages.

## Expected Baseline Output

Confirm the script reproduces the live confidence-page numbers:

- `129` golden test cases
- `5` resolver scenarios
- `645` total predictions
- Brier score: `0.0018`, rating `excellent`
- Expected Calibration Error: `0.0310`, rating `good`
- Reliability bins:
  - `80-90%`: `14` predictions, `88.0%` predicted, `100.0%` observed, gap `0.1200`
  - `90-100%`: `631` predictions, `97.1%` predicted, `100.0%` observed, gap `0.0290`

## Diagnosis to Verify

The entire `80-90%` bin should be explained by DANE/TLSA under the synthetic `1/5` resolver-agreement scenario:

```text
0.2 * rawConfidence(1.0) + 0.8 * DANE prior(0.85) = 0.88
```

All 14 predictions in that bin pass, so this is conservative under-confidence, not evidence of analysis failure.

## Evidence-First Fix to Evaluate

Do not change labels or rating thresholds just to make the page look better.

Evaluate the evidence-backed prior simulation in the script:

```text
effective_prior =
  (base_alpha + capped_passes)
  / (base_alpha + base_beta + capped_passes + capped_failures)
```

Use the lower-confidence ICAE layer as evidence:

```text
min(analysis_consecutive_passes, collection_consecutive_passes)
```

The script should show:

- cap `50`: `80-90%` bin disappears, but not all protocols are excellent
- cap `100`: ECE becomes excellent, but DANE/TLSA remains above the strict excellent gap cutoff
- cap `250`: all protocol gaps become `excellent`, and the `80-90%` bin remains gone
- cap `500`: also excellent, but more aggressive than needed

The recommended first production cap is `250`.

## Production Recommendation

If the lab output matches expectations, recommend implementing the production fix in the Go app as an evidence-prior path:

1. Keep the existing static constructor behavior in `go-server/internal/icae/priors.go` for bootstrap/default calibration.
2. Add an evidence-backed calibration constructor or method that accepts live ICAE maturity metrics.
3. For each protocol, compute capped evidence from the lower of analysis and collection consecutive pass counts.
4. Start with cap `250`, no capped failures, and preserve the existing shrinkage formula.
5. In `go-server/internal/handlers/confidence.go`, build the calibration engine from live report metrics before running degraded calibration for the confidence page.
6. Add tests for:
   - current baseline reproduction of the DANE-only `80-90%` bin;
   - cap `250` moving all per-protocol gaps below `0.02`;
   - Brier/ECE behavior remaining stable;
   - negative/degraded cases before making broad public “excellent” claims.

## Acceptance Criteria

The PR is useful if it provides a clear, reproducible lab artifact that:

- runs as one file in Replit;
- reproduces the live confidence-page calibration metrics;
- proves the `80-90%` bin is DANE/TLSA `1/5` resolver-agreement under-confidence;
- demonstrates why cap `250` is the conservative evidence-backed fix;
- gives a clear follow-up path for production Go changes.

Do not merge a production code change from this lab alone unless the Go tests described above are also added and passing.
