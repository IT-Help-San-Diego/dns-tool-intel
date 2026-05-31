#!/usr/bin/env python3
"""Standalone DNS Tool ICAE confidence gap lab.

Upload this single file to Replit and run:

    python confidence_gap_lab.py

It reproduces the production degraded-calibration shape from
https://dnstool.it-help.tech/confidence, explains the 80-90% confidence bin,
and simulates an evidence-first fix that uses capped audit history to update
bootstrap priors instead of merely relabeling "good" as "excellent".
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


RAW_CONFIDENCE = 1.0
NUM_BINS = 10
RESOLVER_SCENARIOS = ((5, 5), (4, 5), (3, 5), (2, 5), (1, 5))
EXCELLENT_GAP_CUTOFF = 0.02
RECOMMENDED_EVIDENCE_CAP = 250


@dataclass(frozen=True)
class ProtocolConfig:
    key: str
    display: str
    alpha: float
    beta: float
    test_cases: int
    analysis_passes: int
    collection_passes: int

    @property
    def base_prior(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def lower_layer_passes(self) -> int:
        return min(self.analysis_passes, self.collection_passes)


@dataclass(frozen=True)
class Prediction:
    protocol: str
    display: str
    agree: int
    total: int
    confidence: float
    outcome: float


@dataclass
class CalibrationBin:
    start: float
    end: float
    label: str
    count: int = 0
    predicted_sum: float = 0.0
    observed_sum: float = 0.0
    mean_predicted: float = 0.0
    mean_observed: float = 0.0
    gap: float = 0.0
    bar_width_pct: int = 0


PROTOCOLS = (
    ProtocolConfig("SPF", "SPF", 95, 5, 20, 4867, 4344),
    ProtocolConfig("DKIM", "DKIM", 90, 10, 8, 4686, 4325),
    ProtocolConfig("DMARC", "DMARC", 97, 3, 24, 4851, 4237),
    ProtocolConfig("DANE", "DANE/TLSA", 85, 15, 14, 4670, 4315),
    ProtocolConfig("DNSSEC", "DNSSEC", 92, 8, 25, 4848, 4318),
    ProtocolConfig("BIMI", "BIMI", 88, 12, 11, 4685, 4320),
    ProtocolConfig("MTA_STS", "MTA-STS", 90, 10, 12, 4688, 4334),
    ProtocolConfig("TLS_RPT", "TLS-RPT", 93, 7, 5, 4690, 4232),
    ProtocolConfig("CAA", "CAA", 95, 5, 10, 4682, 4321),
)


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def rating_from_brier(score: float) -> str:
    if score < 0.01:
        return "excellent"
    if score < 0.05:
        return "good"
    if score < 0.10:
        return "adequate"
    if score < 0.25:
        return "weak"
    return "poor"


def rating_from_ece(ece: float) -> str:
    if ece < 0.02:
        return "excellent"
    if ece < 0.05:
        return "good"
    if ece < 0.10:
        return "adequate"
    if ece < 0.20:
        return "weak"
    return "poor"


def rating_from_gap(gap: float) -> str:
    if gap < 0.02:
        return "excellent"
    if gap < 0.05:
        return "good"
    if gap < 0.10:
        return "adequate"
    return "weak"


def bin_label(start: float, end: float) -> str:
    return f"{round(start * 100):.0f}-{round(end * 100):.0f}%"


def calibrated_confidence(prior_mean: float, agree: int, total: int) -> float:
    if total == 0:
        return prior_mean
    measurement_quality = agree / total
    calibrated = (
        measurement_quality * RAW_CONFIDENCE
        + (1.0 - measurement_quality) * prior_mean
    )
    return max(0.0, min(1.0, calibrated))


def build_predictions(priors: dict[str, float]) -> list[Prediction]:
    predictions: list[Prediction] = []
    for proto in PROTOCOLS:
        for _ in range(proto.test_cases):
            for agree, total in RESOLVER_SCENARIOS:
                predictions.append(
                    Prediction(
                        protocol=proto.key,
                        display=proto.display,
                        agree=agree,
                        total=total,
                        confidence=calibrated_confidence(
                            priors[proto.key], agree, total
                        ),
                        outcome=1.0,
                    )
                )
    predictions.sort(key=lambda p: p.confidence)
    return predictions


def compute_bins(predictions: Iterable[Prediction]) -> list[CalibrationBin]:
    bin_width = 1.0 / NUM_BINS
    bins = [
        CalibrationBin(
            i * bin_width,
            (i + 1) * bin_width,
            bin_label(i * bin_width, (i + 1) * bin_width),
        )
        for i in range(NUM_BINS)
    ]

    for prediction in predictions:
        idx = int(prediction.confidence / bin_width)
        idx = min(NUM_BINS - 1, max(0, idx))
        bins[idx].count += 1
        bins[idx].predicted_sum += prediction.confidence
        bins[idx].observed_sum += prediction.outcome

    max_count = max((b.count for b in bins), default=0)
    for item in bins:
        if item.count:
            item.mean_predicted = item.predicted_sum / item.count
            item.mean_observed = item.observed_sum / item.count
            item.gap = abs(item.mean_predicted - item.mean_observed)
            item.bar_width_pct = (item.count * 100) // max_count if max_count else 0
    return bins


def compute_per_protocol(predictions: Iterable[Prediction]) -> list[dict[str, object]]:
    grouped: dict[str, list[Prediction]] = defaultdict(list)
    display_by_key = {p.key: p.display for p in PROTOCOLS}
    for prediction in predictions:
        grouped[prediction.protocol].append(prediction)

    rows = []
    for key, items in grouped.items():
        n = len(items)
        mean_confidence = sum(p.confidence for p in items) / n
        pass_rate = sum(p.outcome for p in items) / n
        brier = sum((p.confidence - p.outcome) ** 2 for p in items) / n
        gap = abs(mean_confidence - pass_rate)
        rows.append(
            {
                "protocol": key,
                "display": display_by_key[key],
                "predictions": n,
                "mean_confidence": mean_confidence,
                "pass_rate": pass_rate,
                "brier": brier,
                "gap": gap,
                "rating": rating_from_gap(gap),
            }
        )
    return sorted(rows, key=lambda row: float(row["gap"]))


def compute_calibration(predictions: list[Prediction]) -> dict[str, object]:
    bins = compute_bins(predictions)
    total = len(predictions)
    brier = sum((p.confidence - p.outcome) ** 2 for p in predictions) / total
    ece = sum((item.count / total) * item.gap for item in bins if item.count)
    return {
        "brier": brier,
        "ece": ece,
        "bins": bins,
        "populated_bins": [item for item in bins if item.count],
        "per_protocol": compute_per_protocol(predictions),
        "total_predictions": total,
        "total_cases": sum(p.test_cases for p in PROTOCOLS),
        "resolver_scenarios": len(RESOLVER_SCENARIOS),
    }


def base_priors() -> dict[str, float]:
    return {proto.key: proto.base_prior for proto in PROTOCOLS}


def evidence_priors(cap: int, capped_failures: int = 0) -> dict[str, float]:
    priors: dict[str, float] = {}
    for proto in PROTOCOLS:
        capped_passes = min(proto.lower_layer_passes, cap)
        priors[proto.key] = (
            (proto.alpha + capped_passes)
            / (proto.alpha + proto.beta + capped_passes + capped_failures)
        )
    return priors


def min_clean_passes_for_excellent(proto: ProtocolConfig) -> int:
    passes = 0
    while True:
        effective_prior = (proto.alpha + passes) / (proto.alpha + proto.beta + passes)
        expected_gap = 0.4 * (1.0 - effective_prior)
        if expected_gap < EXCELLENT_GAP_CUTOFF:
            return passes
        passes += 1


def print_header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def print_baseline_report(result: dict[str, object]) -> None:
    print_header("1. Baseline: production-equivalent degraded calibration")
    print(f"Golden test cases:       {result['total_cases']}")
    print(f"Resolver scenarios:      {result['resolver_scenarios']}")
    print(f"Total predictions:       {result['total_predictions']}")
    print(
        f"Brier score:             {result['brier']:.4f} "
        f"({rating_from_brier(float(result['brier']))})"
    )
    print(
        f"Expected calibration err: {result['ece']:.4f} "
        f"({rating_from_ece(float(result['ece']))})"
    )

    print()
    print("Populated reliability bins:")
    print(f"{'Bin':<10} {'Count':>7} {'Predicted':>11} {'Observed':>10} {'Gap':>8}")
    for item in result["populated_bins"]:
        assert isinstance(item, CalibrationBin)
        print(
            f"{item.label:<10} {item.count:>7} {pct(item.mean_predicted):>11} "
            f"{pct(item.mean_observed):>10} {item.gap:>8.4f}"
        )

    print()
    print("Per-protocol calibration:")
    print(
        f"{'Protocol':<10} {'Preds':>6} {'Mean conf':>10} "
        f"{'Pass rate':>10} {'Brier':>8} {'Gap':>8} {'Rating':>10}"
    )
    for row in result["per_protocol"]:
        print(
            f"{str(row['display']):<10} {int(row['predictions']):>6} "
            f"{pct(float(row['mean_confidence'])):>10} "
            f"{pct(float(row['pass_rate'])):>10} "
            f"{float(row['brier']):>8.4f} {float(row['gap']):>8.4f} "
            f"{str(row['rating']):>10}"
        )


def print_bin_anatomy(predictions: list[Prediction]) -> None:
    print_header("2. Bin anatomy: protocol/agreement pairs inside each bin")
    grouped: dict[tuple[str, str, int, int, float], int] = defaultdict(int)
    bin_width = 1.0 / NUM_BINS
    for prediction in predictions:
        idx = int(prediction.confidence / bin_width)
        idx = min(NUM_BINS - 1, max(0, idx))
        start = idx * bin_width
        end = (idx + 1) * bin_width
        grouped[
            (
                bin_label(start, end),
                prediction.display,
                prediction.agree,
                prediction.total,
                prediction.confidence,
            )
        ] += 1

    print(
        f"{'Bin':<10} {'Protocol':<10} {'Resolvers':>9} "
        f"{'Prior->confidence':>22} {'Count':>7}"
    )
    for (label, display, agree, total, confidence), count in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][4], item[0][1], item[0][2])
    ):
        proto = next(p for p in PROTOCOLS if p.display == display)
        resolvers = f"{agree}/{total}"
        print(
            f"{label:<10} {display:<10} {resolvers:>9} "
            f"{proto.base_prior:>7.4f} -> {confidence:<7.4f} {count:>7}"
        )

    print()
    print("Diagnosis:")
    print(
        "The entire 80-90% bin is DANE/TLSA at 1/5 resolver agreement: "
        "0.2 * 1.0 + 0.8 * 0.85 = 0.88. All 14 of those predictions pass, "
        "so the gap is conservative under-confidence, not observed failure."
    )


def print_prior_threshold_report() -> None:
    print_header("3. Prior threshold: what it takes for every protocol to be excellent")
    print(
        "With the five resolver scenarios used by production, protocol mean "
        "confidence is 0.6 + 0.4 * prior. To make the per-protocol gap "
        "strictly excellent (< 0.0200), the effective prior must be > 0.9500."
    )
    print()
    print(
        f"{'Protocol':<10} {'Base prior':>10} {'Base gap':>9} "
        f"{'Min clean passes':>17} {'Lower layer':>12} {'Enough?':>8}"
    )
    for proto in PROTOCOLS:
        required = min_clean_passes_for_excellent(proto)
        base_gap = 0.4 * (1.0 - proto.base_prior)
        enough = "yes" if proto.lower_layer_passes >= required else "no"
        print(
            f"{proto.display:<10} {proto.base_prior:>10.4f} {base_gap:>9.4f} "
            f"{required:>17} {proto.lower_layer_passes:>12} {enough:>8}"
        )

    print()
    print(
        "The important row is DANE/TLSA: its bootstrap prior is 0.8500, "
        "so it needs more than 200 clean effective passes. The live lower "
        "layer already has thousands of clean passes, so a capped evidence "
        "prior can justify the improvement without hand-waving."
    )


def print_evidence_simulation() -> None:
    print_header("4. Evidence-backed simulation: capped audit history priors")
    print(
        "Formula: effective_prior = "
        "(base_alpha + capped_passes) / "
        "(base_alpha + base_beta + capped_passes + capped_failures)"
    )
    print("Evidence source: min(analysis_consecutive_passes, collection_consecutive_passes).")
    print()
    print(
        f"{'Cap':>5} {'Brier':>8} {'Brier rtg':>10} {'ECE':>8} {'ECE rtg':>9} "
        f"{'80-90 cnt':>10} {'Worst proto':>12} {'Worst gap':>10} {'All excellent?':>15}"
    )

    recommended_result: dict[str, object] | None = None
    for cap in (0, 50, 100, RECOMMENDED_EVIDENCE_CAP, 500):
        priors = base_priors() if cap == 0 else evidence_priors(cap)
        result = compute_calibration(build_predictions(priors))
        populated_bins = result["populated_bins"]
        eighty_count = 0
        for item in populated_bins:
            assert isinstance(item, CalibrationBin)
            if item.label == "80-90%":
                eighty_count = item.count

        per_protocol = result["per_protocol"]
        worst = max(per_protocol, key=lambda row: float(row["gap"]))
        all_excellent = all(str(row["rating"]) == "excellent" for row in per_protocol)
        label = "base" if cap == 0 else str(cap)
        print(
            f"{label:>5} {float(result['brier']):>8.4f} "
            f"{rating_from_brier(float(result['brier'])):>10} "
            f"{float(result['ece']):>8.4f} {rating_from_ece(float(result['ece'])):>9} "
            f"{eighty_count:>10} {str(worst['display']):>12} "
            f"{float(worst['gap']):>10.4f} {str(all_excellent):>15}"
        )
        if cap == RECOMMENDED_EVIDENCE_CAP:
            recommended_result = result

    print()
    print(f"Recommended first cap: {RECOMMENDED_EVIDENCE_CAP}")
    print(
        "At this cap, all protocols have strict excellent gaps and the "
        "80-90% bin disappears because DANE/TLSA's 1/5 confidence rises "
        "above 90%."
    )

    if recommended_result is not None:
        print()
        print(f"Per-protocol detail at cap={RECOMMENDED_EVIDENCE_CAP}:")
        print(
            f"{'Protocol':<10} {'Effective prior':>16} "
            f"{'Mean conf':>10} {'Gap':>8} {'Rating':>10}"
        )
        cap_priors = evidence_priors(RECOMMENDED_EVIDENCE_CAP)
        for row in recommended_result["per_protocol"]:
            key = str(row["protocol"])
            print(
                f"{str(row['display']):<10} {cap_priors[key]:>16.4f} "
                f"{pct(float(row['mean_confidence'])):>10} "
                f"{float(row['gap']):>8.4f} {str(row['rating']):>10}"
            )


def print_production_followup() -> None:
    print_header("Production follow-up")
    print("Implement the fix in the Go app as an evidence-prior path, not a label change:")
    print("1. Keep NewCalibrationEngine() as the bootstrap/static-prior constructor.")
    print("2. Add a constructor or method that accepts live ReportMetrics maturity evidence.")
    print("3. For each protocol, use min(analysis_passes, collection_passes), capped at 250 first.")
    print("4. Re-run RunDegradedCalibration with the evidence-backed engine on /confidence.")
    print("5. Add tests for the baseline 80-90% DANE bin, cap=250 excellence, and negative stress cases.")


def main() -> None:
    print("DNS Tool ICAE confidence gap lab")
    print("Source page: https://dnstool.it-help.tech/confidence")
    print("No network and no third-party Python packages are required.")

    baseline_predictions = build_predictions(base_priors())
    baseline_result = compute_calibration(baseline_predictions)

    print_baseline_report(baseline_result)
    print_bin_anatomy(baseline_predictions)
    print_prior_threshold_report()
    print_evidence_simulation()
    print_production_followup()


if __name__ == "__main__":
    main()
