"""Risk scoring utilities."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from .verdict import DetectorResult


def aggregate_risk(
    results: Iterable[DetectorResult],
    weights: Dict[str, float],
    boost_threshold: float = 0.85,
) -> Tuple[int, str, float, str]:
    """Aggregate detector results into a single risk score and top explanation."""
    weighted_score = 0.0
    top_result: DetectorResult | None = None
    top_weighted = -1.0

    for result in results:
        weight = weights.get(result.category, 0.0)
        weighted_score += result.score * weight
        if result.score <= 0 or weight <= 0:
            continue
        weighted_value = result.score * weight
        if weighted_value > top_weighted:
            top_weighted = weighted_value
            top_result = result

    risk_score = int(round(min(1.0, weighted_score) * 100))

    if top_result is not None and top_result.score >= boost_threshold:
        boosted = int(round(min(1.0, top_result.score) * 100))
        risk_score = max(risk_score, boosted)

    if top_result is None:
        return risk_score, "NONE", 0.0, "No high-risk signals detected"

    return risk_score, top_result.category, top_result.confidence, top_result.explanation
