"""Compliance scanning engine for outputs."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from promptshield.engine.events import SecurityEvent

from .config import ComplianceConfig
from .pii import detect_pii
from .secrets import detect_secrets
from .types import ComplianceIssue, ComplianceResult

logger = logging.getLogger(__name__)


def aggregate_compliance_risk(
    issues: Iterable[ComplianceIssue],
    weights: dict[str, float],
    boost_threshold: float,
) -> tuple[int, str, float, str]:
    weighted_score = 0.0
    top_issue: Optional[ComplianceIssue] = None
    top_weighted = -1.0

    for issue in issues:
        weight = weights.get(issue.category, 0.0)
        weighted_score += issue.score * weight
        if issue.score <= 0 or weight <= 0:
            continue
        weighted_value = issue.score * weight
        if weighted_value > top_weighted:
            top_weighted = weighted_value
            top_issue = issue

    risk_score = int(round(min(1.0, weighted_score) * 100))

    if top_issue is not None and top_issue.score >= boost_threshold:
        boosted = int(round(min(1.0, top_issue.score) * 100))
        risk_score = max(risk_score, boosted)

    if top_issue is None:
        return risk_score, "NONE", 0.0, "No compliance issues detected"

    return risk_score, top_issue.category, top_issue.confidence, top_issue.explanation


class ComplianceEngine:
    """Configurable compliance scanner."""

    def __init__(self, config: Optional[ComplianceConfig] = None) -> None:
        self.config = config or ComplianceConfig.from_env()

    def scan(self, text: str) -> ComplianceResult:
        if text is None or not str(text).strip():
            raise ValueError("text must be a non-empty string")

        output = str(text)
        issues = [
            detect_pii(output),
            detect_secrets(output),
        ]

        risk_score, category, confidence, explanation = aggregate_compliance_risk(
            issues,
            weights=self.config.weights,
            boost_threshold=self.config.boost_threshold,
        )
        block = risk_score >= self.config.thresholds.block

        result = ComplianceResult(
            block=block,
            risk_score=risk_score,
            category=category,
            confidence=confidence,
            explanation=explanation,
            issues=issues,
            metadata={"threshold": self.config.thresholds.block},
        )

        self._emit_event(result, output)
        return result

    def _emit_event(self, result: ComplianceResult, output: str) -> None:
        if not self.config.event_sink:
            return

        event = SecurityEvent(
            event_type="promptshield.compliance",
            message="Output scanned",
            metadata={
                "risk_score": result.risk_score,
                "blocked": result.block,
                "category": result.category,
                "confidence": result.confidence,
                "output_length": len(output),
            },
        )
        try:
            self.config.event_sink(event)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Compliance event sink failed: %s", exc)


_DEFAULT_COMPLIANCE_ENGINE = ComplianceEngine()


def scan_output(text: str) -> ComplianceResult:
    """Scan model output text for PII or secrets."""
    return _DEFAULT_COMPLIANCE_ENGINE.scan(text)
