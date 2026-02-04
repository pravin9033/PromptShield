"""PII detector for model outputs."""

from __future__ import annotations

from typing import List

from .patterns import find_matches, pii_patterns
from .types import ComplianceCategory, ComplianceIssue


def detect_pii(text: str) -> ComplianceIssue:
    patterns = pii_patterns()
    critical_hits = find_matches(text, patterns.critical)
    soft_hits = find_matches(text, patterns.soft)
    matches = critical_hits + soft_hits

    if not matches:
        return ComplianceIssue(
            category=ComplianceCategory.PII.value,
            score=0.0,
            confidence=0.0,
            explanation="No PII detected",
            matches=[],
        )

    base_score = 0.8 if critical_hits else 0.4
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.85 if critical_hits else 0.6

    return ComplianceIssue(
        category=ComplianceCategory.PII.value,
        score=score,
        confidence=confidence,
        explanation="Potential PII detected in output",
        matches=matches,
    )
