"""Secret scanner for model outputs."""

from __future__ import annotations

from .patterns import find_matches, secret_patterns
from .types import ComplianceCategory, ComplianceIssue


def detect_secrets(text: str) -> ComplianceIssue:
    patterns = secret_patterns()
    critical_hits = find_matches(text, patterns.critical)
    soft_hits = find_matches(text, patterns.soft)
    matches = critical_hits + soft_hits

    if not matches:
        return ComplianceIssue(
            category=ComplianceCategory.SECRETS.value,
            score=0.0,
            confidence=0.0,
            explanation="No secrets detected",
            matches=[],
        )

    base_score = 0.9 if critical_hits else 0.5
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.9 if critical_hits else 0.65

    return ComplianceIssue(
        category=ComplianceCategory.SECRETS.value,
        score=score,
        confidence=confidence,
        explanation="Potential secret detected in output",
        matches=matches,
    )
