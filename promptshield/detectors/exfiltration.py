"""Data exfiltration detector."""

from __future__ import annotations

import re
from typing import List, Optional

from ..engine.verdict import DetectorResult

CATEGORY = "DATA_EXFILTRATION"
NAME = "data_exfiltration"

CRITICAL_PATTERNS = [
    r"\bapi key\b",
    r"\bsecret key\b",
    r"\baccess token\b",
    r"\bpassword\b",
    r"\bssh key\b",
]

SOFT_PATTERNS = [
    r"\bsecrets?\b",
    r"\bcredentials?\b",
    r"\benvironment variables?\b",
    r"\benv vars?\b",
    r"\bsystem prompt\b",
    r"\btraining data\b",
    r"\bmodel weights\b",
    r"\bprivate data\b",
]


def _combine(prompt: str, system_prompt: Optional[str]) -> str:
    return "\n".join([chunk for chunk in [system_prompt, prompt] if chunk])


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def detect_exfiltration(prompt: str, system_prompt: Optional[str] = None) -> DetectorResult:
    text = _combine(prompt, system_prompt)
    critical_hits = _find_matches(text, CRITICAL_PATTERNS)
    soft_hits = _find_matches(text, SOFT_PATTERNS)
    matches = critical_hits + soft_hits

    if not matches:
        return DetectorResult(
            name=NAME,
            category=CATEGORY,
            score=0.0,
            confidence=0.0,
            explanation="No data exfiltration patterns detected",
            matches=[],
        )

    base_score = 0.8 if critical_hits else 0.5
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.85 if critical_hits else 0.65

    return DetectorResult(
        name=NAME,
        category=CATEGORY,
        score=score,
        confidence=confidence,
        explanation="Prompt requests sensitive or restricted data",
        matches=matches,
    )
