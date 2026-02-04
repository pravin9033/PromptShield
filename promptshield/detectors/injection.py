"""Prompt injection detector."""

from __future__ import annotations

import re
from typing import List, Optional

from ..engine.verdict import DetectorResult

CATEGORY = "PROMPT_INJECTION"
NAME = "prompt_injection"

CRITICAL_PATTERNS = [
    r"\bignore (all |the )?previous instructions\b",
    r"\bdisregard (all |the )?instructions\b",
    r"\bsystem override\b",
    r"\boverride (the )?system\b",
    r"\bdeveloper message\b",
]

SOFT_PATTERNS = [
    r"\byou are now\b",
    r"\bforget (everything|the above)\b",
    r"\bnew instructions\b",
    r"\bact as (the )?system\b",
    r"\bignore the system prompt\b",
]


def _combine(prompt: str, system_prompt: Optional[str]) -> str:
    return "\n".join([chunk for chunk in [system_prompt, prompt] if chunk])


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def detect_injection(prompt: str, system_prompt: Optional[str] = None) -> DetectorResult:
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
            explanation="No prompt injection patterns detected",
            matches=[],
        )

    base_score = 0.9 if critical_hits else 0.6
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.9 if critical_hits else 0.75

    return DetectorResult(
        name=NAME,
        category=CATEGORY,
        score=score,
        confidence=confidence,
        explanation="Attempt to override system instructions",
        matches=matches,
    )
