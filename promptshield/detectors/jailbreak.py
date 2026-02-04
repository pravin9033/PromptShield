"""Jailbreak detector (DAN-style, roleplay exploits, encoding tricks)."""

from __future__ import annotations

import re
from typing import List, Optional

from ..engine.verdict import DetectorResult

CATEGORY = "JAILBREAK"
NAME = "jailbreak"

CRITICAL_PATTERNS = [
    r"\bDAN\b",
    r"\bdo anything now\b",
    r"\bdeveloper mode\b",
    r"\buncensored\b",
]

SOFT_PATTERNS = [
    r"\bjailbreak\b",
    r"\bno restrictions\b",
    r"\bbypass (all )?safety\b",
    r"\bpretend (you are|to be)\b",
    r"\brole ?play\b",
    r"\bbase64\b",
    r"\brot13\b",
    r"\bencode|decode\b",
]


def _combine(prompt: str, system_prompt: Optional[str]) -> str:
    return "\n".join([chunk for chunk in [system_prompt, prompt] if chunk])


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def detect_jailbreak(prompt: str, system_prompt: Optional[str] = None) -> DetectorResult:
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
            explanation="No jailbreak patterns detected",
            matches=[],
        )

    base_score = 0.85 if critical_hits else 0.55
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.88 if critical_hits else 0.7

    return DetectorResult(
        name=NAME,
        category=CATEGORY,
        score=score,
        confidence=confidence,
        explanation="Jailbreak attempt or restriction bypass language detected",
        matches=matches,
    )
