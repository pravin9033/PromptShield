"""Role confusion detector."""

from __future__ import annotations

import re
from typing import List, Optional

from ..engine.verdict import DetectorResult

CATEGORY = "ROLE_CONFUSION"
NAME = "role_confusion"

ROLE_TAG_PATTERNS = [
    r"^(system|assistant|developer|tool)\s*:",
    r"<\s*(system|assistant|developer|tool)\s*>",
    r"\[(system|assistant|developer|tool)\]",
]

ROLE_CLAIM_PATTERNS = [
    r"\bI am the system\b",
    r"\bI am the assistant\b",
    r"\bact as the system\b",
    r"\bpretend to be the system\b",
]


def _combine(prompt: str, system_prompt: Optional[str]) -> str:
    return "\n".join([chunk for chunk in [system_prompt, prompt] if chunk])


def _find_matches(text: str, patterns: List[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            hits.append(pattern)
    return hits


def detect_role_confusion(prompt: str, system_prompt: Optional[str] = None) -> DetectorResult:
    text = _combine(prompt, system_prompt)
    tag_hits = _find_matches(text, ROLE_TAG_PATTERNS)
    claim_hits = _find_matches(text, ROLE_CLAIM_PATTERNS)
    matches = tag_hits + claim_hits

    if not matches:
        return DetectorResult(
            name=NAME,
            category=CATEGORY,
            score=0.0,
            confidence=0.0,
            explanation="No role confusion patterns detected",
            matches=[],
        )

    base_score = 0.65 if tag_hits else 0.5
    score = min(1.0, base_score + 0.05 * max(0, len(matches) - 1))
    confidence = 0.7 if tag_hits else 0.6

    return DetectorResult(
        name=NAME,
        category=CATEGORY,
        score=score,
        confidence=confidence,
        explanation="User content attempts to impersonate system or assistant roles",
        matches=matches,
    )
