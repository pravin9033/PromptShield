"""Prompt injection detector."""

from __future__ import annotations

import re
from typing import Optional

from ..engine.context import PromptContext, build_context
from ..engine.registry import DetectorSpec
from ..engine.types import RiskCategory, MessageSequence
from ..engine.verdict import DetectorResult
from .patterns import find_matches, load_pattern_set

CATEGORY = RiskCategory.PROMPT_INJECTION.value
NAME = "prompt_injection"


def detect_injection_context(context: PromptContext) -> DetectorResult:
    patterns = load_pattern_set("prompt_injection", flags=re.IGNORECASE)
    critical_hits = find_matches(context.combined_text, patterns.critical)
    soft_hits = find_matches(context.combined_text, patterns.soft)
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


def detect_injection(
    prompt: str,
    system_prompt: Optional[str] = None,
    messages: Optional[MessageSequence] = None,
) -> DetectorResult:
    context = build_context(prompt=prompt, system_prompt=system_prompt, messages=messages)
    return detect_injection_context(context)


def get_detector() -> DetectorSpec:
    return DetectorSpec(name=NAME, category=RiskCategory.PROMPT_INJECTION, detect=detect_injection_context)
