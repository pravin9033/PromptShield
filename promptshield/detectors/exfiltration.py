"""Data exfiltration detector."""

from __future__ import annotations

import re
from typing import Optional

from ..engine.context import PromptContext, build_context
from ..engine.registry import DetectorSpec
from ..engine.types import RiskCategory, MessageSequence
from ..engine.verdict import DetectorResult
from .patterns import find_matches, load_pattern_set

CATEGORY = RiskCategory.DATA_EXFILTRATION.value
NAME = "data_exfiltration"


def detect_exfiltration_context(context: PromptContext) -> DetectorResult:
    patterns = load_pattern_set("exfiltration", flags=re.IGNORECASE)
    critical_hits = find_matches(context.combined_text, patterns.critical)
    soft_hits = find_matches(context.combined_text, patterns.soft)
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


def detect_exfiltration(
    prompt: str,
    system_prompt: Optional[str] = None,
    messages: Optional[MessageSequence] = None,
) -> DetectorResult:
    context = build_context(prompt=prompt, system_prompt=system_prompt, messages=messages)
    return detect_exfiltration_context(context)


def get_detector() -> DetectorSpec:
    return DetectorSpec(name=NAME, category=RiskCategory.DATA_EXFILTRATION, detect=detect_exfiltration_context)
