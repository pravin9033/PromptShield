"""Role confusion detector."""

from __future__ import annotations

import re
from typing import Optional

from ..engine.context import PromptContext, build_context
from ..engine.registry import DetectorSpec
from ..engine.types import RiskCategory, MessageSequence
from ..engine.verdict import DetectorResult
from .patterns import find_matches, load_pattern_set

CATEGORY = RiskCategory.ROLE_CONFUSION.value
NAME = "role_confusion"


def detect_role_confusion_context(context: PromptContext) -> DetectorResult:
    patterns = load_pattern_set("role_confusion", flags=re.IGNORECASE | re.MULTILINE)
    tag_hits = find_matches(context.combined_text, patterns.critical)
    claim_hits = find_matches(context.combined_text, patterns.soft)
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


def detect_role_confusion(
    prompt: str,
    system_prompt: Optional[str] = None,
    messages: Optional[MessageSequence] = None,
) -> DetectorResult:
    context = build_context(prompt=prompt, system_prompt=system_prompt, messages=messages)
    return detect_role_confusion_context(context)


def get_detector() -> DetectorSpec:
    return DetectorSpec(name=NAME, category=RiskCategory.ROLE_CONFUSION, detect=detect_role_confusion_context)
