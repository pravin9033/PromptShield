"""Scanning orchestrator."""

from __future__ import annotations

from typing import Optional

from .risk import THRESHOLDS, aggregate_risk
from .verdict import ScanResult
from ..detectors.exfiltration import detect_exfiltration
from ..detectors.injection import detect_injection
from ..detectors.jailbreak import detect_jailbreak
from ..detectors.role_confusion import detect_role_confusion


def scan_prompt(prompt: str, system_prompt: Optional[str] = None) -> ScanResult:
    """Scan a prompt (and optional system prompt) for attack signals."""
    if prompt is None or not str(prompt).strip():
        raise ValueError("prompt must be a non-empty string")

    prompt_text = str(prompt)
    system_text = None if system_prompt is None else str(system_prompt)

    signals = [
        detect_injection(prompt_text, system_text),
        detect_jailbreak(prompt_text, system_text),
        detect_role_confusion(prompt_text, system_text),
        detect_exfiltration(prompt_text, system_text),
    ]

    risk_score, category, confidence, explanation = aggregate_risk(signals)
    block = risk_score >= THRESHOLDS["block"]

    return ScanResult(
        block=block,
        risk_score=risk_score,
        category=category,
        confidence=confidence,
        explanation=explanation,
        reason=explanation,
        signals=signals,
    )
