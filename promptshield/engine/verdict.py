"""Verdicts and detector results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class DetectorResult:
    name: str
    category: str
    score: float
    confidence: float
    explanation: str
    matches: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanResult:
    block: bool
    risk_score: int
    category: str
    confidence: float
    explanation: str
    reason: str
    signals: List[DetectorResult] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
