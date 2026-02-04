"""Compliance scanning types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class ComplianceCategory(str, Enum):
    PII = "PII"
    SECRETS = "SECRETS"
    NONE = "NONE"


@dataclass(frozen=True)
class ComplianceIssue:
    category: str
    score: float
    confidence: float
    explanation: str
    matches: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceResult:
    block: bool
    risk_score: int
    category: str
    confidence: float
    explanation: str
    issues: List[ComplianceIssue] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
