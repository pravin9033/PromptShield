"""Types for model scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from promptshield.compliance.types import ComplianceResult


class ModelAdapter(Protocol):
    name: str

    def generate(
        self,
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        ...


@dataclass(frozen=True)
class ModelScanOutcome:
    attack_id: str
    prompt: Optional[str]
    system_prompt: Optional[str]
    messages: Optional[List[Dict[str, str]]]
    output: str
    compliance: Optional[ComplianceResult]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelScanResult:
    adapter: str
    pack_name: str
    outcomes: List[ModelScanOutcome]
    metadata: Dict[str, Any] = field(default_factory=dict)
