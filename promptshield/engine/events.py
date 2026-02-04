"""Event and error primitives for PromptShield."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


class SecurityError(RuntimeError):
    """Raised when a prompt is blocked by PromptShield."""


@dataclass(frozen=True)
class SecurityEvent:
    event_type: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
