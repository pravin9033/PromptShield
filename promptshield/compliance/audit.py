"""Audit logging for security and compliance events."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from promptshield.engine.events import SecurityEvent


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    timestamp: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """Write audit events to a JSONL file."""

    def __init__(self, path: str = "audit.log.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event)) + "\n")

    def log_security_event(self, event: SecurityEvent) -> None:
        audit_event = AuditEvent(
            event_type=event.event_type,
            timestamp=event.timestamp.isoformat(),
            message=event.message,
            metadata=event.metadata,
        )
        self.log_event(audit_event)

    def log_custom(self, event_type: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        event = AuditEvent(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message=message,
            metadata=metadata or {},
        )
        self.log_event(event)
