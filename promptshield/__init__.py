"""PromptShield public API."""

from .engine.config import EngineConfig, Thresholds
from .engine.scanner import PromptShieldEngine, scan_messages, scan_prompt
from .engine.types import Message, RiskCategory
from .engine.verdict import DetectorResult, ScanResult
from .engine.events import SecurityError, SecurityEvent

__all__ = [
    "scan_prompt",
    "scan_messages",
    "PromptShieldEngine",
    "EngineConfig",
    "Thresholds",
    "Message",
    "RiskCategory",
    "ScanResult",
    "DetectorResult",
    "SecurityEvent",
    "SecurityError",
]
