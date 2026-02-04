"""Scanning orchestrator."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from .config import EngineConfig
from .context import PromptContext, build_context
from .events import SecurityEvent
from .registry import DetectorSpec, resolve_detectors
from .risk import aggregate_risk
from .types import MessageSequence
from .verdict import ScanResult

logger = logging.getLogger(__name__)


class PromptShieldEngine:
    """Configurable scanning engine."""

    def __init__(
        self,
        config: Optional[EngineConfig] = None,
        detectors: Optional[Iterable[DetectorSpec]] = None,
        include_entry_points: bool = True,
    ) -> None:
        self.config = config or EngineConfig.from_env()
        self.detectors = resolve_detectors(detectors, include_entry_points=include_entry_points)

    def scan(
        self,
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        messages: Optional[MessageSequence] = None,
    ) -> ScanResult:
        context = build_context(prompt=prompt, system_prompt=system_prompt, messages=messages)
        return self._scan_context(context)

    def scan_messages(
        self,
        messages: MessageSequence,
        system_prompt: Optional[str] = None,
    ) -> ScanResult:
        return self.scan(prompt=None, system_prompt=system_prompt, messages=messages)

    def _scan_context(self, context: PromptContext) -> ScanResult:
        signals = [detector.detect(context) for detector in self.detectors]

        risk_score, category, confidence, explanation = aggregate_risk(
            signals,
            weights=self.config.weights,
            boost_threshold=self.config.boost_threshold,
        )
        block = risk_score >= self.config.thresholds.block

        result = ScanResult(
            block=block,
            risk_score=risk_score,
            category=category,
            confidence=confidence,
            explanation=explanation,
            reason=explanation,
            signals=signals,
            metadata={
                "threshold": self.config.thresholds.block,
            },
        )

        self._emit_event(context, result)
        return result

    def _emit_event(self, context: PromptContext, result: ScanResult) -> None:
        if not self.config.event_sink:
            return

        event = SecurityEvent(
            event_type="promptshield.scan",
            message="Prompt scanned",
            metadata={
                "risk_score": result.risk_score,
                "blocked": result.block,
                "category": result.category,
                "confidence": result.confidence,
                "prompt_length": len(context.prompt),
                "message_count": len(context.messages),
            },
        )
        try:
            self.config.event_sink(event)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Event sink failed: %s", exc)


_DEFAULT_ENGINE = PromptShieldEngine()


def scan_prompt(prompt: str, system_prompt: Optional[str] = None) -> ScanResult:
    """Scan a prompt (and optional system prompt) for attack signals."""
    if prompt is None or not str(prompt).strip():
        raise ValueError("prompt must be a non-empty string")
    return _DEFAULT_ENGINE.scan(prompt=str(prompt), system_prompt=system_prompt)


def scan_messages(messages: MessageSequence, system_prompt: Optional[str] = None) -> ScanResult:
    """Scan a multi-turn message list for attack signals."""
    return _DEFAULT_ENGINE.scan_messages(messages=messages, system_prompt=system_prompt)
