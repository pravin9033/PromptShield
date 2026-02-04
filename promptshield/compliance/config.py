"""Compliance configuration and thresholds."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from promptshield.engine.events import SecurityEvent
from .types import ComplianceCategory

EventSink = Callable[[SecurityEvent], None]


def default_weights() -> Dict[str, float]:
    return {
        ComplianceCategory.PII.value: 0.6,
        ComplianceCategory.SECRETS.value: 0.4,
    }


@dataclass(frozen=True)
class ComplianceThresholds:
    allow: int = 40
    warn: int = 69
    block: int = 70


@dataclass(frozen=True)
class ComplianceConfig:
    weights: Dict[str, float] = field(default_factory=default_weights)
    thresholds: ComplianceThresholds = field(default_factory=ComplianceThresholds)
    boost_threshold: float = 0.9
    event_sink: Optional[EventSink] = None

    @classmethod
    def from_env(cls) -> "ComplianceConfig":
        weights = default_weights()
        thresholds = ComplianceThresholds()
        boost_threshold = _get_env_float("PROMPTSHIELD_COMPLIANCE_BOOST", 0.9)
        boost_threshold = max(0.0, min(1.0, boost_threshold))

        weights = _apply_weight_env_overrides(weights)
        thresholds = _apply_threshold_env_overrides(thresholds)

        return cls(weights=weights, thresholds=thresholds, boost_threshold=boost_threshold)


def _get_env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _apply_weight_env_overrides(weights: Dict[str, float]) -> Dict[str, float]:
    override_json = os.getenv("PROMPTSHIELD_COMPLIANCE_WEIGHTS")
    if override_json:
        try:
            parsed = json.loads(override_json)
            if isinstance(parsed, dict):
                weights.update({str(k): float(v) for k, v in parsed.items()})
        except (ValueError, TypeError):
            pass

    for category in ComplianceCategory:
        env_key = f"PROMPTSHIELD_COMPLIANCE_WEIGHT_{category.value}"
        if env_key in os.environ:
            weights[category.value] = _get_env_float(env_key, weights.get(category.value, 0.0))

    return weights


def _apply_threshold_env_overrides(thresholds: ComplianceThresholds) -> ComplianceThresholds:
    allow = _get_env_int("PROMPTSHIELD_COMPLIANCE_ALLOW", thresholds.allow)
    warn = _get_env_int("PROMPTSHIELD_COMPLIANCE_WARN", thresholds.warn)
    block = _get_env_int("PROMPTSHIELD_COMPLIANCE_BLOCK", thresholds.block)

    allow = max(0, min(100, allow))
    warn = max(0, min(100, warn))
    block = max(0, min(100, block))

    return ComplianceThresholds(allow=allow, warn=warn, block=block)
