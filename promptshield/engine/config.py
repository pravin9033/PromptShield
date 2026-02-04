"""Engine configuration and environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from .events import SecurityEvent
from .types import RiskCategory

EventSink = Callable[[SecurityEvent], None]


def default_weights() -> Dict[str, float]:
    return {
        RiskCategory.PROMPT_INJECTION.value: 0.4,
        RiskCategory.JAILBREAK.value: 0.3,
        RiskCategory.ROLE_CONFUSION.value: 0.2,
        RiskCategory.DATA_EXFILTRATION.value: 0.1,
    }


@dataclass(frozen=True)
class Thresholds:
    allow: int = 40
    warn: int = 69
    block: int = 70


@dataclass(frozen=True)
class EngineConfig:
    weights: Dict[str, float] = field(default_factory=default_weights)
    thresholds: Thresholds = field(default_factory=Thresholds)
    boost_threshold: float = 0.85
    event_sink: Optional[EventSink] = None

    @classmethod
    def from_env(cls) -> "EngineConfig":
        weights = default_weights()
        thresholds = Thresholds()
        boost_threshold = _get_env_float("PROMPTSHIELD_BOOST_THRESHOLD", 0.85)
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
    override_json = os.getenv("PROMPTSHIELD_WEIGHTS")
    if override_json:
        try:
            parsed = json.loads(override_json)
            if isinstance(parsed, dict):
                weights.update({str(k): float(v) for k, v in parsed.items()})
        except (ValueError, TypeError):
            pass

    for category in RiskCategory:
        env_key = f"PROMPTSHIELD_WEIGHT_{category.value}"
        if env_key in os.environ:
            weights[category.value] = _get_env_float(env_key, weights.get(category.value, 0.0))

    return weights


def _apply_threshold_env_overrides(thresholds: Thresholds) -> Thresholds:
    allow = _get_env_int("PROMPTSHIELD_THRESHOLD_ALLOW", thresholds.allow)
    warn = _get_env_int("PROMPTSHIELD_THRESHOLD_WARN", thresholds.warn)
    block = _get_env_int("PROMPTSHIELD_THRESHOLD_BLOCK", thresholds.block)

    allow = max(0, min(100, allow))
    warn = max(0, min(100, warn))
    block = max(0, min(100, block))

    return Thresholds(allow=allow, warn=warn, block=block)
