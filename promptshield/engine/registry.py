"""Detector registry and plugin loading."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Callable, Iterable, List, Optional

from .context import PromptContext
from .types import RiskCategory
from .verdict import DetectorResult

logger = logging.getLogger(__name__)

DetectorFn = Callable[[PromptContext], DetectorResult]


@dataclass(frozen=True)
class DetectorSpec:
    name: str
    category: RiskCategory
    detect: DetectorFn


def default_detectors() -> List[DetectorSpec]:
    from promptshield.detectors import exfiltration, injection, jailbreak, role_confusion

    return [
        injection.get_detector(),
        jailbreak.get_detector(),
        role_confusion.get_detector(),
        exfiltration.get_detector(),
    ]


def load_entry_point_detectors() -> List[DetectorSpec]:
    detectors: List[DetectorSpec] = []
    for entry in entry_points(group="promptshield.detectors"):
        try:
            loaded = entry.load()
            if isinstance(loaded, DetectorSpec):
                detectors.append(loaded)
            elif callable(loaded):
                detectors.append(loaded())
            else:
                logger.warning("Entry point %s did not return a DetectorSpec", entry.name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load detector entry point %s: %s", entry.name, exc)
    return detectors


def resolve_detectors(
    detectors: Optional[Iterable[DetectorSpec]] = None,
    include_entry_points: bool = True,
) -> List[DetectorSpec]:
    resolved = list(detectors) if detectors is not None else default_detectors()
    if include_entry_points:
        resolved.extend(load_entry_point_detectors())
    if not resolved:
        raise ValueError("No detectors configured")
    deduped: List[DetectorSpec] = []
    seen: set[str] = set()
    for detector in resolved:
        if detector.name in seen:
            continue
        seen.add(detector.name)
        deduped.append(detector)
    return deduped
