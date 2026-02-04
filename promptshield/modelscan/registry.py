"""Model adapter registry and built-ins."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Dict, Optional

from .types import ModelAdapter

logger = logging.getLogger(__name__)


@dataclass
class EchoAdapter:
    name: str = "echo"

    def generate(self, prompt=None, system_prompt=None, messages=None) -> str:
        if messages:
            return "\n".join(f"[{m['role']}] {m['content']}" for m in messages)
        return prompt or ""


def load_adapters() -> Dict[str, ModelAdapter]:
    adapters: Dict[str, ModelAdapter] = {"echo": EchoAdapter()}
    for entry in entry_points(group="promptshield.models"):
        try:
            adapter = entry.load()
            if callable(adapter):
                adapter = adapter()
            adapters[getattr(adapter, "name", entry.name)] = adapter
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to load model adapter %s: %s", entry.name, exc)
    return adapters


def get_adapter(name: str) -> Optional[ModelAdapter]:
    adapters = load_adapters()
    return adapters.get(name)
