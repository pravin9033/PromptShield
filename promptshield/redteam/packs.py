"""Attack pack loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schema import validate_attack_pack_data

@dataclass(frozen=True)
class AttackCase:
    attack_id: str
    prompt: str
    system_prompt: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    expect_block: Optional[bool] = None
    notes: Optional[str] = None


@dataclass(frozen=True)
class AttackPack:
    name: str
    version: str
    description: str
    attacks: List[AttackCase]
    source_path: Path


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "PyYAML is required for attack packs. Install with: pip install pyyaml"
        ) from exc

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError("Attack pack must be a YAML mapping")
    return data


def load_attack_pack(path_str: str) -> AttackPack:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"Attack pack not found: {path}")

    data = _load_yaml(path)
    errors = validate_attack_pack_data(data)
    if errors:
        formatted = "\n".join(f"- {error}" for error in errors)
        raise ValueError(f"Attack pack schema validation failed for {path}:\n{formatted}")
    name = str(data.get("name", "unnamed-pack"))
    version = str(data.get("version", "0.1"))
    description = str(data.get("description", ""))

    attacks_raw = data.get("attacks", [])
    if not isinstance(attacks_raw, list):
        raise ValueError("attacks must be a list")

    attacks: List[AttackCase] = []
    for idx, item in enumerate(attacks_raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"attack #{idx} must be a mapping")
        attack_id = str(item.get("id", f"attack-{idx}"))
        prompt = item.get("prompt")
        if not prompt:
            raise ValueError(f"attack #{idx} missing prompt")
        attacks.append(
            AttackCase(
                attack_id=attack_id,
                prompt=str(prompt),
                system_prompt=item.get("system_prompt"),
                category=item.get("category"),
                tags=list(item.get("tags", []) or []),
                expect_block=item.get("expect_block"),
                notes=item.get("notes"),
            )
        )

    return AttackPack(
        name=name,
        version=version,
        description=description,
        attacks=attacks,
        source_path=path,
    )
