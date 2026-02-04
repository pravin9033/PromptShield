"""JSON schema validation for attack packs."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any, Dict, List

from jsonschema import Draft202012Validator


def _load_schema() -> Dict[str, Any]:
    schema_text = resources.files("promptshield.redteam").joinpath("schema.json").read_text(
        encoding="utf-8"
    )
    return json.loads(schema_text)


_SCHEMA = _load_schema()
_VALIDATOR = Draft202012Validator(_SCHEMA)


def validate_attack_pack_data(data: Dict[str, Any]) -> List[str]:
    """Return a list of validation error messages (empty if valid)."""
    errors = sorted(_VALIDATOR.iter_errors(data), key=lambda err: list(err.path))
    return [format_validation_error(error) for error in errors]


def format_validation_error(error) -> str:
    path = ".".join(str(part) for part in error.path) or "<root>"
    return f"{path}: {error.message}"
