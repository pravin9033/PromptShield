"""Shared type definitions for PromptShield."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence, Union


class RiskCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    ROLE_CONFUSION = "ROLE_CONFUSION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    NONE = "NONE"


@dataclass(frozen=True)
class Message:
    role: str
    content: str


MessageLike = Union[Message, Mapping[str, str]]
MessageSequence = Sequence[MessageLike]
